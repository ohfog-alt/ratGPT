from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from .auth import chatgpt_account_id, decode_jwt_payload

DEFAULT_ISSUER = "https://auth.openai.com"
DEFAULT_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
DEFAULT_TIMEOUT_SECONDS = 15 * 60


@dataclass(frozen=True)
class DeviceCode:
    verification_url: str
    user_code: str
    device_auth_id: str
    interval_seconds: int


@dataclass(frozen=True)
class AuthorizationCode:
    authorization_code: str
    code_challenge: str
    code_verifier: str


@dataclass(frozen=True)
class ExchangedTokens:
    id_token: str
    access_token: str
    refresh_token: str


@dataclass(frozen=True)
class AuthWriteResult:
    path: Path
    backup_path: Path | None
    account_id: str | None
    email: str | None


def normalize_issuer(issuer: str) -> str:
    return issuer.rstrip("/")


def default_codex_home() -> Path:
    from .state import STATE_DIR

    return Path(os.environ.get("RATGPT_CODEX_HOME", STATE_DIR)).expanduser()


def auth_file_path(codex_home: Path) -> Path:
    return codex_home.expanduser() / "auth.json"


def _decode_response(response: httpx.Response) -> Any:
    if not response.text:
        return None
    try:
        return response.json()
    except ValueError:
        return response.text[:500]


def _raise_for_status(response: httpx.Response, action: str) -> None:
    if 200 <= response.status_code < 300:
        return
    decoded = _decode_response(response)
    detail = json.dumps(decoded, separators=(",", ":"), ensure_ascii=False)
    raise RuntimeError(f"{action} failed with HTTP {response.status_code}: {detail}")


def _required_string(body: dict[str, Any], key: str, action: str) -> str:
    value = body.get(key)
    if not isinstance(value, str) or not value:
        raise RuntimeError(f"{action} returned no {key!r}: {json.dumps(body, separators=(',', ':'))}")
    return value


def request_device_code(
    client: httpx.Client,
    *,
    issuer: str = DEFAULT_ISSUER,
    client_id: str = DEFAULT_CLIENT_ID,
) -> DeviceCode:
    issuer = normalize_issuer(issuer)
    response = client.post(
        f"{issuer}/api/accounts/deviceauth/usercode",
        json={"client_id": client_id},
    )
    if response.status_code == 404:
        raise RuntimeError(
            "device code login is not enabled for this issuer; use browser login or verify --issuer"
        )
    _raise_for_status(response, "device code request")
    body = response.json()
    if not isinstance(body, dict):
        raise RuntimeError(f"device code request returned non-object body: {body!r}")

    user_code = body.get("user_code") or body.get("usercode")
    if not isinstance(user_code, str) or not user_code:
        raise RuntimeError(f"device code request returned no user code: {json.dumps(body, separators=(',', ':'))}")
    raw_interval = body.get("interval", 5)
    try:
        interval_seconds = max(1, int(str(raw_interval).strip()))
    except ValueError as error:
        raise RuntimeError(f"device code request returned invalid interval: {raw_interval!r}") from error

    return DeviceCode(
        verification_url=f"{issuer}/codex/device",
        user_code=user_code,
        device_auth_id=_required_string(body, "device_auth_id", "device code request"),
        interval_seconds=interval_seconds,
    )


def poll_for_authorization_code(
    client: httpx.Client,
    device_code: DeviceCode,
    *,
    issuer: str = DEFAULT_ISSUER,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> AuthorizationCode:
    issuer = normalize_issuer(issuer)
    deadline = time.monotonic() + timeout_seconds
    url = f"{issuer}/api/accounts/deviceauth/token"

    while True:
        response = client.post(
            url,
            json={
                "device_auth_id": device_code.device_auth_id,
                "user_code": device_code.user_code,
            },
        )
        if 200 <= response.status_code < 300:
            body = response.json()
            if not isinstance(body, dict):
                raise RuntimeError(f"device auth poll returned non-object body: {body!r}")
            return AuthorizationCode(
                authorization_code=_required_string(body, "authorization_code", "device auth poll"),
                code_challenge=_required_string(body, "code_challenge", "device auth poll"),
                code_verifier=_required_string(body, "code_verifier", "device auth poll"),
            )

        if response.status_code not in {403, 404}:
            _raise_for_status(response, "device auth poll")

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"device auth timed out after {timeout_seconds} seconds")
        time.sleep(min(float(device_code.interval_seconds), remaining))


def exchange_authorization_code(
    client: httpx.Client,
    authorization: AuthorizationCode,
    *,
    issuer: str = DEFAULT_ISSUER,
    client_id: str = DEFAULT_CLIENT_ID,
) -> ExchangedTokens:
    issuer = normalize_issuer(issuer)
    response = client.post(
        f"{issuer}/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": authorization.authorization_code,
            "redirect_uri": f"{issuer}/deviceauth/callback",
            "client_id": client_id,
            "code_verifier": authorization.code_verifier,
        },
    )
    _raise_for_status(response, "authorization code exchange")
    body = response.json()
    if not isinstance(body, dict):
        raise RuntimeError(f"authorization code exchange returned non-object body: {body!r}")
    return ExchangedTokens(
        id_token=_required_string(body, "id_token", "authorization code exchange"),
        access_token=_required_string(body, "access_token", "authorization code exchange"),
        refresh_token=_required_string(body, "refresh_token", "authorization code exchange"),
    )


def summarize_id_token(id_token: str) -> dict[str, Any]:
    payload = decode_jwt_payload(id_token) or {}
    profile = payload.get("https://api.openai.com/profile") if isinstance(payload, dict) else None
    auth = payload.get("https://api.openai.com/auth") if isinstance(payload, dict) else None
    email = payload.get("email") if isinstance(payload.get("email"), str) else None
    if email is None and isinstance(profile, dict) and isinstance(profile.get("email"), str):
        email = profile["email"]
    return {
        "email": email,
        "account_id": chatgpt_account_id(id_token),
        "user_id": auth.get("chatgpt_user_id") if isinstance(auth, dict) else None,
        "plan_type": auth.get("chatgpt_plan_type") if isinstance(auth, dict) else None,
        "is_fedramp": auth.get("chatgpt_account_is_fedramp") if isinstance(auth, dict) else None,
    }


def build_auth_json(tokens: ExchangedTokens) -> dict[str, Any]:
    return {
        "auth_mode": "chatgpt",
        "OPENAI_API_KEY": None,
        "tokens": {
            "id_token": tokens.id_token,
            "access_token": tokens.access_token,
            "refresh_token": tokens.refresh_token,
            "account_id": chatgpt_account_id(tokens.id_token),
        },
        "last_refresh": datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
    }


def write_codex_auth(
    codex_home: Path,
    auth_json: dict[str, Any],
    *,
    force: bool = False,
    backup: bool = True,
) -> AuthWriteResult:
    codex_home = codex_home.expanduser()
    path = auth_file_path(codex_home)
    if path.exists() and not force:
        raise FileExistsError(f"{path} already exists; rerun with --force to replace it")

    backup_path = None
    codex_home.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists() and backup:
        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        backup_path = path.with_name(f"{path.name}.chatex-python-login-backup-{timestamp}")
        shutil.copy2(path, backup_path)

    fd, temp_name = tempfile.mkstemp(prefix=".auth.json.", suffix=".tmp", dir=codex_home)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(auth_json, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, path)
    except Exception:
        try:
            temp_path.unlink(missing_ok=True)
        finally:
            raise

    tokens = auth_json.get("tokens") if isinstance(auth_json, dict) else None
    id_token = tokens.get("id_token") if isinstance(tokens, dict) else None
    summary = summarize_id_token(id_token) if isinstance(id_token, str) else {}
    return AuthWriteResult(
        path=path,
        backup_path=backup_path,
        account_id=summary.get("account_id"),
        email=summary.get("email"),
    )
