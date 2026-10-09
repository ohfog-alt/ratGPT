from __future__ import annotations

import base64
import json
import os
import queue
import shlex
import subprocess
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from .encoding import json_compact
from .logutil import sanitize

BASE_TIMEOUT_MS = int(os.environ.get("RATGPT_TIMEOUT_MS", os.environ.get("CODEX_TIMEOUT_MS", "5000")))
CODEX_BIN = os.environ.get("CODEX_BIN", "codex")
CODEX_ARGS = shlex.split(os.environ.get("CODEX_APP_SERVER_ARGS", "app-server --stdio"))
AUTH_SOURCE = os.environ.get("RATGPT_AUTH_SOURCE", "direct").lower().strip()
DEFAULT_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
REFRESH_TOKEN_URL = os.environ.get("CODEX_REFRESH_TOKEN_URL_OVERRIDE", "https://auth.openai.com/oauth/token")
TOKEN_REFRESH_WINDOW_SECONDS = int(os.environ.get("RATGPT_AUTH_REFRESH_WINDOW_SECONDS", "300"))
APP_SERVER_REFRESH_TOKEN = os.environ.get("RATGPT_APP_SERVER_REFRESH_TOKEN", "0") == "1"


@dataclass
class AuthStatus:
    token: str
    status: dict[str, Any]
    app_server: dict[str, Any]
    source: str = "direct"
    auth_path: str | None = None


def _frame(message: dict[str, Any]) -> str:
    return f"{json_compact(message)}\n"


def get_auth_status_with_token(
    *,
    codex_bin: str = CODEX_BIN,
    codex_args: list[str] | None = None,
    timeout_ms: int = BASE_TIMEOUT_MS,
    client_name: str = "chatex-python-helper",
    client_title: str = "Chatex Python Helper",
) -> AuthStatus:
    if AUTH_SOURCE in {"direct", "file", "auth-json", "auth_json"}:
        return get_direct_auth_status_with_token()
    if AUTH_SOURCE in {"app-server", "app_server", "codex"}:
        return get_app_server_auth_status_with_token(
            codex_bin=codex_bin,
            codex_args=codex_args,
            timeout_ms=timeout_ms,
            client_name=client_name,
            client_title=client_title,
        )
    raise RuntimeError(
        f"Unsupported RATGPT_AUTH_SOURCE={AUTH_SOURCE!r}; expected 'direct' or 'app-server'."
    )


def get_app_server_auth_status_with_token(
    *,
    codex_bin: str = CODEX_BIN,
    codex_args: list[str] | None = None,
    timeout_ms: int = BASE_TIMEOUT_MS,
    client_name: str = "chatex-python-helper",
    client_title: str = "Chatex Python Helper",
) -> AuthStatus:
    args = codex_args if codex_args is not None else CODEX_ARGS
    frames = [
        _frame(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "clientInfo": {
                        "name": client_name,
                        "title": client_title,
                        "version": "0.1.0",
                    },
                    "capabilities": {
                        "experimentalApi": True,
                        "requestAttestation": False,
                        "optOutNotificationMethods": [],
                    },
                },
            }
        ),
        _frame({"jsonrpc": "2.0", "method": "initialized"}),
        _frame(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "getAuthStatus",
                "params": {"includeToken": True, "refreshToken": APP_SERVER_REFRESH_TOKEN},
            }
        ),
    ]

    proc = subprocess.Popen(
        [codex_bin, *args],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    timed_out = False
    response_queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=1)
    stderr_chunks: list[str] = []

    def read_stdout() -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                message = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if message.get("id") == 2:
                try:
                    response_queue.put_nowait(message)
                except queue.Full:
                    pass
                return

    def read_stderr() -> None:
        assert proc.stderr is not None
        data = proc.stderr.read()
        if data:
            stderr_chunks.append(data)

    stdout_thread = threading.Thread(target=read_stdout, daemon=True)
    stderr_thread = threading.Thread(target=read_stderr, daemon=True)
    stdout_thread.start()
    stderr_thread.start()

    try:
        assert proc.stdin is not None
        for frame in frames:
            proc.stdin.write(frame)
        proc.stdin.flush()
    except BrokenPipeError:
        pass

    try:
        response = response_queue.get(timeout=timeout_ms / 1000)
    except queue.Empty:
        timed_out = True
        response = None

    try:
        if proc.stdin is not None:
            proc.stdin.close()
    except Exception:
        pass

    try:
        proc.wait(timeout=1)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=1)

    stdout_thread.join(timeout=0.2)
    stderr_thread.join(timeout=0.2)
    stderr = "".join(stderr_chunks)

    if not response:
        raise RuntimeError(
            f"getAuthStatus did not return response id 2; stderr={json.dumps(stderr.strip())}"
        )
    if response.get("error"):
        raise RuntimeError(f"getAuthStatus error: {json.dumps(response['error'])}")

    result = response.get("result") or {}
    token = result.get("authToken")
    if not token:
        raise RuntimeError(f"getAuthStatus returned no authToken; result={json.dumps(sanitize(result))}")

    return AuthStatus(
        token=token,
        status={
            "authMethod": result.get("authMethod"),
            "requiresOpenaiAuth": result.get("requiresOpenaiAuth"),
        },
        app_server={
            "command": " ".join([codex_bin, *args]),
            "stderr": stderr.strip() or None,
            "timedOut": timed_out,
        },
        source="app-server",
    )


def codex_home() -> Path:
    from .state import STATE_DIR

    return Path(os.environ.get("RATGPT_CODEX_HOME", STATE_DIR)).expanduser()


def auth_file_path(home: Path | None = None) -> Path:
    return (home or codex_home()).expanduser() / "auth.json"


def _read_auth_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise RuntimeError(
            f"No Codex auth file found at {path}. Run `CODEX_HOME={path.parent} ./run-login.sh`, "
            "or set CHATEX_AUTH_SOURCE=app-server to reuse Codex app-server auth."
        )
    try:
        body = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise RuntimeError(f"Could not parse Codex auth file at {path}: {error}") from error
    if not isinstance(body, dict):
        raise RuntimeError(f"Codex auth file at {path} is not a JSON object.")
    return body


def _write_auth_json(path: Path, auth: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    import tempfile

    fd, temp_name = tempfile.mkstemp(prefix=".auth.json.", suffix=".tmp", dir=path.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(auth, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, path)
    except Exception:
        try:
            temp_path.unlink(missing_ok=True)
        finally:
            raise


def _jwt_exp(token: str) -> int | None:
    payload = decode_jwt_payload(token)
    exp = payload.get("exp") if isinstance(payload, dict) else None
    if isinstance(exp, bool):
        return None
    if isinstance(exp, int):
        return exp
    if isinstance(exp, float):
        return int(exp)
    return None


def _is_access_token_fresh(token: str, *, refresh_window_seconds: int = TOKEN_REFRESH_WINDOW_SECONDS) -> bool:
    exp = _jwt_exp(token)
    if exp is None:
        return False
    return exp > int(datetime.now(UTC).timestamp()) + refresh_window_seconds


def _tokens(auth: dict[str, Any], path: Path) -> dict[str, Any]:
    auth_mode = auth.get("auth_mode")
    if auth_mode != "chatgpt":
        raise RuntimeError(
            f"Codex auth at {path} has auth_mode={auth_mode!r}; chatex-python direct auth requires 'chatgpt'."
        )
    tokens = auth.get("tokens")
    if not isinstance(tokens, dict):
        raise RuntimeError(f"Codex auth at {path} does not contain a tokens object. Run ./run-login.sh first.")
    return tokens


def _required_token(tokens: dict[str, Any], field: str, path: Path) -> str:
    value = tokens.get(field)
    if not isinstance(value, str) or not value:
        raise RuntimeError(f"Codex auth at {path} is missing tokens.{field}. Run ./run-login.sh first.")
    return value


def _decode_response(response: httpx.Response) -> Any:
    if not response.text:
        return None
    try:
        return response.json()
    except ValueError:
        return response.text[:500]


def _refresh_chatgpt_tokens(
    auth: dict[str, Any],
    path: Path,
    tokens: dict[str, Any],
    refresh_token: str,
) -> dict[str, Any]:
    with httpx.Client(timeout=30) as client:
        response = client.post(
            REFRESH_TOKEN_URL,
            headers={"Content-Type": "application/json"},
            json={
                "client_id": DEFAULT_CLIENT_ID,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            },
        )

    decoded = _decode_response(response)
    if response.status_code < 200 or response.status_code >= 300:
        raise RuntimeError(
            "ChatGPT token refresh failed "
            f"({response.status_code}): {json_compact(sanitize(decoded))}"
        )
    if not isinstance(decoded, dict):
        raise RuntimeError(f"ChatGPT token refresh returned non-object body: {sanitize(decoded)!r}")

    for field in ("id_token", "access_token", "refresh_token"):
        value = decoded.get(field)
        if isinstance(value, str) and value:
            tokens[field] = value

    id_token = tokens.get("id_token")
    if isinstance(id_token, str) and id_token:
        tokens["account_id"] = chatgpt_account_id(id_token)
    auth["tokens"] = tokens
    auth["last_refresh"] = datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    _write_auth_json(path, auth)
    return tokens


def get_direct_auth_status_with_token() -> AuthStatus:
    path = auth_file_path()
    auth = _read_auth_json(path)
    tokens = _tokens(auth, path)
    access_token = _required_token(tokens, "access_token", path)
    refreshed = False

    if not _is_access_token_fresh(access_token):
        refresh_token = _required_token(tokens, "refresh_token", path)
        tokens = _refresh_chatgpt_tokens(auth, path, tokens, refresh_token)
        access_token = _required_token(tokens, "access_token", path)
        refreshed = True
        if not _is_access_token_fresh(access_token):
            raise RuntimeError("ChatGPT token refresh did not return a fresh JWT access token.")

    return AuthStatus(
        token=access_token,
        status={
            "authMethod": "chatgpt",
            "requiresOpenaiAuth": True,
            "refreshed": refreshed,
        },
        app_server={
            "authSource": "direct",
            "authPath": str(path),
            "refreshed": refreshed,
        },
        source="direct",
        auth_path=str(path),
    )


def _base64url_decode(value: str) -> bytes:
    padded = value + ("=" * ((4 - len(value) % 4) % 4))
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def decode_jwt_payload(token: str) -> dict[str, Any] | None:
    parts = token.split(".")
    if len(parts) < 2 or not parts[1]:
        return None
    try:
        return json.loads(_base64url_decode(parts[1]).decode("utf-8"))
    except Exception:
        return None


def chatgpt_account_id(token: str) -> str | None:
    payload = decode_jwt_payload(token)
    auth = payload.get("https://api.openai.com/auth") if isinstance(payload, dict) else None
    if not isinstance(auth, dict):
        return None
    if isinstance(auth.get("chatgpt_account_id"), str):
        return auth["chatgpt_account_id"]
    if isinstance(auth.get("account_id"), str):
        return auth["account_id"]
    return None
