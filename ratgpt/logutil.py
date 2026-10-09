from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from typing import Any

_VERBOSE = os.environ.get("RATGPT_VERBOSE", "").lower() in {"1", "true", "yes", "on"}


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def is_verbose() -> bool:
    return _VERBOSE


def set_verbose(enabled: bool) -> bool:
    global _VERBOSE
    _VERBOSE = enabled
    return _VERBOSE


def toggle_verbose() -> bool:
    return set_verbose(not is_verbose())


def short_id(value: str | None) -> str:
    if not value:
        return "(none)"
    if len(value) <= 14:
        return value
    return f"{value[:8]}...{value[-4:]}"


def redact_string(value: str, keep_edge: bool = False) -> dict[str, Any]:
    if not keep_edge or len(value) <= 12:
        return {"redacted": True, "length": len(value)}
    return {
        "redacted": True,
        "length": len(value),
        "prefix": value[:8],
        "suffix": value[-4:],
    }


def sanitize(value: Any, key: str = "") -> Any:
    lowered = key.lower()
    if isinstance(value, str):
        if (
            "token" in lowered
            or "secret" in lowered
            or "authorization" in lowered
            or "cursor" in lowered
            or "nonce" in lowered
            or "signature" in lowered
            or "signed_payload" in lowered
            or "signedpayload" in lowered
            or "public_key" in lowered
            or "publickey" in lowered
            or "identity_hash" in lowered
            or "identityhash" in lowered
            or "pairing_code" in lowered
            or "pairingcode" in lowered
            or "sha256" in lowered
            or "account_user_id" in lowered
            or "accountuserid" in lowered
            or lowered == "user_id"
        ):
            return redact_string(value)
        if (
            lowered.endswith("_id")
            or lowered.endswith("id")
            or lowered == "id"
            or lowered in {
                "client_id",
                "clientid",
                "env_id",
                "envid",
                "environment_id",
                "environmentid",
                "server_id",
                "serverid",
                "stream_id",
                "streamid",
                "installation_id",
                "installationid",
                "session_id",
                "sessionid",
                "key_id",
                "keyid",
                "challenge_id",
                "challengeid",
            }
        ):
            return redact_string(value, keep_edge=True)
        return value
    if isinstance(value, list):
        return [sanitize(item, key) for item in value]
    if isinstance(value, dict):
        return {field: sanitize(field_value, field) for field, field_value in value.items()}
    return value


def log(event: str, **fields: Any) -> None:
    if not is_verbose():
        return
    print(
        json.dumps({"ts": now_iso(), "event": event, **fields}, separators=(",", ":")),
        file=sys.stderr,
        flush=True,
    )


def token_metadata(token: str | None) -> dict[str, Any]:
    if not token:
        return {"received": False, "length": 0, "sha256Prefix": None, "looksLikeJwt": False}
    return {
        "received": True,
        "length": len(token),
        "sha256Prefix": hashlib.sha256(token.encode("utf-8")).hexdigest()[:12],
        "looksLikeJwt": len(token.split(".")) == 3,
    }
