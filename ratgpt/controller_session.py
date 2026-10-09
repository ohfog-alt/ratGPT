from __future__ import annotations

import hashlib
import os
from typing import Any
from urllib.parse import urlparse

from .api import ACCOUNT_ID, get_json, post_json, with_query
from .auth import chatgpt_account_id
from .device_key import KeyState, device_identity_hash, sign_device_key_payload
from .logutil import sanitize


SESSION_REFRESH_SKEW_SECONDS = int(os.environ.get("CHATEX_SESSION_REFRESH_SKEW_SECONDS", "60"))


def _refresh_payload(
    enrollment: dict[str, Any],
    challenge: dict[str, Any],
    identity_hash: str,
) -> dict[str, Any]:
    return {
        "type": "remoteControlClientEnrollment",
        "nonce": challenge.get("nonce"),
        "audience": challenge.get("audience"),
        "challengeId": challenge.get("challenge_id"),
        "targetOrigin": challenge.get("target_origin"),
        "targetPath": challenge.get("target_path"),
        "accountUserId": enrollment.get("accountUserId"),
        "clientId": enrollment.get("clientId"),
        "deviceIdentitySha256Base64url": challenge.get("device_identity_hash") or identity_hash,
        "challengeExpiresAt": challenge.get("challenge_expires_at"),
    }


async def refresh_client_session(
    *,
    auth_token: str,
    enrollment: dict[str, Any],
    key_state: KeyState,
) -> dict[str, Any]:
    start = await post_json(
        "/codex/remote/control/client/refresh/start",
        {"client_id": enrollment["clientId"]},
        auth_token,
        user_agent="chatex-python-client/0.1",
    )
    challenge = start.get("device_key_challenge") if isinstance(start, dict) else None
    if not challenge:
        raise RuntimeError(f"refresh/start returned no challenge: {sanitize(start)}")
    identity_hash = device_identity_hash(key_state.device_key)
    signed_payload = _refresh_payload(enrollment, challenge, identity_hash)
    proof = sign_device_key_payload(key_state.device_key, signed_payload)
    finish = await post_json(
        "/codex/remote/control/client/refresh/finish",
        {
            "client_id": enrollment["clientId"],
            "device_key_proof": {
                "challenge_token": challenge.get("challenge_token"),
                "key_id": key_state.device_key.key_id,
                "signature_der_base64": proof["signatureDerBase64"],
                "signed_payload_base64": proof["signedPayloadBase64"],
                "algorithm": key_state.device_key.algorithm,
            },
        },
        auth_token,
        user_agent="chatex-python-client/0.1",
    )
    remote_control_token = finish.get("remote_control_token") if isinstance(finish, dict) else None
    expires_at = finish.get("expires_at") if isinstance(finish, dict) else None
    if not isinstance(remote_control_token, str) or not isinstance(expires_at, str):
        raise RuntimeError(f"refresh/finish returned invalid body: {sanitize(finish)}")
    from datetime import datetime

    token_expires_at = int(datetime.fromisoformat(expires_at.replace("Z", "+00:00")).timestamp())
    return {
        "remoteControlToken": remote_control_token,
        "tokenExpiresAt": token_expires_at,
        "scopes": finish.get("scopes") if isinstance(finish.get("scopes"), list) else [],
    }


async def select_environment(
    auth_token: str,
    *,
    target_env_id: str | None = None,
    target_env_name: str | None = None,
) -> dict[str, Any]:
    env_id = target_env_id or os.environ.get("CODEX_REMOTE_ENV_ID")
    env_name = target_env_name or os.environ.get("CODEX_REMOTE_ENV_NAME")
    environments = await get_json(
        with_query("/codex/remote/control/environments", {"limit": 25}),
        auth_token,
        user_agent="chatex-python-client/0.1",
    )
    items = environments.get("items") if isinstance(environments, dict) else []
    candidates = [item for item in items if isinstance(item, dict) and item.get("online") is True]
    if env_id:
        candidates = [item for item in candidates if item.get("env_id") == env_id]
    if env_name:
        candidates = [
            item
            for item in candidates
            if env_name in {item.get("display_name"), item.get("host_name"), item.get("name")}
        ]
    if len(candidates) != 1:
        summary = [
            {
                "env_id": item.get("env_id"),
                "display_name": item.get("display_name"),
                "host_name": item.get("host_name"),
                "name": item.get("name"),
                "online": item.get("online"),
                "busy": item.get("busy"),
                "os": item.get("os"),
                "arch": item.get("arch"),
                "app_server_version": item.get("app_server_version"),
            }
            for item in items
            if isinstance(item, dict)
        ]
        raise RuntimeError(
            f"Expected exactly one matching online environment; got {len(candidates)}: {sanitize(summary)}"
        )
    return candidates[0]


def _connection_payload(challenge: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "remoteControlClientConnection",
        "nonce": challenge.get("nonce"),
        "audience": challenge.get("audience"),
        "sessionId": challenge.get("sessionId"),
        "targetOrigin": challenge.get("targetOrigin"),
        "targetPath": challenge.get("targetPath"),
        "accountUserId": challenge.get("accountUserId"),
        "clientId": challenge.get("clientId"),
        "tokenSha256Base64url": challenge.get("tokenSha256Base64url"),
        "tokenExpiresAt": challenge.get("tokenExpiresAt"),
        "scopes": challenge.get("scopes"),
    }


def validate_websocket_challenge(
    *,
    challenge: dict[str, Any],
    ws_url: str,
    enrollment: dict[str, Any],
    remote_control_token: str,
    token_expires_at: int,
    scopes: list[str],
) -> None:
    parsed = urlparse(ws_url)
    expected_origin = f"{'https' if parsed.scheme == 'wss' else 'http'}://{parsed.netloc}"
    token_hash = hashlib.sha256(remote_control_token.encode("utf-8")).digest()
    from .encoding import base64url

    errors = []
    if challenge.get("purpose") != "remote_control_client_websocket":
        errors.append("purpose")
    if challenge.get("audience") != "remote_control_client_websocket":
        errors.append("audience")
    if challenge.get("targetOrigin") != expected_origin:
        errors.append("targetOrigin")
    if challenge.get("targetPath") != parsed.path:
        errors.append("targetPath")
    if challenge.get("accountUserId") != enrollment.get("accountUserId"):
        errors.append("accountUserId")
    if challenge.get("clientId") != enrollment.get("clientId"):
        errors.append("clientId")
    if challenge.get("tokenSha256Base64url") != base64url(token_hash):
        errors.append("tokenSha256Base64url")
    if challenge.get("tokenExpiresAt") != token_expires_at:
        errors.append("tokenExpiresAt")
    if not isinstance(challenge.get("scopes"), list) or "\0".join(challenge["scopes"]) != "\0".join(scopes):
        errors.append("scopes")
    if errors:
        raise RuntimeError(f"websocket device-key challenge validation failed: {', '.join(errors)}")


def websocket_proof(*, challenge: dict[str, Any], key_state: KeyState) -> dict[str, Any]:
    proof = sign_device_key_payload(key_state.device_key, _connection_payload(challenge))
    return {
        "type": "device_key_proof",
        "keyId": key_state.device_key.key_id,
        "signatureDerBase64": proof["signatureDerBase64"],
        "signedPayloadBase64": proof["signedPayloadBase64"],
        "algorithm": key_state.device_key.algorithm,
    }


def controller_headers(
    *,
    auth_token: str,
    enrollment: dict[str, Any],
    session: dict[str, Any],
    cursor: str | None = None,
) -> dict[str, str]:
    account_id = ACCOUNT_ID or chatgpt_account_id(auth_token)
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "originator": os.environ.get("CODEX_ORIGINATOR", "Codex Desktop"),
        "User-Agent": os.environ.get("CODEX_WS_USER_AGENT", "Codex Desktop/26.519.81530 (Linux; arm64)"),
        "x-codex-client-id": enrollment["clientId"],
        "x-codex-protocol-version": "3",
        "x-codex-client-session-token": f"Bearer {session['remoteControlToken']}",
    }
    if account_id:
        headers["ChatGPT-Account-Id"] = account_id
    if cursor:
        headers["x-codex-subscribe-cursor"] = cursor
    return headers
