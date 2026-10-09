from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlencode

import httpx

from .auth import chatgpt_account_id
from .encoding import json_compact
from .logutil import sanitize

BASE_URL = os.environ.get("CHATGPT_BASE_URL", "https://chatgpt.com/backend-api")
ACCOUNT_ID = os.environ.get("CHATGPT_ACCOUNT_ID")


def api_url(pathname: str, base_url: str = BASE_URL) -> str:
    return f"{base_url.rstrip('/')}{pathname}"


def with_query(pathname: str, params: dict[str, Any]) -> str:
    clean = {key: value for key, value in params.items() if value is not None}
    if not clean:
        return pathname
    return f"{pathname}?{urlencode(clean)}"


def controller_websocket_url(base_url: str = BASE_URL) -> str:
    base = httpx.URL(base_url)
    path = f"{base.path.rstrip('/')}/codex/remote/control/client"
    scheme = "wss" if base.scheme == "https" else "ws"
    return str(base.copy_with(scheme=scheme, path=path, query=None))


def server_websocket_url(base_url: str = BASE_URL) -> str:
    base = httpx.URL(base_url)
    path = f"{base.path.rstrip('/')}/wham/remote/control/server"
    scheme = "wss" if base.scheme == "https" else "ws"
    return str(base.copy_with(scheme=scheme, path=path, query=None))


def _headers(
    token: str,
    *,
    account_id: str | None = None,
    installation_id: str | None = None,
    user_agent: str = "chatex-python/0.1",
    json_body: bool = False,
) -> dict[str, str]:
    headers = {
        "accept": "application/json",
        "authorization": f"Bearer {token}",
        "user-agent": user_agent,
    }
    resolved_account_id = account_id if account_id is not None else ACCOUNT_ID or chatgpt_account_id(token)
    if resolved_account_id:
        headers["chatgpt-account-id"] = resolved_account_id
    if installation_id:
        headers["x-codex-installation-id"] = installation_id
    if json_body:
        headers["content-type"] = "application/json"
    return headers


def _decode_response(response: httpx.Response) -> Any:
    text = response.text
    if not text:
        return None
    try:
        return response.json()
    except ValueError:
        return text[:500]


async def request_json(
    method: str,
    pathname: str,
    token: str,
    *,
    body: Any | None = None,
    account_id: str | None = None,
    installation_id: str | None = None,
    user_agent: str = "chatex-python/0.1",
) -> Any:
    headers = _headers(
        token,
        account_id=account_id,
        installation_id=installation_id,
        user_agent=user_agent,
        json_body=body is not None,
    )
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.request(
            method,
            api_url(pathname),
            content=json_compact(body) if body is not None else None,
            headers=headers,
        )
    decoded = _decode_response(response)
    if response.status_code < 200 or response.status_code >= 300:
        raise RuntimeError(
            f"{method} {pathname} failed ({response.status_code}): {json_compact(sanitize(decoded))}"
        )
    return decoded


def request_json_sync(
    method: str,
    pathname: str,
    token: str,
    *,
    body: Any | None = None,
    account_id: str | None = None,
    installation_id: str | None = None,
    user_agent: str = "chatex-python/0.1",
) -> Any:
    headers = _headers(
        token,
        account_id=account_id,
        installation_id=installation_id,
        user_agent=user_agent,
        json_body=body is not None,
    )
    with httpx.Client(timeout=30) as client:
        response = client.request(
            method,
            api_url(pathname),
            content=json_compact(body) if body is not None else None,
            headers=headers,
        )
    decoded = _decode_response(response)
    if response.status_code < 200 or response.status_code >= 300:
        raise RuntimeError(
            f"{method} {pathname} failed ({response.status_code}): {json_compact(sanitize(decoded))}"
        )
    return decoded


async def get_json(pathname: str, token: str, **kwargs: Any) -> Any:
    return await request_json("GET", pathname, token, **kwargs)


async def post_json(pathname: str, body: Any, token: str, **kwargs: Any) -> Any:
    return await request_json("POST", pathname, token, body=body, **kwargs)


def get_json_sync(pathname: str, token: str, **kwargs: Any) -> Any:
    return request_json_sync("GET", pathname, token, **kwargs)


def post_json_sync(pathname: str, body: Any, token: str, **kwargs: Any) -> Any:
    return request_json_sync("POST", pathname, token, body=body, **kwargs)


def delete_json_sync(pathname: str, token: str, **kwargs: Any) -> Any:
    return request_json_sync("DELETE", pathname, token, **kwargs)
