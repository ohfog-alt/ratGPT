from __future__ import annotations

import hashlib
import http.server
import os
import queue
import secrets
import threading
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

from .auth import chatgpt_account_id
from .encoding import base64url
from .logutil import log, sanitize

STEP_UP_TOKEN = os.environ.get("CODEX_STEP_UP_TOKEN")
STEP_UP_MODE = os.environ.get("CODEX_STEP_UP_MODE", "oauth")
STEP_UP_TIMEOUT_SECONDS = int(os.environ.get("CODEX_STEP_UP_TIMEOUT_SECONDS", "600"))
STEP_UP_ISSUER = os.environ.get("CODEX_STEP_UP_ISSUER", "https://auth.openai.com")
STEP_UP_CLIENT_ID = os.environ.get("CODEX_STEP_UP_CLIENT_ID", "app_EMoamEEZ73f0CkXaXp7hrann")
STEP_UP_SCOPE = "codex.remote_control.enroll"
STEP_UP_REAUTH = "remote_control"
STEP_UP_CALLBACK_PATH = "/auth/callback"
STEP_UP_CALLBACK_PORTS = [1455, 1457]
ORIGINATOR = os.environ.get("CODEX_ORIGINATOR", "Codex Desktop")


@dataclass
class StepUpToken:
    token: str
    source: str


def _issuer_base() -> str:
    return STEP_UP_ISSUER.rstrip("/")


def _code_challenge(code_verifier: str) -> str:
    return base64url(hashlib.sha256(code_verifier.encode("ascii")).digest())


def _write_text(handler: http.server.BaseHTTPRequestHandler, status: int, text: str) -> None:
    handler.send_response(status)
    handler.send_header("content-type", "text/plain; charset=utf-8")
    handler.send_header("connection", "close")
    handler.end_headers()
    handler.wfile.write(text.encode("utf-8"))


def _write_success(handler: http.server.BaseHTTPRequestHandler) -> None:
    handler.send_response(200)
    handler.send_header("content-type", "text/html; charset=utf-8")
    handler.send_header("connection", "close")
    handler.end_headers()
    handler.wfile.write(
        b"<!doctype html><html><body><p>Remote control authorization completed.</p></body></html>"
    )


def _listen_for_step_up_code(state: str) -> tuple[str, "queue.Queue[tuple[str, str]]", http.server.ThreadingHTTPServer]:
    result_queue: queue.Queue[tuple[str, str]] = queue.Queue(maxsize=1)

    for candidate_port in STEP_UP_CALLBACK_PORTS:
        callback_path = STEP_UP_CALLBACK_PATH
        expected_state = state

        class CallbackHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: Any) -> None:
                return

            def do_GET(self) -> None:
                parsed = urlparse(self.path)
                if parsed.path != callback_path:
                    _write_text(self, 404, "Not Found")
                    return
                params = parse_qs(parsed.query)
                received_state = params.get("state", [""])[0]
                if received_state != expected_state:
                    _write_text(self, 400, "State mismatch")
                    return
                error = params.get("error", [""])[0]
                if error:
                    description = params.get("error_description", [""])[0]
                    _write_text(self, 400, "Remote control login failed")
                    result_queue.put(("error", f"{error}: {description}" if description else error))
                    return
                code = params.get("code", [""])[0]
                if not code:
                    _write_text(self, 400, "Missing authorization code")
                    return
                _write_success(self)
                result_queue.put(("code", code))

        try:
            server = http.server.ThreadingHTTPServer(("localhost", candidate_port), CallbackHandler)
        except OSError as error:
            if getattr(error, "errno", None) == 48 or getattr(error, "errno", None) == 98:
                continue
            raise

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        redirect_uri = f"http://localhost:{candidate_port}{STEP_UP_CALLBACK_PATH}"
        return redirect_uri, result_queue, server

    raise RuntimeError("Remote control login callback ports 1455 and 1457 are already in use.")


def step_up_authorize_url(
    *,
    account_id: str | None,
    code_challenge_value: str,
    redirect_uri: str,
    state: str,
) -> str:
    params = {
        "response_type": "code",
        "client_id": STEP_UP_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "scope": STEP_UP_SCOPE,
        "code_challenge": code_challenge_value,
        "code_challenge_method": "S256",
        "state": state,
        "originator": ORIGINATOR,
        "reauth": STEP_UP_REAUTH,
        "max_age": "0",
        "codex_cli_simplified_flow": "true",
    }
    if account_id:
        params["allowed_workspace_id"] = account_id
        params["current_workspace_id"] = account_id
    return f"{_issuer_base()}/oauth/authorize?{urlencode(params)}"


def exchange_step_up_code(*, authorization_code: str, code_verifier: str, redirect_uri: str) -> str:
    with httpx.Client(timeout=30) as client:
        response = client.post(
            f"{_issuer_base()}/oauth/token",
            headers={"content-type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "authorization_code",
                "code": authorization_code,
                "redirect_uri": redirect_uri,
                "client_id": STEP_UP_CLIENT_ID,
                "code_verifier": code_verifier,
            },
        )
    try:
        body: Any = response.json()
    except ValueError:
        body = response.text[:300]
    if response.status_code < 200 or response.status_code >= 300:
        raise RuntimeError(
            f"Remote control step-up token exchange failed with status "
            f"{response.status_code}: {sanitize(body)}"
        )
    access_token = body.get("access_token") if isinstance(body, dict) else None
    if not access_token:
        raise RuntimeError(f"Remote control step-up token exchange returned no access_token: {sanitize(body)}")
    return access_token


def oauth_step_up_token(auth_token: str) -> str:
    code_verifier = base64url(secrets.token_bytes(32))
    state = base64url(secrets.token_bytes(32))
    redirect_uri, result_queue, server = _listen_for_step_up_code(state)
    account_id = os.environ.get("CHATGPT_ACCOUNT_ID") or chatgpt_account_id(auth_token)
    authorize_url = step_up_authorize_url(
        account_id=account_id,
        code_challenge_value=_code_challenge(code_verifier),
        redirect_uri=redirect_uri,
        state=state,
    )
    try:
        log(
            "step-up-auth-url",
            message=(
                "Open this URL in a browser authenticated as the same ChatGPT account. "
                "If running from a different machine, forward local port 1455 or 1457 first."
            ),
            redirectUri=redirect_uri,
            accountIdProvided=bool(account_id),
            originator=ORIGINATOR,
            url=authorize_url,
        )
        print(f"Open this URL to authorize remote-control enrollment:\n{authorize_url}", flush=True)
        kind, value = result_queue.get(timeout=STEP_UP_TIMEOUT_SECONDS)
        if kind == "error":
            raise RuntimeError(value)
        return exchange_step_up_code(
            authorization_code=value,
            code_verifier=code_verifier,
            redirect_uri=redirect_uri,
        )
    finally:
        server.shutdown()
        server.server_close()


def resolve_step_up_token(auth_token: str) -> StepUpToken:
    if STEP_UP_TOKEN:
        return StepUpToken(token=STEP_UP_TOKEN, source="env")
    if STEP_UP_MODE == "empty":
        return StepUpToken(token="", source="empty")
    if STEP_UP_MODE != "oauth":
        raise RuntimeError(f"Unsupported CODEX_STEP_UP_MODE={STEP_UP_MODE!r}; use oauth or empty.")
    return StepUpToken(token=oauth_step_up_token(auth_token), source="oauth")
