from __future__ import annotations

import asyncio
import base64
import json
import sys
import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

from .api import controller_websocket_url
from .auth import get_auth_status_with_token
from .controller_session import (
    SESSION_REFRESH_SKEW_SECONDS,
    controller_headers,
    refresh_client_session,
    select_environment,
    validate_websocket_challenge,
    websocket_proof,
)
from .device_key import load_existing_controller_identity
from .encoding import json_compact
from .logutil import log, sanitize
from .websocket_utils import connect_websocket, parse_text_message, send_json

STREAM_PING_SECONDS = 30
REQUEST_TIMEOUT_SECONDS = 120

NotificationHandler = Callable[[dict[str, Any]], None | Awaitable[None]]


class ServerMessageReassembler:
    def __init__(self) -> None:
        self.assemblies: dict[str, dict[str, Any]] = {}

    def observe(self, envelope: dict[str, Any]) -> dict[str, Any] | None:
        if envelope.get("type") != "server_message_chunk":
            return envelope
        key = f"{envelope.get('env_id')}:{envelope.get('stream_id')}:{envelope.get('seq_id')}"
        assembly = self.assemblies.setdefault(
            key,
            {"first": envelope, "chunks": [None] * int(envelope.get("segment_count") or 0)},
        )
        chunks = assembly["chunks"]
        segment_id = int(envelope.get("segment_id") or 0)
        if segment_id < 0 or segment_id >= len(chunks):
            self.assemblies.pop(key, None)
            return None
        chunks[segment_id] = envelope.get("message_chunk_base64")
        if any(chunk is None for chunk in chunks):
            return None
        self.assemblies.pop(key, None)
        payload = b"".join(base64.b64decode(chunk) for chunk in chunks)
        if len(payload) != int(envelope.get("message_size_bytes") or len(payload)):
            return None
        try:
            message = json.loads(payload.decode("utf-8"))
        except json.JSONDecodeError:
            return None
        return {
            "type": "server_message",
            "client_id": envelope.get("client_id"),
            "env_id": envelope.get("env_id"),
            "stream_id": envelope.get("stream_id"),
            "seq_id": envelope.get("seq_id"),
            "cursor": envelope.get("cursor"),
            "message": message,
        }


class RemoteAppServer:
    def __init__(self, *, target: str | None = None, notification_handler: NotificationHandler | None = None) -> None:
        self.target = target
        self.notification_handler = notification_handler
        self.auth_token: str | None = None
        self.key_state: Any | None = None
        self.enrollment: dict[str, Any] | None = None
        self.session: dict[str, Any] | None = None
        self.env: dict[str, Any] | None = None
        self.ws: Any | None = None
        self.ready = False
        self.stream_id = str(uuid.uuid4())
        self.next_seq_id = 1
        self.next_request_id = 1
        self.cursor: str | None = None
        self.unacked: dict[str, dict[str, Any]] = {}
        self.pending: dict[int, asyncio.Future[Any]] = {}
        self.reassembler = ServerMessageReassembler()
        self.reader_task: asyncio.Task[Any] | None = None
        self.ping_task: asyncio.Task[Any] | None = None
        self.initialized = False
        self.has_connected = False
        self.send_lock = asyncio.Lock()

    @property
    def controlled_label(self) -> str:
        env = self.env or {}
        return str(env.get("display_name") or env.get("host_name") or env.get("name") or env.get("env_id") or self.target)

    async def connect(self) -> None:
        auth = get_auth_status_with_token(client_name="ratgpt-auth", client_title="ratGPT")
        self.auth_token = auth.token
        self.key_state, self.enrollment = load_existing_controller_identity()
        target_env_id = self.target if isinstance(self.target, str) and self.target.startswith("env_") else None
        target_env_name = self.target if target_env_id is None else None
        self.env = await select_environment(
            auth.token,
            target_env_name=target_env_name,
            target_env_id=target_env_id,
        )
        self.session = await refresh_client_session(
            auth_token=auth.token,
            enrollment=self.enrollment,
            key_state=self.key_state,
        )
        await self._open_ws()
        self.reader_task = asyncio.create_task(self._reader_loop())
        self.ping_task = asyncio.create_task(self._ping_loop())
        await self.initialize()

    async def close(self) -> None:
        if self.ping_task:
            self.ping_task.cancel()
            self.ping_task = None
        if self.reader_task:
            self.reader_task.cancel()
            self.reader_task = None
        await self._send_client_closed()
        if self.ws:
            await self.ws.close()
            self.ws = None
        self.ready = False

    async def _refresh_session_for_connect(self) -> None:
        assert self.auth_token and self.enrollment and self.key_state
        now = int(time.time())
        if (
            not self.session
            or self.has_connected
            or self.session["tokenExpiresAt"] <= now + SESSION_REFRESH_SKEW_SECONDS
        ):
            self.session = await refresh_client_session(
                auth_token=self.auth_token,
                enrollment=self.enrollment,
                key_state=self.key_state,
            )

    async def _open_ws(self) -> None:
        assert self.auth_token and self.enrollment and self.session and self.key_state
        await self._refresh_session_for_connect()
        self.ws = await connect_websocket(
            controller_websocket_url(),
            controller_headers(
                auth_token=self.auth_token,
                enrollment=self.enrollment,
                session=self.session,
                cursor=self.cursor,
            ),
        )
        first = await asyncio.wait_for(self.ws.recv(), timeout=10)
        challenge = parse_text_message(first)
        if challenge.get("type") != "device_key_challenge":
            raise RuntimeError(f"Expected device_key_challenge, got {sanitize(challenge)}")
        validate_websocket_challenge(
            challenge=challenge,
            ws_url=controller_websocket_url(),
            enrollment=self.enrollment,
            remote_control_token=self.session["remoteControlToken"],
            token_expires_at=self.session["tokenExpiresAt"],
            scopes=self.session["scopes"],
        )
        await send_json(self.ws, websocket_proof(challenge=challenge, key_state=self.key_state))
        self.ready = True
        self.has_connected = True
        await self._replay_unacked()

    async def _reader_loop(self) -> None:
        assert self.ws is not None
        async for raw in self.ws:
            await self._handle_remote_text(raw)

    async def _handle_remote_text(self, raw: str | bytes) -> None:
        envelope = parse_text_message(raw)
        typ = envelope.get("type")
        if typ == "ack":
            self._handle_ack(envelope)
            return
        if typ == "pong":
            self._remember_cursor(envelope)
            if envelope.get("status") == "unknown":
                raise RuntimeError("remote stream became unknown")
            return
        if typ in {"server_message", "server_message_chunk"}:
            assembled = self.reassembler.observe(envelope)
            if not assembled:
                return
            self._remember_cursor(assembled)
            await self._handle_json_rpc(assembled.get("message"))
            return
        if typ == "device_key_challenge":
            return
        log("ratgpt-unknown-envelope", envelope=sanitize(envelope))

    async def _handle_json_rpc(self, message: Any) -> None:
        if not isinstance(message, dict):
            return
        msg_id = message.get("id")
        if isinstance(msg_id, int) and msg_id in self.pending:
            fut = self.pending.pop(msg_id)
            if message.get("error"):
                fut.set_exception(RuntimeError(f"JSON-RPC {msg_id} error: {json_compact(message['error'])}"))
            else:
                fut.set_result(message.get("result"))
            return
        if message.get("method") and self.notification_handler:
            result = self.notification_handler(message)
            if asyncio.iscoroutine(result):
                await result

    @staticmethod
    def _envelope_key(envelope: dict[str, Any]) -> str:
        return ":".join(
            [
                str(envelope.get("env_id") or ""),
                str(envelope.get("stream_id") or ""),
                str(envelope.get("seq_id") or ""),
                str(envelope.get("segment_id") or ""),
                str(envelope.get("type") or ""),
            ]
        )

    def _track(self, envelope: dict[str, Any]) -> None:
        self.unacked[self._envelope_key(envelope)] = envelope

    def _handle_ack(self, ack: dict[str, Any]) -> None:
        ack_segment_id = ack.get("segment_id", sys.maxsize)
        for key, envelope in list(self.unacked.items()):
            if envelope.get("env_id") != ack.get("env_id") or envelope.get("stream_id") != ack.get("stream_id"):
                continue
            segment_id = envelope.get("segment_id", 0)
            if envelope.get("seq_id", 0) < ack.get("seq_id", 0) or (
                envelope.get("seq_id") == ack.get("seq_id") and segment_id <= ack_segment_id
            ):
                self.unacked.pop(key, None)

    def _remember_cursor(self, envelope: dict[str, Any]) -> None:
        cursor = envelope.get("cursor")
        if isinstance(cursor, str) and cursor:
            self.cursor = cursor

    async def _send_envelope(self, envelope: dict[str, Any], *, track: bool = True) -> None:
        assert self.ws is not None
        if track:
            self._track(envelope)
        async with self.send_lock:
            await send_json(self.ws, envelope)

    async def _replay_unacked(self) -> None:
        for envelope in list(self.unacked.values()):
            await self._send_envelope(envelope, track=False)

    async def _send_client_message(self, message: dict[str, Any]) -> None:
        assert self.enrollment and self.env
        envelope = {
            "type": "client_message",
            "client_id": self.enrollment["clientId"],
            "env_id": self.env["env_id"],
            "stream_id": self.stream_id,
            "seq_id": self.next_seq_id,
            "skip_history": False,
            "message": message,
        }
        self.next_seq_id += 1
        await self._send_envelope(envelope)

    async def _send_ping(self) -> None:
        assert self.enrollment and self.env
        envelope = {
            "type": "ping",
            "client_id": self.enrollment["clientId"],
            "env_id": self.env["env_id"],
            "stream_id": self.stream_id,
            "seq_id": self.next_seq_id,
            "state": "foreground",
            "skip_history": True,
        }
        self.next_seq_id += 1
        await self._send_envelope(envelope)

    async def _send_client_closed(self) -> None:
        if not self.ws or not self.enrollment or not self.env:
            return
        envelope = {
            "type": "client_closed",
            "client_id": self.enrollment["clientId"],
            "env_id": self.env["env_id"],
            "stream_id": self.stream_id,
            "seq_id": self.next_seq_id,
        }
        self.next_seq_id += 1
        await self._send_envelope(envelope)

    async def _ping_loop(self) -> None:
        while True:
            await asyncio.sleep(STREAM_PING_SECONDS)
            await self._send_ping()

    async def request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        timeout: float = REQUEST_TIMEOUT_SECONDS,
    ) -> Any:
        req_id = self.next_request_id
        self.next_request_id += 1
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            message["params"] = params
        fut: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
        self.pending[req_id] = fut
        await self._send_client_message(message)
        return await asyncio.wait_for(fut, timeout=timeout)

    async def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        await self._send_client_message(message)

    async def initialize(self) -> Any:
        if self.initialized:
            return None
        result = await self.request(
            "initialize",
            {
                "clientInfo": {"name": "ratgpt", "title": "ratGPT", "version": "0.1.0"},
                "capabilities": {
                    "experimentalApi": True,
                    "requestAttestation": False,
                    "optOutNotificationMethods": [],
                },
            },
            timeout=30,
        )
        await self.notify("initialized")
        self.initialized = True
        return result
