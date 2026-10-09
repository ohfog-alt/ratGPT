from __future__ import annotations

import json
from typing import Any

import websockets

from .encoding import json_compact


async def connect_websocket(url: str, headers: dict[str, str]):
    try:
        return await websockets.connect(
            url,
            additional_headers=headers,
            ping_interval=10,
            ping_timeout=60,
            max_size=None,
        )
    except TypeError:
        return await websockets.connect(
            url,
            extra_headers=headers,
            ping_interval=10,
            ping_timeout=60,
            max_size=None,
        )


async def send_json(ws: Any, value: dict[str, Any]) -> None:
    await ws.send(json_compact(value))


def parse_text_message(message: str | bytes) -> dict[str, Any]:
    if isinstance(message, bytes):
        message = message.decode("utf-8")
    return json.loads(message)
