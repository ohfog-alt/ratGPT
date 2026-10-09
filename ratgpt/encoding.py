from __future__ import annotations

import base64
import json
from typing import Any


def base64_standard(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def json_compact(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def json_pretty(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False)


def utf8_bytes(value: str) -> bytes:
    return value.encode("utf-8")
