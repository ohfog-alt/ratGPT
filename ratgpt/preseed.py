from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import uuid
from pathlib import Path
from typing import Any

from .api import post_json_sync
from .auth import chatgpt_account_id, get_auth_status_with_token
from .logutil import sanitize
from .releases import parse_release_version
from .state import DEFAULT_CONTROLLER_ENROLLMENT_PATH, read_json_if_exists


def _codex_platform(os_name: str, arch: str) -> tuple[str, str]:
    return ({"mac": "macos"}.get(os_name, os_name), {"arm64": "aarch64", "x64": "x86_64"}[arch])


def _initialize_state_db(codex_home: Path, release: str) -> tuple[Path, str]:
    codex_bin = os.environ.get("RATGPT_CODEX_BIN") or os.environ.get("CODEX_BIN") or shutil.which("codex")
    if not codex_bin:
        raise RuntimeError("preseed requires local Codex; set RATGPT_CODEX_BIN")
    expected = parse_release_version(release)
    version = subprocess.run([codex_bin, "--version"], check=True, capture_output=True, text=True).stdout
    if expected and ".".join(map(str, expected)) not in version:
        raise RuntimeError(f"local state builder {version.strip()} does not match payload release {release}")
    env = {**os.environ, "CODEX_HOME": str(codex_home), "HOME": str(codex_home.parent)}
    initialize = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"clientInfo": {"name": "ratgpt-preseed", "version": "0.1.0"}, "capabilities": {"experimentalApi": True}}}
    subprocess.run([codex_bin, "app-server", "--stdio"], input=json.dumps(initialize) + "\n", env=env, capture_output=True, text=True, timeout=15, check=True)
    state_db = codex_home / "state_5.sqlite"
    installation_path = codex_home / "installation_id"
    if not state_db.exists() or not installation_path.exists():
        raise RuntimeError("local Codex did not create state_5.sqlite and installation_id")
    for generated in codex_home.glob("*.sqlite"):
        if generated != state_db:
            generated.unlink()
    return state_db, installation_path.read_text(encoding="utf-8").strip()


def preseed_remote_control(stage: Path, *, os_name: str, arch: str, release: str, server_name: str | None = None) -> dict[str, Any]:
    codex_home = stage / ".codex"
    state_db, installation_id = _initialize_state_db(codex_home, release)
    auth = get_auth_status_with_token(client_name="ratgpt-preseed-auth", client_title="ratGPT Preseed")
    account_id = chatgpt_account_id(auth.token)
    if not account_id:
        raise RuntimeError("preseed auth token has no ChatGPT account id")
    enrollment = read_json_if_exists(DEFAULT_CONTROLLER_ENROLLMENT_PATH)
    if not isinstance(enrollment, dict) or not isinstance(enrollment.get("clientId"), str):
        raise RuntimeError("missing controller enrollment; run `ratgpt enroll` first")
    target_os, target_arch = _codex_platform(os_name, arch)
    name = server_name or f"ratgpt-{uuid.uuid4().hex[:8]}"
    server = post_json_sync(
        "/wham/remote/control/server/enroll",
        {"name": name, "os": target_os, "arch": target_arch, "app_server_version": ".".join(map(str, parse_release_version(release) or ())), "installation_id": installation_id},
        auth.token, installation_id=installation_id, user_agent="ratgpt/0.1",
    )
    required = ("server_id", "environment_id", "remote_control_token")
    if not isinstance(server, dict) or any(not isinstance(server.get(key), str) for key in required):
        raise RuntimeError(f"server/enroll returned unexpected body: {sanitize(server)}")
    pairing = post_json_sync("/wham/remote/control/server/pair", {"manual_code": True}, server["remote_control_token"], user_agent="ratgpt/0.1")
    code = pairing.get("manual_pairing_code") if isinstance(pairing, dict) else None
    if not isinstance(code, str):
        raise RuntimeError(f"server/pair returned no manual code: {sanitize(pairing)}")
    post_json_sync("/wham/remote/control/client/pair", {"client_id": enrollment["clientId"], "manual_pairing_code": code}, auth.token, user_agent="ratgpt/0.1")
    status = post_json_sync("/wham/remote/control/server/pair/status", {"manual_pairing_code": code}, server["remote_control_token"], user_agent="ratgpt/0.1")
    if status != {"claimed": True}:
        raise RuntimeError(f"pairing was not claimed: {sanitize(status)}")
    with sqlite3.connect(state_db) as db:
        db.execute("INSERT OR REPLACE INTO remote_control_enrollments (websocket_url,account_id,app_server_client_name,server_id,environment_id,server_name,remote_control_enabled,updated_at) VALUES (?,?,?,?,?,?,NULL,strftime('%s','now'))", ("wss://chatgpt.com/backend-api/wham/remote/control/server", account_id, "", server["server_id"], server["environment_id"], name))
        db.commit()
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
    for suffix in ("-wal", "-shm"):
        Path(f"{state_db}{suffix}").unlink(missing_ok=True)
    return {"environment_id": server["environment_id"], "server_name": name}
