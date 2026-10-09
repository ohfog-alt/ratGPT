from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


STATE_DIR = Path(os.environ.get("RATGPT_STATE_DIR", "~/.ratgpt")).expanduser()

DEFAULT_AUTH_PATH = Path(os.environ.get("RATGPT_AUTH_PATH", STATE_DIR / "auth.json")).expanduser()
DEFAULT_CONTROLLER_DEVICE_KEY_PATH = Path(
    os.environ.get("RATGPT_CONTROLLER_DEVICE_KEY_PATH", STATE_DIR / "controller-device-key.json")
).expanduser()
DEFAULT_CONTROLLER_ENROLLMENT_PATH = Path(
    os.environ.get("RATGPT_CONTROLLER_ENROLLMENT_PATH", STATE_DIR / "controller-enrollment.json")
).expanduser()
DEFAULT_CONFIG_PATH = Path(os.environ.get("RATGPT_CONFIG_PATH", STATE_DIR / "config.json")).expanduser()
DEFAULT_ARTIFACT_DIR = Path(os.environ.get("RATGPT_ARTIFACT_DIR", STATE_DIR / "artifacts")).expanduser()


def read_json_if_exists(path: str | Path) -> Any | None:
    file_path = Path(path).expanduser()
    if not file_path.exists():
        return None
    return json.loads(file_path.read_text(encoding="utf-8"))


def write_json_file(path: str | Path, value: Any, mode: int = 0o600) -> None:
    file_path = Path(path).expanduser()
    file_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    file_path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")
    file_path.chmod(mode)


def load_config() -> dict[str, Any]:
    config = read_json_if_exists(DEFAULT_CONFIG_PATH)
    return config if isinstance(config, dict) else {}


def save_config(config: dict[str, Any]) -> None:
    write_json_file(DEFAULT_CONFIG_PATH, config)
