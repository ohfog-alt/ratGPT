from __future__ import annotations

import hashlib
import json
import re
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .state import DEFAULT_ARTIFACT_DIR, load_config, save_config


GITHUB_LATEST_RELEASE_URL = "https://api.github.com/repos/openai/codex/releases/latest"
CONFIG_RELEASE_KEY = "codex_release"
BUNDLED_DEFAULT_RELEASE = "rust-v0.160.0"


@dataclass(frozen=True)
class ReleaseInfo:
    tag: str
    name: str
    html_url: str
    assets: dict[str, str]


def configured_release() -> str:
    config = load_config()
    value = config.get(CONFIG_RELEASE_KEY)
    return value if isinstance(value, str) and value else BUNDLED_DEFAULT_RELEASE


def set_configured_release(release: str) -> None:
    config = load_config()
    config[CONFIG_RELEASE_KEY] = release
    save_config(config)


def release_artifact_dir(release: str) -> Path:
    return DEFAULT_ARTIFACT_DIR / release


def parse_release_version(tag: str) -> tuple[int, ...] | None:
    match = re.search(r"(\d+(?:\.\d+)+)", tag)
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def is_newer_release(latest: str, current: str) -> bool:
    latest_version = parse_release_version(latest)
    current_version = parse_release_version(current)
    if latest_version is not None and current_version is not None:
        return latest_version > current_version
    return latest != current


def fetch_latest_release() -> ReleaseInfo:
    request = urllib.request.Request(
        GITHUB_LATEST_RELEASE_URL,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "ratgpt-release-check/0.1",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        body = json.loads(response.read().decode("utf-8"))
    assets: dict[str, str] = {}
    for asset in body.get("assets") or []:
        if not isinstance(asset, dict):
            continue
        name = asset.get("name")
        url = asset.get("browser_download_url")
        if isinstance(name, str) and isinstance(url, str):
            assets[name] = url
    tag = body.get("tag_name")
    if not isinstance(tag, str) or not tag:
        raise RuntimeError(f"GitHub latest release returned unexpected body: {body!r}")
    return ReleaseInfo(
        tag=tag,
        name=body.get("name") if isinstance(body.get("name"), str) else tag,
        html_url=body.get("html_url") if isinstance(body.get("html_url"), str) else "",
        assets=assets,
    )


def download_url(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    request = urllib.request.Request(url, headers={"User-Agent": "ratgpt-release-check/0.1"})
    with urllib.request.urlopen(request, timeout=120) as response:
        with destination.open("wb") as handle:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                handle.write(chunk)
    destination.chmod(0o600)


def parse_checksums(path: Path) -> dict[str, str]:
    checksums: dict[str, str] = {}
    if not path.exists():
        return checksums
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
            checksums[Path(parts[-1]).name] = parts[0].lower()
    return checksums


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_release_assets(release: ReleaseInfo, asset_names: list[str]) -> list[Path]:
    out_dir = release_artifact_dir(release.tag)
    checksum_name = "codex-package_SHA256SUMS"
    checksum_path = out_dir / checksum_name
    if checksum_name in release.assets and not checksum_path.exists():
        download_url(release.assets[checksum_name], checksum_path)
    checksums = parse_checksums(checksum_path)

    downloaded: list[Path] = []
    for asset_name in asset_names:
        url = release.assets.get(asset_name)
        if not url:
            raise RuntimeError(f"release {release.tag} does not contain asset {asset_name}")
        destination = out_dir / asset_name
        if not destination.exists():
            print(f"downloading {asset_name}", file=sys.stderr)
            download_url(url, destination)
        expected = checksums.get(asset_name)
        if expected:
            actual = sha256_file(destination)
            if actual != expected:
                raise RuntimeError(f"checksum mismatch for {asset_name}: expected {expected}, got {actual}")
        downloaded.append(destination)
    return downloaded


def prompt_yes_no(question: str) -> bool:
    if not sys.stdin.isatty():
        return False
    answer = input(f"{question} [y/N] ").strip().lower()
    return answer in {"y", "yes"}
