from __future__ import annotations

import os
import shutil
import stat
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

from .releases import BUNDLED_DEFAULT_RELEASE, configured_release, release_artifact_dir
from .state import DEFAULT_ARTIFACT_DIR, DEFAULT_AUTH_PATH
from .preseed import preseed_remote_control

DEFAULT_RELEASE = os.environ.get("RATGPT_CODEX_RELEASE", configured_release())

TARGETS = {
    ("linux", "arm64"): "codex-package-aarch64-unknown-linux-musl.tar.gz",
    ("linux", "x64"): "codex-package-x86_64-unknown-linux-musl.tar.gz",
    ("mac", "arm64"): "codex-package-aarch64-apple-darwin.tar.gz",
    ("mac", "x64"): "codex-package-x86_64-apple-darwin.tar.gz",
    ("windows", "arm64"): "codex-package-aarch64-pc-windows-msvc.tar.gz",
    ("windows", "x64"): "codex-package-x86_64-pc-windows-msvc.tar.gz",
}


def release_for_payload() -> str:
    return os.environ.get("RATGPT_CODEX_RELEASE", configured_release())


def local_artifact_candidates(release: str, asset: str) -> list[Path]:
    candidates = [
        release_artifact_dir(release) / asset,
        Path(f"~/scratch/remote-codex-artifacts/{release}/downloads/{asset}").expanduser(),
    ]
    if release == BUNDLED_DEFAULT_RELEASE:
        candidates.append(DEFAULT_ARTIFACT_DIR / asset)
    return candidates


def normalize_arch(arch: str) -> str:
    value = arch.lower()
    if value in {"aarch64", "arm64"}:
        return "arm64"
    if value in {"x86_64", "amd64", "x64"}:
        return "x64"
    if value == "auto":
        import platform

        return normalize_arch(platform.machine())
    raise ValueError(f"unsupported arch: {arch}")


def find_or_download_archive(os_name: str, arch: str, *, standalone_archive: str | None = None) -> Path:
    if standalone_archive:
        path = Path(standalone_archive).expanduser()
        if not path.exists():
            raise FileNotFoundError(path)
        return path
    key = (os_name, arch)
    asset = TARGETS.get(key)
    if not asset:
        raise RuntimeError(
            f"no known managed standalone asset for --os {os_name} --arch {arch}; "
            "provide --standalone-archive"
        )
    release = release_for_payload()
    for candidate in local_artifact_candidates(release, asset):
        if candidate.exists():
            return candidate
    destination = release_artifact_dir(release) / asset
    destination.parent.mkdir(parents=True, exist_ok=True)
    url = f"https://github.com/openai/codex/releases/download/{release}/{asset}"
    urllib.request.urlretrieve(url, destination)
    destination.chmod(0o600)
    return destination


def write_launcher(stage: Path, os_name: str, *, detach: bool = False) -> None:
    if os_name == "windows":
        if detach:
            raise ValueError("--detach is currently supported only for macOS and Linux payloads")
        script = stage / "run-controlled.ps1"
        script.write_text(
            "$root = Split-Path -Parent $MyInvocation.MyCommand.Path\n"
            "$env:HOME = $root\n"
            "$env:CODEX_HOME = Join-Path $root '.codex'\n"
            "$codex = Join-Path $env:CODEX_HOME 'packages/standalone/current/bin/codex.exe'\n"
            "& $codex login status\n"
            "& $codex remote-control start --json\n",
            encoding="utf-8",
        )
        return
    script = stage / "run-controlled.sh"
    lines = [
        "#!/usr/bin/env sh",
        "set -eu",
        'ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"',
        'export HOME="$ROOT"',
        'export CODEX_HOME="$ROOT/.codex"',
        'export PATH="$CODEX_HOME/packages/standalone/current/bin:$PATH"',
        'CODEX="$CODEX_HOME/packages/standalone/current/bin/codex"',
        'if [ ! -e "$CODEX_HOME/packages/standalone/current/codex" ]; then',
        '  ln -s "bin/codex" "$CODEX_HOME/packages/standalone/current/codex"',
        "fi",
    ]
    if detach:
        lines.extend(
            [
                'LOG_DIR="$ROOT/logs"',
                'RUNTIME_DIR="$ROOT/runtime"',
                'LOG_PATH="$LOG_DIR/remote-control.log"',
                'PID_PATH="$RUNTIME_DIR/remote-control.pid"',
                'mkdir -p "$LOG_DIR" "$RUNTIME_DIR"',
                ': > "$LOG_PATH"',
                "nohup sh -c '",
                '  "$1" login status',
                '  "$1" remote-control start --json',
                '\' sh "$CODEX" >>"$LOG_PATH" 2>&1 </dev/null &',
                'PID="$!"',
                'printf "%s\\n" "$PID" > "$PID_PATH"',
                'printf "remote control started in background; pid=%s; log=%s\\n" "$PID" "$LOG_PATH"',
            ]
        )
    else:
        lines.extend(
            [
                '"$CODEX" login status',
                '"$CODEX" remote-control start --json',
            ]
        )
    script.write_text("\n".join(lines) + "\n", encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def build_payload(
    *,
    os_name: str,
    arch: str,
    output: str | None = None,
    standalone_archive: str | None = None,
    detach: bool = False,
) -> Path:
    os_name = os_name.lower()
    arch = normalize_arch(arch)
    if os_name not in {"linux", "mac", "windows"}:
        raise ValueError("--os must be linux, mac, or windows")
    if os_name == "windows" and detach:
        raise ValueError("--detach is currently supported only for macOS and Linux payloads")
    auth_path = DEFAULT_AUTH_PATH
    if not auth_path.exists():
        raise FileNotFoundError(f"missing ratGPT auth at {auth_path}; run ratgpt login first")
    archive = find_or_download_archive(os_name, arch, standalone_archive=standalone_archive)
    out = Path(output or f"ratgpt-payload-{os_name}-{arch}.zip").expanduser().resolve()

    with tempfile.TemporaryDirectory(prefix="ratgpt-payload.") as tmp:
        stage = Path(tmp) / "ratgpt-controlled"
        current = stage / ".codex/packages/standalone/current"
        bin_dir = current / "bin"
        bin_dir.mkdir(parents=True)
        shutil.copy2(auth_path, stage / ".codex/auth.json")
        (stage / ".codex/auth.json").chmod(0o600)

        if tarfile.is_tarfile(archive):
            with tarfile.open(archive) as tar:
                tar.extractall(current)
        elif archive.suffix.lower() == ".zip":
            with zipfile.ZipFile(archive) as zf:
                zf.extractall(current)
        else:
            raise RuntimeError(f"unsupported standalone archive format: {archive}")

        codex_name = "codex.exe" if os_name == "windows" else "codex"
        codex_bin = bin_dir / codex_name
        if not codex_bin.exists() and (current / "bin/codex").exists() and os_name != "windows":
            codex_bin = current / "bin/codex"
        if not codex_bin.exists():
            raise RuntimeError(f"archive did not produce expected binary under {bin_dir}")
        codex_bin.chmod(codex_bin.stat().st_mode | stat.S_IXUSR)
        current_codex = current / codex_name
        if current_codex.exists() and current_codex.is_file() and current_codex.resolve() != codex_bin.resolve():
            current_codex.unlink()

        preseed_remote_control(stage, os_name=os_name, arch=arch, release=release_for_payload())
        write_launcher(stage, os_name, detach=detach)
        out.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for path in stage.rglob("*"):
                zf.write(path, path.relative_to(stage.parent))
        out.chmod(0o600)
    return out
