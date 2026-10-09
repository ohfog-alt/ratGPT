from __future__ import annotations

import argparse
import asyncio
import json
import shlex
import sys
from pathlib import Path
from typing import Any

from .api import get_json_sync, post_json_sync, with_query
from .auth import get_auth_status_with_token
from .device_auth_login import (
    build_auth_json,
    default_codex_home,
    exchange_authorization_code,
    poll_for_authorization_code,
    request_device_code,
    write_codex_auth,
)
from .device_key import (
    build_enrollment_record,
    device_identity,
    device_identity_hash,
    load_or_create_software_device_key,
    sign_device_key_payload,
    write_enrollment,
)
from .logutil import log, sanitize, set_verbose, short_id
from .oauth import resolve_step_up_token
from .ops import AppServerOps, parse_argv
from .payload import TARGETS, build_payload, normalize_arch, release_for_payload
from .releases import (
    configured_release,
    download_release_assets,
    fetch_latest_release,
    is_newer_release,
    prompt_yes_no,
    set_configured_release,
)
from .remote import RemoteAppServer
from .state import DEFAULT_AUTH_PATH, DEFAULT_CONTROLLER_DEVICE_KEY_PATH, DEFAULT_CONTROLLER_ENROLLMENT_PATH

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None


HELP_TEXT = """ratGPT REPL commands

/help
  Show this help.
/controlleds
  List online controlled Codex hosts visible to this account.
/use <controlled>, /attach <controlled>
  Select a controlled host by env id, display name, host name, or name.
/detach
  Close the current remote app-server stream.
/status
  Show active controlled host and remote cwd.
/exec <shell command>
  Run a one-shot shell command using process/spawn ["bash","-lc", command].
/spawn <argv...>
  Run raw argv with process/spawn. No shell parsing beyond local shlex.
/shell
  Start an interactive bash -i PTY on the controlled host. Type exit to return.
/put <local> <remote_abs_path>
  Upload a local file with fs/writeFile.
/get <remote_abs_path> <local>
  Download a remote file with fs/readFile.
/ls <remote_abs_dir>, /ll <remote_abs_dir>
  List a remote directory using fs/readDirectory and optional metadata.
/mkdir <remote_abs_dir>
  Create a remote directory.
/rm <remote_abs_path>
  Remove a remote file or directory tree.
/cp <remote_abs_src> <remote_abs_dst>
  Copy a remote file or directory tree.
/pwd
  Print ratGPT's remote cwd for process/spawn.
/cd <remote_abs_or_relative_dir>
  Change ratGPT's remote cwd for process/spawn.
/exit
  Leave the REPL.
"""

CONTROLLED_WATCH_INTERVAL_SECONDS = 5


def challenge_payload(start_body: dict[str, Any], challenge: dict[str, Any], identity_hash: str) -> dict[str, Any]:
    return {
        "type": "remoteControlClientEnrollment",
        "nonce": challenge.get("nonce"),
        "audience": challenge.get("audience"),
        "challengeId": challenge.get("challenge_id"),
        "targetOrigin": challenge.get("target_origin"),
        "targetPath": challenge.get("target_path"),
        "accountUserId": start_body.get("account_user_id"),
        "clientId": start_body.get("client_id"),
        "deviceIdentitySha256Base64url": challenge.get("device_identity_hash") or identity_hash,
        "challengeExpiresAt": challenge.get("challenge_expires_at"),
    }


def cmd_login(args: argparse.Namespace) -> int:
    if httpx is None:
        raise RuntimeError("httpx is required")
    with httpx.Client(timeout=30) as client:
        device_code = request_device_code(client)
        print(f"Open: {device_code.verification_url}")
        print(f"Code: {device_code.user_code}")
        authorization = poll_for_authorization_code(client, device_code)
        tokens = exchange_authorization_code(client, authorization)
    result = write_codex_auth(default_codex_home(), build_auth_json(tokens), force=args.force, backup=True)
    print(f"auth: {result.path}")
    if result.backup_path:
        print(f"backup: {result.backup_path}")
    if result.email:
        print(f"email: {result.email}")
    if result.account_id:
        print(f"account: {short_id(result.account_id)}")
    return 0


def cmd_enroll(args: argparse.Namespace) -> int:
    key_state = load_or_create_software_device_key(DEFAULT_CONTROLLER_DEVICE_KEY_PATH)
    identity = device_identity(key_state.device_key)
    identity_hash = device_identity_hash(key_state.device_key)
    auth = get_auth_status_with_token(client_name="ratgpt-enroll-auth", client_title="ratGPT Enroll Auth")
    step_up = resolve_step_up_token(auth.token)
    start = post_json_sync("/codex/remote/control/client/enroll/start", {}, auth.token, user_agent="ratgpt/0.1")
    challenge = start.get("device_key_challenge") if isinstance(start, dict) else None
    if not isinstance(start.get("client_id"), str) or not isinstance(start.get("account_user_id"), str) or not challenge:
        raise RuntimeError(f"enroll/start returned unexpected body: {sanitize(start)}")
    signed_payload = challenge_payload(start, challenge, identity_hash)
    proof = sign_device_key_payload(key_state.device_key, signed_payload)
    finish = post_json_sync(
        "/codex/remote/control/client/enroll/finish",
        {
            "client_id": start["client_id"],
            "step_up_token": step_up.token,
            "device_identity": identity,
            "device_key_proof": {
                "challenge_token": challenge.get("challenge_token"),
                "key_id": key_state.device_key.key_id,
                "signature_der_base64": proof["signatureDerBase64"],
                "signed_payload_base64": proof["signedPayloadBase64"],
                "algorithm": key_state.device_key.algorithm,
            },
        },
        auth.token,
        user_agent="ratgpt/0.1",
    )
    if not isinstance(finish.get("client_id"), str) or not isinstance(finish.get("account_user_id"), str):
        raise RuntimeError(f"enroll/finish returned unexpected body: {sanitize(finish)}")
    write_enrollment(
        build_enrollment_record(
            account_user_id=finish["account_user_id"],
            client_id=finish["client_id"],
            device_key=key_state.device_key,
            source="ratgpt-enroll",
        ),
        DEFAULT_CONTROLLER_ENROLLMENT_PATH,
    )
    print("Controller enrollment complete.")
    print(f"  client id: {short_id(finish['client_id'])}")
    print(f"  enrollment: {DEFAULT_CONTROLLER_ENROLLMENT_PATH}")
    print(f"  device key: {DEFAULT_CONTROLLER_DEVICE_KEY_PATH}")
    print(f"  step-up source: {step_up.source}")
    return 0


def list_controlleds(*, online_only: bool = False) -> list[dict[str, Any]]:
    auth = get_auth_status_with_token(client_name="ratgpt-controlleds", client_title="ratGPT Controlleds")
    body = get_json_sync(with_query("/codex/remote/control/environments", {"limit": 100}), auth.token, user_agent="ratgpt/0.1")
    items = body.get("items") if isinstance(body, dict) else []
    results = [item for item in items if isinstance(item, dict)]
    if online_only:
        results = [item for item in results if item.get("online") is True]
    return results


def controlled_state(item: dict[str, Any]) -> str:
    if item.get("online") is not True:
        return "offline"
    if item.get("busy") is True:
        return "busy"
    return "ready"


def controlled_name(item: dict[str, Any]) -> str:
    return str(item.get("display_name") or item.get("host_name") or item.get("name") or item.get("env_id") or "(unknown)")


def format_controlled(item: dict[str, Any]) -> str:
    return (
        f"{short_id(item.get('env_id')):16} "
        f"state={controlled_state(item):7} "
        f"online={str(item.get('online')).lower():5} "
        f"busy={str(item.get('busy')).lower():5} "
        f"name={controlled_name(item)}"
    )


def online_controlled_ids(items: list[dict[str, Any]]) -> set[str]:
    return {
        env_id
        for item in items
        if item.get("online") is True and isinstance((env_id := item.get("env_id")), str)
    }


def newly_online_controlleds(previous_online_ids: set[str], items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        item
        for item in items
        if item.get("online") is True
        and isinstance(item.get("env_id"), str)
        and item["env_id"] not in previous_online_ids
    ]


def print_controlleds(args: argparse.Namespace) -> int:
    items = list_controlleds(online_only=not args.all)
    if args.json:
        print(json.dumps(items, indent=2, ensure_ascii=False))
        return 0
    for item in items:
        print(format_controlled(item))
    return 0


async def with_ops(controlled: str, fn):
    ops_holder: dict[str, AppServerOps] = {}

    def on_notification(message: dict[str, Any]) -> None:
        ops = ops_holder.get("ops")
        if ops:
            ops.handle_notification(message)

    remote = RemoteAppServer(target=controlled, notification_handler=on_notification)
    await remote.connect()
    ops = AppServerOps(remote)
    ops_holder["ops"] = ops
    try:
        return await fn(ops)
    finally:
        await remote.close()


def require_controlled(args: argparse.Namespace) -> str:
    if not args.controlled:
        raise RuntimeError("targeted commands require --controlled/-c")
    return args.controlled


def cmd_exec(args: argparse.Namespace) -> int:
    async def run(ops: AppServerOps) -> int:
        return await ops.exec_shell(args.command)

    return asyncio.run(with_ops(require_controlled(args), run))


def cmd_spawn(args: argparse.Namespace) -> int:
    async def run(ops: AppServerOps) -> int:
        return await ops.run_process(args.argv)

    return asyncio.run(with_ops(require_controlled(args), run))


def cmd_shell(args: argparse.Namespace) -> int:
    async def run(ops: AppServerOps) -> int:
        return await ops.shell()

    return asyncio.run(with_ops(require_controlled(args), run))


def cmd_put(args: argparse.Namespace) -> int:
    async def run(ops: AppServerOps) -> int:
        await ops.write_file(args.local, args.remote)
        print(f"uploaded {args.local} -> {args.remote}")
        return 0

    return asyncio.run(with_ops(require_controlled(args), run))


def cmd_get(args: argparse.Namespace) -> int:
    async def run(ops: AppServerOps) -> int:
        await ops.get_file(args.remote, args.local)
        print(f"downloaded {args.remote} -> {args.local}")
        return 0

    return asyncio.run(with_ops(require_controlled(args), run))


def cmd_ls(args: argparse.Namespace, *, long: bool = False) -> int:
    async def run(ops: AppServerOps) -> int:
        await ops.ls(args.path, long=long)
        return 0

    return asyncio.run(with_ops(require_controlled(args), run))


def cmd_payload(args: argparse.Namespace) -> int:
    out = build_payload(
        os_name=args.os,
        arch=args.arch,
        output=args.out,
        standalone_archive=args.standalone_archive,
        detach=args.detach,
    )
    print(out)
    return 0


def _selected_release_assets(args: argparse.Namespace) -> list[str]:
    if args.all_targets or (not args.os and args.arch == "all"):
        return sorted(set(TARGETS.values()))
    if not args.os:
        import platform

        system = platform.system().lower()
        if system == "darwin":
            os_name = "mac"
        elif system == "windows":
            os_name = "windows"
        else:
            os_name = "linux"
    else:
        os_name = args.os
    if args.arch == "all":
        return sorted(asset for (target_os, _), asset in TARGETS.items() if target_os == os_name)
    return [TARGETS[(os_name, normalize_arch(args.arch))]]


def cmd_release_check(args: argparse.Namespace) -> int:
    current = release_for_payload()
    configured = configured_release()
    latest = fetch_latest_release()
    newer = is_newer_release(latest.tag, current)
    asset_names = _selected_release_assets(args)
    missing = [name for name in asset_names if name not in latest.assets]

    if args.json:
        print(
            json.dumps(
                {
                    "current_release": current,
                    "configured_release": configured,
                    "latest_release": latest.tag,
                    "newer_available": newer,
                    "selected_assets": asset_names,
                    "missing_assets": missing,
                    "url": latest.html_url,
                },
                indent=2,
            )
        )
        return 0 if not missing else 1

    print(f"current payload release: {current}")
    if configured != current:
        print(f"configured release:       {configured}")
    print(f"latest GitHub release:    {latest.tag}")
    if latest.html_url:
        print(f"release URL:              {latest.html_url}")
    print(f"newer available:          {str(newer).lower()}")
    if missing:
        print("missing expected assets:")
        for name in missing:
            print(f"  {name}")
        return 1

    should_download = bool(args.download)
    should_use = bool(args.use)
    if newer and not should_download and not should_use:
        if args.yes or prompt_yes_no(f"Download {len(asset_names)} selected assets and use {latest.tag} for new payloads?"):
            should_download = True
            should_use = True

    if should_download:
        paths = download_release_assets(latest, asset_names)
        print("downloaded/cached assets:")
        for path in paths:
            print(f"  {path}")

    if should_use:
        set_configured_release(latest.tag)
        print(f"configured new payloads to use: {latest.tag}")
        print("override per-run with RATGPT_CODEX_RELEASE=<tag> if needed")

    if newer and not should_download and not should_use:
        print(f"run `ratgpt release-check --download --use` to cache assets and use {latest.tag}")
    return 0


class Repl:
    def __init__(self) -> None:
        self.remote: RemoteAppServer | None = None
        self.ops: AppServerOps | None = None
        self.controlled: str | None = None
        self.watcher_task: asyncio.Task[Any] | None = None
        self.online_ids: set[str] = set()

    async def attach(self, controlled: str) -> None:
        await self.detach()

        def on_notification(message: dict[str, Any]) -> None:
            if self.ops:
                self.ops.handle_notification(message)

        self.remote = RemoteAppServer(target=controlled, notification_handler=on_notification)
        await self.remote.connect()
        self.ops = AppServerOps(self.remote)
        self.controlled = controlled
        print(f"attached: {self.remote.controlled_label}")

    async def detach(self) -> None:
        if self.remote:
            await self.remote.close()
        self.remote = None
        self.ops = None
        self.controlled = None

    async def watch_controlleds(self) -> None:
        while True:
            await asyncio.sleep(CONTROLLED_WATCH_INTERVAL_SECONDS)
            try:
                items = await asyncio.to_thread(list_controlleds, online_only=False)
            except Exception as error:
                log("ratgpt-controlled-watch-error", error=str(error))
                continue
            for item in newly_online_controlleds(self.online_ids, items):
                print(f"\ncontrolled ready: {controlled_name(item)} ({short_id(item.get('env_id'))})")
            self.online_ids = online_controlled_ids(items)

    def require_ops(self) -> AppServerOps:
        if not self.ops:
            raise RuntimeError("no controlled host selected; use /controlleds then /use <controlled>")
        return self.ops

    async def handle(self, line: str) -> bool:
        if not line.strip():
            return True
        if not line.startswith("/"):
            print("commands must start with /; use /help")
            return True
        cmdline = line[1:]
        parts = shlex.split(cmdline)
        if not parts:
            return True
        cmd, args = parts[0], parts[1:]
        if cmd == "help":
            print(HELP_TEXT)
        elif cmd == "exit":
            return False
        elif cmd == "controlleds":
            show_all = bool(args and args[0] == "all")
            for item in list_controlleds(online_only=not show_all):
                print(format_controlled(item))
        elif cmd in {"use", "attach"}:
            if len(args) != 1:
                print("usage: /use <controlled>")
            else:
                await self.attach(args[0])
        elif cmd == "detach":
            await self.detach()
            print("detached")
        elif cmd == "status":
            if self.remote and self.ops:
                print(f"controlled={self.remote.controlled_label} cwd={self.ops.cwd}")
            else:
                print("detached")
        elif cmd == "exec":
            await self.require_ops().exec_shell(cmdline.partition(" ")[2])
        elif cmd == "spawn":
            await self.require_ops().run_process(args)
        elif cmd == "shell":
            await self.require_ops().shell()
            print("[ratgpt] returned from remote shell")
        elif cmd == "put" and len(args) == 2:
            await self.require_ops().write_file(args[0], args[1])
            print(f"uploaded {args[0]} -> {args[1]}")
        elif cmd == "get" and len(args) == 2:
            await self.require_ops().get_file(args[0], args[1])
            print(f"downloaded {args[0]} -> {args[1]}")
        elif cmd in {"ls", "ll"}:
            path = args[0] if args else self.require_ops().cwd
            await self.require_ops().ls(path, long=cmd == "ll")
        elif cmd == "mkdir" and len(args) == 1:
            await self.require_ops().mkdir(args[0])
        elif cmd == "rm" and len(args) == 1:
            await self.require_ops().remove(args[0])
        elif cmd == "cp" and len(args) == 2:
            await self.require_ops().copy(args[0], args[1])
        elif cmd == "pwd":
            print(self.require_ops().cwd)
        elif cmd == "cd" and len(args) == 1:
            print(self.require_ops().cd(args[0]))
        else:
            print(f"unknown or invalid command: /{cmd}; use /help")
        return True

    async def run(self) -> int:
        print("ratGPT REPL. Use /help, /controlleds, /use <controlled>, /exit.")
        loop = asyncio.get_running_loop()
        try:
            try:
                initial_items = await asyncio.to_thread(list_controlleds, online_only=False)
                self.online_ids = online_controlled_ids(initial_items)
            except Exception as error:
                log("ratgpt-controlled-watch-initial-error", error=str(error))
            self.watcher_task = asyncio.create_task(self.watch_controlleds())
            while True:
                prompt = f"ratgpt[{self.remote.controlled_label if self.remote else '-'}]> "
                line = await loop.run_in_executor(None, input, prompt)
                try:
                    keep_going = await self.handle(line)
                except Exception as error:
                    print(f"error: {error}", file=sys.stderr)
                    keep_going = True
                if not keep_going:
                    break
        finally:
            if self.watcher_task:
                self.watcher_task.cancel()
                try:
                    await self.watcher_task
                except asyncio.CancelledError:
                    pass
                self.watcher_task = None
            await self.detach()
        return 0


def cmd_repl(_: argparse.Namespace) -> int:
    return asyncio.run(Repl().run())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ratgpt")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command")

    login = sub.add_parser("login")
    login.add_argument("--force", action="store_true")
    login.set_defaults(func=cmd_login)

    enroll = sub.add_parser("enroll")
    enroll.set_defaults(func=cmd_enroll)

    controlleds = sub.add_parser("controlleds")
    controlleds.add_argument("--json", action="store_true")
    controlleds.add_argument("--all", action="store_true", help="include stale/offline environment records")
    controlleds.set_defaults(func=print_controlleds)

    repl = sub.add_parser("repl")
    repl.set_defaults(func=cmd_repl)

    exec_p = sub.add_parser("exec")
    exec_p.add_argument("-c", "--controlled")
    exec_p.add_argument("command")
    exec_p.set_defaults(func=cmd_exec)

    spawn_p = sub.add_parser("spawn")
    spawn_p.add_argument("-c", "--controlled")
    spawn_p.add_argument("argv", nargs=argparse.REMAINDER)
    spawn_p.set_defaults(func=cmd_spawn)

    shell = sub.add_parser("shell")
    shell.add_argument("-c", "--controlled")
    shell.set_defaults(func=cmd_shell)

    put = sub.add_parser("put")
    put.add_argument("-c", "--controlled")
    put.add_argument("local")
    put.add_argument("remote")
    put.set_defaults(func=cmd_put)

    get = sub.add_parser("get")
    get.add_argument("-c", "--controlled")
    get.add_argument("remote")
    get.add_argument("local")
    get.set_defaults(func=cmd_get)

    ls = sub.add_parser("ls")
    ls.add_argument("-c", "--controlled")
    ls.add_argument("path")
    ls.set_defaults(func=lambda args: cmd_ls(args, long=False))

    ll = sub.add_parser("ll")
    ll.add_argument("-c", "--controlled")
    ll.add_argument("path")
    ll.set_defaults(func=lambda args: cmd_ls(args, long=True))

    payload = sub.add_parser("payload")
    payload.add_argument("--os", required=True, choices=["linux", "mac", "windows"])
    payload.add_argument("--arch", default="auto", choices=["auto", "x64", "arm64", "amd64", "aarch64", "x86_64"])
    payload.add_argument("--out")
    payload.add_argument("--standalone-archive")
    payload.add_argument("--detach", action="store_true", help="generate a macOS/Linux launcher that starts in the background")
    payload.set_defaults(func=cmd_payload)

    release_check = sub.add_parser("release-check")
    release_check.add_argument("--json", action="store_true")
    release_check.add_argument("--download", action="store_true", help="download selected release assets")
    release_check.add_argument("--use", action="store_true", help="store latest release as the default for new payloads")
    release_check.add_argument("--yes", "-y", action="store_true", help="answer yes to the interactive download/use prompt")
    release_check.add_argument("--all-targets", action="store_true", help="select all known payload package targets")
    release_check.add_argument("--os", choices=["linux", "mac", "windows"], help="limit downloaded assets to one OS")
    release_check.add_argument(
        "--arch",
        default="auto",
        choices=["auto", "all", "x64", "arm64", "amd64", "aarch64", "x86_64"],
        help="limit downloaded assets to one arch, or all",
    )
    release_check.set_defaults(func=cmd_release_check)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    set_verbose(bool(args.verbose))
    if not hasattr(args, "func"):
        parser.print_help()
        print("\nUse `ratgpt repl` for interactive mode.")
        return 2
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
