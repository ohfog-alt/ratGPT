from __future__ import annotations

import asyncio
import base64
import os
import posixpath
import shlex
import uuid
from pathlib import Path
from typing import Any

from .remote import RemoteAppServer


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"))


def assert_abs_remote(path: str) -> None:
    if not path.startswith("/"):
        raise ValueError(f"remote path must be absolute: {path}")


class AppServerOps:
    def __init__(self, remote: RemoteAppServer, *, cwd: str = "/tmp") -> None:
        self.remote = remote
        self.cwd = cwd
        self.process_events: dict[str, asyncio.Queue[dict[str, Any]]] = {}

    def handle_notification(self, message: dict[str, Any]) -> None:
        method = message.get("method")
        params = message.get("params") if isinstance(message.get("params"), dict) else {}
        handle = params.get("processHandle")
        if method in {"process/outputDelta", "process/exited"} and isinstance(handle, str):
            queue = self.process_events.get(handle)
            if queue:
                queue.put_nowait(message)

    async def initialize(self) -> None:
        await self.remote.initialize()

    async def spawn(
        self,
        argv: list[str],
        *,
        cwd: str | None = None,
        tty: bool = False,
        stream: bool = True,
        timeout_ms: int | None = 120000,
        output_bytes_cap: int | None = None,
        env: dict[str, str | None] | None = None,
        process_handle: str | None = None,
    ) -> tuple[str, asyncio.Queue[dict[str, Any]]]:
        if not argv:
            raise ValueError("argv must not be empty")
        remote_cwd = cwd or self.cwd
        assert_abs_remote(remote_cwd)
        handle = process_handle or f"p-{uuid.uuid4()}"
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.process_events[handle] = queue
        params: dict[str, Any] = {
            "command": argv,
            "processHandle": handle,
            "cwd": remote_cwd,
            "tty": tty,
            "streamStdin": tty,
            "streamStdoutStderr": stream or tty,
            "timeoutMs": timeout_ms,
            "outputBytesCap": output_bytes_cap,
        }
        if env is not None:
            params["env"] = env
        if tty:
            params["size"] = {"rows": 40, "cols": 120}
        await self.remote.request("process/spawn", params, timeout=30)
        return handle, queue

    async def write_stdin(self, handle: str, data: bytes = b"", *, close: bool = False) -> None:
        params: dict[str, Any] = {"processHandle": handle, "closeStdin": close}
        if data:
            params["deltaBase64"] = b64(data)
        await self.remote.request("process/writeStdin", params, timeout=30)

    async def kill(self, handle: str) -> None:
        await self.remote.request("process/kill", {"processHandle": handle}, timeout=30)

    async def run_process(self, argv: list[str], *, shell_display: str | None = None, timeout_ms: int | None = 120000) -> int:
        handle, queue = await self.spawn(argv, timeout_ms=timeout_ms, output_bytes_cap=None)
        if shell_display:
            print(f"[{self.remote.controlled_label}] {shell_display}", flush=True)
        exit_code = 0
        while True:
            message = await queue.get()
            method = message.get("method")
            params = message.get("params") if isinstance(message.get("params"), dict) else {}
            if method == "process/outputDelta":
                data = unb64(params.get("deltaBase64") or "")
                print(data.decode("utf-8", errors="replace"), end="", flush=True)
            elif method == "process/exited":
                stdout = params.get("stdout")
                stderr = params.get("stderr")
                if isinstance(stdout, str) and stdout:
                    print(stdout, end="", flush=True)
                if isinstance(stderr, str) and stderr:
                    print(stderr, end="", flush=True)
                exit_code = int(params.get("exitCode") or 0)
                self.process_events.pop(handle, None)
                break
        return exit_code

    async def exec_shell(self, command: str) -> int:
        return await self.run_process(["bash", "-lc", command], shell_display=command)

    async def read_file(self, remote_path: str) -> bytes:
        assert_abs_remote(remote_path)
        result = await self.remote.request("fs/readFile", {"path": remote_path}, timeout=120)
        data = result.get("dataBase64") if isinstance(result, dict) else None
        if not isinstance(data, str):
            raise RuntimeError(f"fs/readFile returned no dataBase64: {result!r}")
        return unb64(data)

    async def write_file(self, local_path: str, remote_path: str) -> None:
        assert_abs_remote(remote_path)
        data = Path(local_path).read_bytes()
        await self.remote.request("fs/writeFile", {"path": remote_path, "dataBase64": b64(data)}, timeout=120)

    async def get_file(self, remote_path: str, local_path: str) -> None:
        data = await self.read_file(remote_path)
        path = Path(local_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    async def mkdir(self, remote_path: str) -> None:
        assert_abs_remote(remote_path)
        await self.remote.request("fs/createDirectory", {"path": remote_path, "recursive": True}, timeout=30)

    async def remove(self, remote_path: str) -> None:
        assert_abs_remote(remote_path)
        await self.remote.request("fs/remove", {"path": remote_path, "recursive": True, "force": True}, timeout=60)

    async def copy(self, source: str, destination: str) -> None:
        assert_abs_remote(source)
        assert_abs_remote(destination)
        await self.remote.request(
            "fs/copy",
            {"sourcePath": source, "destinationPath": destination, "recursive": True},
            timeout=120,
        )

    async def read_dir(self, remote_path: str) -> list[Any]:
        assert_abs_remote(remote_path)
        result = await self.remote.request("fs/readDirectory", {"path": remote_path}, timeout=60)
        entries = result.get("entries") if isinstance(result, dict) else None
        if entries is None:
            entries = result.get("children") if isinstance(result, dict) else None
        if not isinstance(entries, list):
            return []
        return entries

    async def metadata(self, remote_path: str) -> dict[str, Any]:
        assert_abs_remote(remote_path)
        result = await self.remote.request("fs/getMetadata", {"path": remote_path}, timeout=30)
        return result if isinstance(result, dict) else {}

    async def ls(self, remote_path: str, *, long: bool = False) -> None:
        entries = await self.read_dir(remote_path)
        names: list[str] = []
        for entry in entries:
            if isinstance(entry, str):
                names.append(entry)
            elif isinstance(entry, dict):
                names.append(str(entry.get("name") or entry.get("path") or entry))
            else:
                names.append(str(entry))
        for name in sorted(names):
            if not long:
                print(name)
                continue
            full = posixpath.join(remote_path.rstrip("/"), name)
            try:
                meta = await self.metadata(full)
            except Exception as error:
                print(f"? {name} ({error})")
                continue
            kind = "d" if meta.get("isDirectory") else "-" if meta.get("isFile") else "l" if meta.get("isSymlink") else "?"
            size = meta.get("size") or meta.get("len") or ""
            print(f"{kind} {str(size).rjust(10)} {name}")

    def cd(self, path: str) -> str:
        if path.startswith("/"):
            self.cwd = posixpath.normpath(path)
        else:
            self.cwd = posixpath.normpath(posixpath.join(self.cwd, path))
        return self.cwd

    async def shell(self) -> int:
        handle, queue = await self.spawn(
            ["bash", "-i"],
            tty=True,
            stream=True,
            timeout_ms=None,
            output_bytes_cap=None,
            process_handle=f"shell-{uuid.uuid4()}",
        )

        async def output_loop() -> int:
            exit_code = 0
            while True:
                message = await queue.get()
                params = message.get("params") if isinstance(message.get("params"), dict) else {}
                if message.get("method") == "process/outputDelta":
                    print(unb64(params.get("deltaBase64") or "").decode("utf-8", errors="replace"), end="", flush=True)
                elif message.get("method") == "process/exited":
                    exit_code = int(params.get("exitCode") or 0)
                    break
            return exit_code

        output_task = asyncio.create_task(output_loop())
        loop = asyncio.get_running_loop()
        while not output_task.done():
            line = await loop.run_in_executor(None, input, "")
            await self.write_stdin(handle, f"{line}\n".encode("utf-8"))
            if line.strip() == "exit":
                break
        exit_code = await output_task
        self.process_events.pop(handle, None)
        return exit_code


def parse_argv(text: str) -> list[str]:
    return shlex.split(text)


def local_size(path: str) -> int:
    return os.stat(path).st_size
