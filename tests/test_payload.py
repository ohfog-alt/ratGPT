from __future__ import annotations

import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from ratgpt.payload import build_payload, write_launcher


class PayloadLauncherTests(unittest.TestCase):
    def test_posix_foreground_launcher_keeps_existing_behavior(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp)
            write_launcher(stage, "linux")
            script = (stage / "run-controlled.sh").read_text(encoding="utf-8")

        self.assertIn('"$CODEX" login status', script)
        self.assertIn('"$CODEX" remote-control start --json', script)
        self.assertNotIn("nohup", script)
        self.assertNotIn("remote-control.log", script)

    def test_posix_detached_launcher_writes_runtime_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp)
            write_launcher(stage, "mac", detach=True)
            script = (stage / "run-controlled.sh").read_text(encoding="utf-8")

        self.assertIn("nohup sh -c", script)
        self.assertIn('LOG_PATH="$LOG_DIR/remote-control.log"', script)
        self.assertIn('PID_PATH="$RUNTIME_DIR/remote-control.pid"', script)
        self.assertIn('printf "%s\\n" "$PID" > "$PID_PATH"', script)
        self.assertIn("remote control started in background", script)

    def test_windows_detach_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "supported only for macOS and Linux"):
            build_payload(os_name="windows", arch="x64", detach=True)

    def test_detached_launcher_runs_dummy_codex_without_account_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp)
            codex = stage / ".codex/packages/standalone/current/bin/codex"
            codex.parent.mkdir(parents=True)
            codex.write_text(
                "#!/usr/bin/env sh\n"
                'printf "%s\\n" "$*" >> "$HOME/dummy-codex.calls"\n',
                encoding="utf-8",
            )
            codex.chmod(0o755)
            write_launcher(stage, "linux", detach=True)

            completed = subprocess.run(
                [str(stage / "run-controlled.sh")],
                check=True,
                capture_output=True,
                text=True,
            )
            pid_path = stage / "runtime/remote-control.pid"
            log_path = stage / "logs/remote-control.log"
            calls_path = stage / "dummy-codex.calls"
            for _ in range(20):
                if calls_path.exists() and len(calls_path.read_text(encoding="utf-8").splitlines()) == 2:
                    break
                time.sleep(0.05)

            self.assertRegex(completed.stdout, r"remote control started in background; pid=\d+; log=")
            self.assertTrue(pid_path.read_text(encoding="utf-8").strip().isdigit())
            self.assertTrue(log_path.exists())
            self.assertEqual(
                calls_path.read_text(encoding="utf-8").splitlines(),
                ["login status", "remote-control start --json"],
            )


if __name__ == "__main__":
    unittest.main()
