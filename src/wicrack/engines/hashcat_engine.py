"""hashcat backend (GPU/OpenCL, mode 22000)."""

from __future__ import annotations

import shutil
import subprocess
import threading
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger

from wicrack.engines.base import AttackSpec, BaseEngine

if TYPE_CHECKING:
    from wicrack.config import Settings
    from wicrack.core.models import CrackSource

_SPEED_RE = None  # parsed inline; avoids duplicate import churn


class HashcatEngine(BaseEngine):
    """Turns :class:`AttackSpec` objects into hashcat mode-22000 commands."""

    name = "hashcat"

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self._brain_proc: subprocess.Popen[bytes] | None = None

    # ------------------------------------------------------------ availability
    def available(self) -> bool:
        return shutil.which("hashcat") is not None

    # ------------------------------------------------------------- cmd builder
    def _base_args(self, session: str | None) -> list[str]:
        s = self.settings
        cmd = [
            "hashcat",
            "-m",
            "22000",
            "-w",
            str(s.workload),
            "--hwmon-temp-abort",
            str(s.temp_abort),
            "--status",
            "--status-timer",
            str(s.status_timer),
            "--potfile-path",
            str(s.potfile_path),
        ]
        if s.optimized:
            cmd.append("-O")
        if s.devices:
            cmd += ["-d", s.devices]
        if session:
            cmd += ["--session", session]
        cmd += self._brain_flags()
        return cmd

    def _brain_flags(self) -> list[str]:
        if not self.settings.enable_brain:
            return []
        self._ensure_brain_server()
        s = self.settings
        return [
            "--brain-client",
            "--brain-host",
            s.brain_host,
            "--brain-port",
            str(s.brain_port),
            "--brain-password",
            s.brain_password,
        ]

    def _ensure_brain_server(self) -> None:
        if self._brain_proc is not None:
            return
        s = self.settings
        try:
            self._brain_proc = subprocess.Popen(
                [
                    "hashcat",
                    "--brain-server",
                    "--brain-host",
                    s.brain_host,
                    "--brain-port",
                    str(s.brain_port),
                    "--brain-password",
                    s.brain_password,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            logger.info("hashcat brain server on :{}", s.brain_port)
        except OSError as exc:
            logger.warning("Brain server failed to start: {}", exc)
            self._brain_proc = None

    # --------------------------------------------------------- worker splitting
    def _rules_path(self, rules: Path | None) -> Path | None:
        """Split rule file across distributed workers (worker_total > 1)."""
        s = self.settings
        if rules is None or s.worker_total <= 1:
            return rules
        lines = rules.read_text(encoding="utf-8", errors="ignore").splitlines()
        chunk = (len(lines) + s.worker_total - 1) // s.worker_total
        part = lines[(s.worker_id - 1) * chunk : s.worker_id * chunk]
        out = Path(f"worker{s.worker_id}_rules.rule")
        out.write_text("\n".join(part) + "\n", encoding="utf-8")
        logger.info(
            "[worker {}/{}] rules split {}/{}", s.worker_id, s.worker_total, len(part), len(lines)
        )
        return out

    def _worker_straight_args(self, wordlist: Path | None) -> list[str]:
        s = self.settings
        if wordlist is None or s.worker_total <= 1 or not wordlist.exists():
            return []
        total = sum(1 for _ in wordlist.open("r", encoding="utf-8", errors="ignore"))
        if total == 0:
            return []
        chunk = (total + s.worker_total - 1) // s.worker_total
        return ["--skip", str((s.worker_id - 1) * chunk), "--limit", str(chunk)]

    # ------------------------------------------------------------------ crack
    def crack(
        self,
        attack: AttackSpec,
        source: CrackSource,
        *,
        stop_event: threading.Event,
        status_cb=None,
        session=None,
    ) -> int:
        if not source.hc22000:
            logger.error("no hc22000 file for hashcat — skip {}", attack.label)
            return -1
        cmd = self._base_args(session) + [str(source.hc22000)]
        stdin_iter = None

        if attack.kind == "straight":
            if attack.rules:
                rules = self._rules_path(attack.rules)
                if rules:
                    cmd += ["-r", str(rules)]
            cmd += self._worker_straight_args(attack.wordlist) if not attack.rules else []
        elif attack.kind == "mask":
            cmd += ["-a", "3"]
            if attack.custom_charset:
                cmd += ["-1", attack.custom_charset]
            cmd.append(attack.mask or "")
        elif attack.kind == "combinator":
            cmd += ["-a", "1"]
            if attack.separator:
                cmd += ["-j", attack.separator]
            cmd += [str(attack.wordlist or ""), str(attack.right_wordlist or attack.wordlist or "")]
        elif attack.kind == "hybrid_word_mask":
            cmd += ["-a", "6", str(attack.wordlist or ""), attack.mask or ""]
        elif attack.kind == "hybrid_mask_word":
            cmd += ["-a", "7", attack.mask or "", str(attack.wordlist or "")]
        elif attack.kind == "stdin":
            stdin_iter = attack.generator() if attack.generator else iter(())
        else:
            logger.error("unsupported attack kind: {}", attack.kind)
            return -1

        return self._run(
            cmd, stop_event=stop_event, status_cb=status_cb, stdin_iter=stdin_iter, session=session
        )

    # --------------------------------------------------------------- potfile
    def pot_check(self, source: CrackSource) -> list[str]:
        if not source.hc22000 or self.settings.dry_run:
            return []
        try:
            proc = subprocess.run(
                [
                    "hashcat",
                    "-m",
                    "22000",
                    str(source.hc22000),
                    "--show",
                    "--potfile-path",
                    str(self.settings.potfile_path),
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.warning("pot_check failed: {}", exc)
            return []
        return proc.stdout.strip().splitlines() if proc.stdout.strip() else []

    # ---------------------------------------------------------------- status
    def _log_line(self, line: str) -> None:
        import re

        if re.search(
            r"(Speed\.|Progress|Status\.|Recovered\.|Cracked|"
            r"Exhausted|WARNING|ERROR|Hardware\.Mon)",
            line,
        ):
            logger.info("[hashcat] {}", line)
        else:
            logger.debug("[hashcat] {}", line)

    def _parse_status(self, line: str) -> dict:
        import re

        updates: dict = {}
        if "Speed.#" in line:
            m = re.search(r"Speed\.#\d+[^:]*:\s*([\d.]+\s*[kMGT]?H/s)", line)
            if m:
                updates["speed"] = m.group(1)
        if "Progress" in line:
            m = re.search(r"([\d.,]+)\s*/\s*([\d.,]+)", line)
            if m:
                updates["progress"] = f"{m.group(1)}/{m.group(2)}"
        return updates

    def terminate_all(self) -> None:
        super().terminate_all()
        if self._brain_proc is not None:
            with suppress(Exception):
                self._brain_proc.terminate()
            self._brain_proc = None
