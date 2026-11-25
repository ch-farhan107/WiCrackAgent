"""John the Ripper backend — the CPU-friendly engine (wpapsk)."""

from __future__ import annotations

import re
import shutil
import subprocess
import threading
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger

from wicrack.engines.base import AttackSpec, BaseEngine

if TYPE_CHECKING:
    from wicrack.core.models import CrackSource

# hashcat rule files -> JtR config rule sections (jumbo ships Best64/Dive)
_RULE_SECTION_MAP = {"best64": "Best64", "dive": "Dive"}
_SPEED_RE = re.compile(r"([\d.]+[KMGT]?p/s)")
_STATUS_RE = re.compile(r"(\d+)g")


class JohnEngine(BaseEngine):
    """CPU-oriented engine; picks wpapsk format with the converted hash."""

    name = "john"

    def available(self) -> bool:
        return shutil.which("john") is not None

    def supports(self, kind: str) -> bool:
        return kind in ("straight", "mask", "stdin")

    # ------------------------------------------------------------------ crack
    def _hashfile(self, source: CrackSource) -> str | None:
        if source.john and source.john.exists():
            return str(source.john)
        return None

    @staticmethod
    def _rule_args(rules) -> list[str]:
        """Map a hashcat rule file to a JtR config rule section."""
        if rules is None:
            return []
        path = Path(rules)
        section = _RULE_SECTION_MAP.get(path.stem.lower())
        if section:
            return [f"--rules={section}"]
        logger.warning(
            "john: rule file {} has no built-in section — using default rules", path.name
        )
        return ["--rules"]

    def crack(
        self,
        attack: AttackSpec,
        source: CrackSource,
        *,
        stop_event: threading.Event,
        status_cb=None,
        session=None,
    ) -> int:
        if not self.available():
            logger.error("john not installed")
            return -1
        hashfile = self._hashfile(source)
        if hashfile is None:
            logger.error("no John-format hash for this capture — skip {}", attack.label)
            return -1

        cmd = ["john", "--format=wpapsk"]
        stdin_iter = None

        if attack.kind == "straight":
            if attack.wordlist:
                cmd.append(f"--wordlist={attack.wordlist}")
            cmd += self._rule_args(attack.rules)
        elif attack.kind == "mask":
            cmd.append(f"--mask={attack.mask or ''}")
            if attack.custom_charset:
                cmd.append(f"--1={attack.custom_charset}")
        elif attack.kind == "stdin":
            cmd.append("--stdin")
            stdin_iter = attack.generator() if attack.generator else iter(())
        else:
            logger.warning("john does not support '{}' — skipping {}", attack.kind, attack.label)
            return -1
        cmd.append(hashfile)
        return self._run(
            cmd, stop_event=stop_event, status_cb=status_cb, stdin_iter=stdin_iter, session=session
        )

    # ------------------------------------------------------------------- pot
    def pot_check(self, source: CrackSource) -> list[str]:
        hashfile = self._hashfile(source)
        if hashfile is None:
            return []
        try:
            proc = subprocess.run(
                ["john", "--show", hashfile], capture_output=True, text=True, timeout=120
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.warning("john pot_check failed: {}", exc)
            return []
        out = proc.stdout.strip()
        if not out or out.endswith(("no password hash", "loaded 0")):
            return []
        # john --show prints "hashfile:plain" lines; last line may be a summary
        lines = [
            ln
            for ln in out.splitlines()
            if ":" in ln and not ln.startswith((" cracked", " Session"))
        ]
        return lines

    # ---------------------------------------------------------------- status
    def _parse_status(self, line: str) -> dict:
        updates: dict = {}
        speed = _SPEED_RE.search(line)
        if speed:
            updates["speed"] = speed.group(1)
        cracked = _STATUS_RE.search(line)
        if cracked and cracked.group(1) != "0":
            updates["progress"] = f"{cracked.group(1)}g"
        return updates
