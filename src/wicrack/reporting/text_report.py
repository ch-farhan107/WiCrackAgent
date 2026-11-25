"""Append-only text report (cracked_passwords.txt) — the audit log."""

from __future__ import annotations

import time
from pathlib import Path

from loguru import logger

from wicrack.core.models import CrackResult, CrackSource

_SEPARATOR = "=" * 62


def append_text_report(path: Path, source: CrackSource, results: list[CrackResult]) -> None:
    """Append one block per cracked capture; never overwrite history."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(_SEPARATOR + "\n")
        fh.write(f"Date     : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        fh.write(f"Capture  : {source.cap.name}\n")
        for result in results:
            fh.write(
                f"Target   : ESSID='{result.essid}'  BSSID={result.bssid}  Mode={result.mode}\n"
            )
        for result in results:
            fh.write(f"KEY      : {result.key}\n")
        fh.write(_SEPARATOR + "\n\n")
    logger.info("Text report updated: {}", path)
