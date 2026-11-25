"""Optional WPA3/SAE detection via tshark (advisory only, fail-soft)."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from loguru import logger


def detect_sae_frames(cap_path: Path, timeout: int = 120) -> int | None:
    """Count SAE (WPA3) authentication frames; None when tshark missing."""
    if shutil.which("tshark") is None:
        return None
    try:
        proc = subprocess.run(
            ["tshark", "-r", str(cap_path), "-Y", "wlan.fixed.auth.alg == 5", "-T", "count"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("SAE detection skipped: {}", exc)
        return None
    match = re.search(r"(\d+)", proc.stdout or "")
    count = int(match.group(1)) if match else 0
    if count > 0:
        logger.warning(
            "SAE (WPA3) frames detected: {} — mode 22000 cannot crack pure SAE. "
            "Target the WPA2 fallback of a transition-mode network instead.",
            count,
        )
    return count
