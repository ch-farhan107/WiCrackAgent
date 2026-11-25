"""Hardware detection and benchmarking (hashcat OpenCL devices)."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from wicrack.config import Settings

_UNIT = {"H/s": 1, "kH/s": 1e3, "MH/s": 1e6, "GH/s": 1e9, "TH/s": 1e12}
_SPEED_RE = re.compile(r"Speed\.#\d+[^:]*:\s*([\d.]+)\s*([kMGT]?H/s)", re.IGNORECASE)
_CACHE_TTL = 3600


def gpu_count() -> int:
    """Number of OpenCL/CUDA GPUs hashcat sees (0 when CPU-only/missing)."""
    if shutil.which("hashcat") is None:
        return 0
    try:
        proc = subprocess.run(["hashcat", "-I"], capture_output=True, text=True, timeout=90)
        types = re.findall(r"Type.*?:\s*(\S+)", proc.stdout or "")
        return sum(1 for t in types if "GPU" in t.upper())
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.warning("Hardware detection failed: {}", exc)
        return 0


def device_names() -> list[str]:
    if shutil.which("hashcat") is None:
        return []
    try:
        proc = subprocess.run(["hashcat", "-I"], capture_output=True, text=True, timeout=90)
        return [n.strip() for n in re.findall(r"Device Name.*?:\s*(.+)", proc.stdout or "")]
    except (subprocess.TimeoutExpired, OSError):
        return []


def benchmark_speed(settings: Settings, use_cache: bool = True) -> int | None:
    """Benchmark WPA (mode 22000) speed; cached for 1h in data/benchmark.json."""
    cache: dict = {}
    if use_cache and settings.benchmark_cache.exists():
        try:
            cache = json.loads(settings.benchmark_cache.read_text())
            if time.time() - cache.get("ts", 0) < _CACHE_TTL:
                return int(cache["speed"])
        except Exception:
            cache = {}

    if settings.dry_run or shutil.which("hashcat") is None:
        return None
    logger.info("Benchmarking WPA speed (~1-2 min)...")
    try:
        proc = subprocess.run(
            ["hashcat", "-b", "-m", "22000"],
            capture_output=True,
            text=True,
            timeout=900,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.warning("Benchmark failed: {}", exc)
        return None

    total = 0.0
    for val, unit in _SPEED_RE.findall(proc.stdout or ""):
        total += float(val) * _UNIT.get(unit, 1)
    speed = int(total) if total > 0 else None
    if speed:
        logger.success("Benchmark: {:,} H/s", speed)
        try:
            settings.benchmark_cache.parent.mkdir(parents=True, exist_ok=True)
            settings.benchmark_cache.write_text(json.dumps({"ts": time.time(), "speed": speed}))
        except OSError:
            pass
    return speed
