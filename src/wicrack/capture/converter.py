"""Convert packet captures to hashcat (hc22000) and John the Ripper formats."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from loguru import logger

from wicrack.capture.parser import CAP_EXTENSIONS


def convert_to_22000(cap_path: Path, out_path: Path | None = None) -> Path | None:
    """Run hcxpcapngtool and return the hc22000 path, or None on failure.

    Reuses an existing conversion when it is newer than the capture.
    """
    out = out_path or cap_path.with_suffix(cap_path.suffix + ".hc22000")
    if out.exists() and out.stat().st_size > 0:
        try:
            if out.stat().st_mtime >= cap_path.stat().st_mtime:
                logger.info("Reusing existing conversion: {}", out.name)
                return out
        except OSError:
            pass
        out.unlink(missing_ok=True)

    if shutil.which("hcxpcapngtool") is None:
        logger.error("hcxpcapngtool not found — install hcxtools")
        return None
    try:
        subprocess.run(
            ["hcxpcapngtool", "-o", str(out), str(cap_path)],
            capture_output=True,
            text=True,
            timeout=600,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.error("Conversion failed for {}: {}", cap_path.name, exc)
        return None

    if out.exists() and out.stat().st_size > 0:
        logger.success("Extracted {}", out.name)
        return out
    logger.warning("No valid handshake/PMKID found in {}", cap_path.name)
    return None


def convert_to_john(cap_path: Path, out_path: Path | None = None) -> Path | None:
    """Convert a capture to John the Ripper format via wpapcap2john."""
    out = out_path or cap_path.with_suffix(cap_path.suffix + ".john")
    if out.exists() and out.stat().st_size > 0:
        return out
    tool = shutil.which("wpapcap2john")
    if tool is None:
        logger.warning(
            "wpapcap2john not found — John engine unavailable "
            "for this capture (install john-data / john)"
        )
        return None
    try:
        proc = subprocess.run([tool, str(cap_path)], capture_output=True, text=True, timeout=600)
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.error("John conversion failed for {}: {}", cap_path.name, exc)
        return None
    if proc.stdout.strip():
        out.write_text(proc.stdout, encoding="utf-8")
        logger.success("Converted to John format: {}", out.name)
        return out
    return None


def scan_captures(folder: Path) -> list[Path]:
    if not folder.is_dir():
        logger.warning("Capture folder not found: {}", folder)
        return []
    files = sorted(
        p for p in folder.iterdir() if p.is_file() and p.suffix.lower() in CAP_EXTENSIONS
    )
    logger.info("Found {} capture file(s) in {}", len(files), folder)
    return files
