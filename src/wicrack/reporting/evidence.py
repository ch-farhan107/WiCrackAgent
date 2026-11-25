"""Evidence export: tamper-evident JSON audit trail with SHA-256 integrity."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from loguru import logger

from wicrack import __version__
from wicrack.core.store import Store


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def export_evidence(
    store: Store,
    out_path: Path,
    *,
    engine: str = "unknown",
    include_plaintext: bool = False,
) -> Path:
    """Write a self-describing evidence file.

    Keys are stored as SHA-256 hashes unless ``include_plaintext`` is set
    (only appropriate for the engagement owner's own records).
    """
    rows = store.all_results()
    payload = {
        "format": "wicrack-evidence/1",
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "tool_version": __version__,
        "engine": engine,
        "key_material": "plaintext" if include_plaintext else "sha256",
        "results": [
            {
                "ts": r["ts"],
                "essid": r["essid"],
                "bssid": r["bssid"],
                "mode": r["mode"],
                "stage": r["stage"],
                "key": r["key"] if include_plaintext else _sha256(r["key"]),
                "key_len": r["key_len"],
            }
            for r in rows
        ],
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    payload["integrity_sha256"] = hashlib.sha256(canonical.encode()).hexdigest()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    logger.success("Evidence exported: {} ({} result(s))", out_path, len(rows))
    return out_path
