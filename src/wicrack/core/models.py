"""Domain models shared by every layer."""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from wicrack.capture.parser import parse_22000_line


@dataclass(slots=True)
class Target:
    """A wireless target extracted from a capture."""

    kind: str  # "PMKID" | "EAPOL"
    essid: str
    bssid: str
    raw_line: str


@dataclass(slots=True)
class CrackSource:
    """Per-job artifacts; engines pick the file matching their format."""

    cap: Path
    hc22000: Path | None = None
    john: Path | None = None


@dataclass(slots=True)
class CrackResult:
    """One cracked credential (from a potfile or the pipeline)."""

    ts: str
    source: str
    essid: str
    bssid: str
    mode: str
    key: str
    key_len: int
    has_space: bool
    only_digits: bool
    stage: str

    @classmethod
    def from_pot_line(
        cls, raw: str, *, source: str = "engine", stage: str = ""
    ) -> CrackResult | None:
        """Parse a ``hash:plain`` pot line (hashcat 22000 or John)."""
        line = raw.strip()
        if ":" not in line:
            return None
        head, plain = line.rsplit(":", 1)
        plain = plain.strip()
        essid, bssid, kind = "?", "?", "?"
        if head.startswith("WPA*"):
            t = parse_22000_line(head)
            if t:
                essid = t.get("essid") or "?"
                bssid = t.get("ap") or "?"
                kind = t.get("type") or "?"
        return cls(
            ts=time.strftime("%Y-%m-%d %H:%M:%S"),
            source=source,
            essid=essid,
            bssid=bssid,
            mode=kind,
            key=plain,
            key_len=len(plain),
            has_space=" " in plain,
            only_digits=plain.isdigit(),
            stage=stage,
        )


@dataclass(slots=True)
class Evidence:
    """Metadata attached to an assessment report."""

    operator: str = "authorized assessor"
    engagement: str = ""
    notes: str = ""


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    STOPPED = "stopped"


@dataclass(slots=True)
class Job:
    path: Path
    status: JobStatus = JobStatus.QUEUED
    started: str = ""
    finished: str = ""
    result: str = ""
