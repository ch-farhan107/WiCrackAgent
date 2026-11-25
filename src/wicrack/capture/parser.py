"""Parse hashcat 22000 (WPA-PMKID/EAPOL) hash files.

Format reference: https://hashcat.net/wiki/doku.php?id=example_hashes
- PMKID : ``WPA*01*<pmkid>*<ap_mac>*<sta_mac>*<essid_hex>*``
- EAPOL : ``WPA*02*<mac_sta>*<mac_ap>*<essid>...`` (essid hex in field 4)
"""

from __future__ import annotations

import re
from pathlib import Path

CAP_EXTENSIONS = (".cap", ".pcap", ".pcapng")


def parse_22000_line(line: str) -> dict | None:
    """Parse one hc22000 line into ``{type, essid, ap, line}`` or None."""
    line = line.strip()
    if not line.startswith("WPA*"):
        return None
    parts = line.split("*")
    try:
        if parts[1] == "01" and len(parts) >= 6:  # PMKID
            return {
                "type": "PMKID",
                "ap": parts[3].lower(),
                "essid": bytes.fromhex(parts[5]).decode("utf-8", "ignore"),
                "line": line,
            }
        if parts[1] == "02" and len(parts) >= 7:  # EAPOL (4-way handshake)
            return {
                "type": "EAPOL",
                "ap": parts[3].lower(),
                "essid": bytes.fromhex(parts[4]).decode("utf-8", "ignore"),
                "line": line,
            }
    except (IndexError, ValueError):
        return None
    return None


def parse_22000_file(path: Path) -> list[dict]:
    """Return all valid targets found in a hc22000 file."""
    targets: list[dict] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return targets
    for line in text.splitlines():
        target = parse_22000_line(line)
        if target:
            targets.append(target)
    return targets


def is_capture_file(name: str) -> bool:
    return name.lower().endswith(CAP_EXTENSIONS)


def list_capture_files(folder: Path) -> list[Path]:
    """Sorted capture files inside ``folder``."""
    if not folder.is_dir():
        return []
    return sorted(p for p in folder.iterdir() if p.is_file() and is_capture_file(p.name))


def apply_filter(
    hc_path: Path,
    targets: list[dict],
    *,
    essids: list[str],
    bssids: list[str],
    mode: str,
) -> Path | None:
    """Filter hc22000 file by ESSID/BSSID (include/exclude mode).

    Returns the path to use (original or a ``.filtered`` file) or ``None``
    when every target was dropped.
    """
    want_e = {e.strip().lower() for e in essids if e.strip()}
    want_b = {b.strip().lower().replace(":", "").replace("-", "") for b in bssids if b.strip()}
    if not want_e and not want_b:
        return hc_path

    keep: list[dict] = []
    for t in targets:
        essid = (t.get("essid") or "").lower()
        bssid = (t.get("ap") or "").replace(":", "").replace("-", "").lower()
        hit = essid in want_e or bssid in want_b
        if (mode == "include" and hit) or (mode == "exclude" and not hit):
            keep.append(t)

    if not keep:
        return None
    if len(keep) == len(targets):
        return hc_path
    out = hc_path.with_suffix(hc_path.suffix + ".filtered")
    out.write_text("\n".join(t["line"] for t in keep) + "\n", encoding="utf-8")
    return out


MAC_RE = re.compile(r"^([0-9a-f]{2}:?){5}[0-9a-f]{2}$", re.IGNORECASE)


def normalize_mac(mac: str) -> str:
    """Lowercase mac without separators (``AA:BB:..`` -> ``aabbcc...``)."""
    return mac.strip().lower().replace(":", "").replace("-", "")
