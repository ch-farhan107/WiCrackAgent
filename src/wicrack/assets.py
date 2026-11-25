"""Assets manager: download wordlists/rules from verified upstream URLs."""

from __future__ import annotations

from pathlib import Path

from loguru import logger

try:
    import requests

    _HAS_REQUESTS = True
except ImportError:  # pragma: no cover
    _HAS_REQUESTS = False

ASSETS: dict[str, dict] = {
    "rockyou": {
        "url": (
            "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
        ),
        "description": "rockyou.txt wordlist (~14.6M passwords, ~135 MB)",
    },
    "ortra": {
        "url": (
            "https://raw.githubusercontent.com/NotSoSecure/"
            "password_cracking_rules/master/OneRuleToRuleThemAll.rule"
        ),
        "description": "OneRuleToRuleThemAll.rule (NotSoSecure)",
    },
}


def asset_destination(name: str, settings) -> Path:
    """Default destination for an asset (inside data_dir unless packaged)."""
    if name == "ortra":
        return Path(settings.rules_ortra)
    return settings.data_dir / "rockyou.txt"


def download_asset(name: str, settings, dest: Path | None = None, chunk_mb: int = 8) -> Path:
    """Download one asset with a streaming progress log."""
    if not _HAS_REQUESTS:
        raise RuntimeError("requests not installed — pip install requests")
    if name not in ASSETS:
        raise KeyError(f"unknown asset '{name}' (available: {', '.join(ASSETS)})")
    meta = ASSETS[name]
    dest = dest or asset_destination(name, settings)
    dest.parent.mkdir(parents=True, exist_ok=True)

    logger.info("Downloading {} -> {}", meta["description"], dest)
    with requests.get(meta["url"], stream=True, timeout=120) as resp:
        resp.raise_for_status()
        done = 0
        with dest.open("wb") as fh:
            for chunk in resp.iter_content(chunk_size=1024 * 512):
                fh.write(chunk)
                done += len(chunk)
                if done >= chunk_mb * 1024 * 1024:
                    logger.info("  ... {:,.0f} MB", done / 1024 / 1024)
                    done = 0
    logger.success("Asset saved: {} ({:,.1f} MB)", dest, dest.stat().st_size / 1024 / 1024)
    return dest


def download_all(settings) -> dict[str, Path]:
    return {name: download_asset(name, settings) for name in ("rockyou", "ortra")}
