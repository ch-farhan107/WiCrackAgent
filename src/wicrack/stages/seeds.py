"""Seed extraction for combinator / mangler / phrase stages."""

from __future__ import annotations

from pathlib import Path

from loguru import logger


def build_seed_list(
    src: Path,
    out_path: Path,
    *,
    min_len: int,
    max_len: int,
    limit: int,
    alnum_only: bool,
) -> Path | None:
    """Extract alnum words within a length window into a seed file."""
    count, seen = 0, set()
    try:
        with (
            src.open("r", encoding="utf-8", errors="ignore") as fin,
            out_path.open("w", encoding="utf-8") as fout,
        ):
            for line in fin:
                word = line.rstrip("\r\n")
                if not (min_len <= len(word) <= max_len):
                    continue
                if alnum_only and not word.isalnum():
                    continue
                if word in seen:
                    continue
                seen.add(word)
                fout.write(word + "\n")
                count += 1
                if count >= limit:
                    break
    except OSError as exc:
        logger.warning("Seed extraction failed from {}: {}", src, exc)
        return None
    if count == 0:
        return None
    logger.info("Seed list {}: {} words", out_path, count)
    return out_path


def ensure_seeds(settings) -> Path | None:
    """Return a seed file, building one from the first available wordlist."""
    if settings.seed_file.exists():
        return settings.seed_file
    for wl in settings.wordlists:
        wl = Path(wl)
        if wl.exists():
            settings.seed_file.parent.mkdir(parents=True, exist_ok=True)
            return build_seed_list(
                wl,
                settings.seed_file,
                min_len=settings.seed_min_len,
                max_len=settings.seed_max_len,
                limit=settings.seed_limit,
                alnum_only=settings.alnum_only,
            )
    logger.warning("No wordlist available to build seeds")
    return None


def build_core_seeds(settings) -> Path | None:
    """Smaller seed file for the expensive 3-word phrase stage."""
    for wl in settings.wordlists:
        wl = Path(wl)
        if wl.exists():
            settings.seed_core_file.parent.mkdir(parents=True, exist_ok=True)
            return build_seed_list(
                wl,
                settings.seed_core_file,
                min_len=settings.seed_min_len,
                max_len=settings.seed_max_len,
                limit=settings.seed_core_limit,
                alnum_only=settings.alnum_only,
            )
    return None
