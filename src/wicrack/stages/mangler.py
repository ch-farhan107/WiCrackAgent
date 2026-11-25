"""Mangler stage: leet/capitalization/digit mutations streamed via stdin."""

from __future__ import annotations

from collections.abc import Iterable

from wicrack.engines.base import AttackSpec
from wicrack.stages.base import Stage, StageContext
from wicrack.stages.seeds import ensure_seeds

LEET = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7"}
MANGLE_DIGITS = ["1", "12", "123", "1234", "2024", "2025", "2026"]


def _leet(word: str) -> str:
    return "".join(LEET.get(c, c) for c in word)


def builtin_mangler(seed_path) -> Iterable[str]:
    """Generate mutations of every seed word (lazy — streams to stdin)."""
    from pathlib import Path

    path = Path(seed_path)
    if not path.exists():
        return
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        seeds = [ln.strip() for ln in fh if ln.strip()]
    for seed in seeds:
        base = {seed, seed.capitalize(), seed.upper(), _leet(seed), _leet(seed).capitalize()}
        for variant in base:
            yield variant
            for digits in MANGLE_DIGITS:
                yield variant + digits
                yield digits + variant
            yield variant + "!"
            yield variant + "@123"


class ManglerStage(Stage):
    """G: mutation engine over the seed list."""

    id = "G"
    label = "Builtin mangler"

    def enabled(self, ctx: StageContext) -> bool:
        return ctx.settings.enable_mangler

    def attacks(self, ctx: StageContext) -> Iterable[AttackSpec]:
        seeds = ensure_seeds(ctx.settings)
        if seeds is None:
            self._log_skip(ctx, "no seed list available")
            return
        n = self._count_lines(seeds)
        yield AttackSpec(
            kind="stdin",
            label="G: builtin mangler (stream)",
            generator=lambda: builtin_mangler(seeds),
            heavy=True,
            estimated_candidates=n * 5 * (2 * len(MANGLE_DIGITS) + 2),
        )
