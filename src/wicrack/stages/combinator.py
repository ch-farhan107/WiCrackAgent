"""Combination stages: word+word, word+digits, and multi-word phrases."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from wicrack.engines.base import AttackSpec
from wicrack.stages.base import Stage, StageContext
from wicrack.stages.masks import mask_keyspace
from wicrack.stages.seeds import build_core_seeds, ensure_seeds


def _read_words(path: Path) -> list[str]:
    """Non-empty lines of a wordlist file."""
    with Path(path).open(encoding="utf-8", errors="ignore") as fh:
        return [ln.rstrip("\r\n") for ln in fh if ln.strip()]


class CombinatorStage(Stage):
    """E1: seed+seed with common separators (MyName, my-name, Name123...)."""

    id = "E1"
    label = "Combinator pairs"

    def enabled(self, ctx: StageContext) -> bool:
        return ctx.settings.enable_combinator

    def attacks(self, ctx: StageContext) -> Iterable[AttackSpec]:
        seeds = ensure_seeds(ctx.settings)
        if seeds is None:
            self._log_skip(ctx, "no seed list")
            return
        n = self._count_lines(seeds)
        seps = ctx.settings.combo_separators
        yield AttackSpec(
            kind="combinator",
            label="E1: combinator pairs",
            wordlist=seeds,
            right_wordlist=seeds,
            heavy=True,
            estimated_candidates=n * n * len(seps),
        )


class HybridStage(Stage):
    """E2: word+digits and digits+word hybrids."""

    id = "E2"
    label = "Word + digit hybrids"

    def enabled(self, ctx: StageContext) -> bool:
        return ctx.settings.enable_combinator

    def attacks(self, ctx: StageContext) -> Iterable[AttackSpec]:
        seeds = ensure_seeds(ctx.settings)
        if seeds is None:
            self._log_skip(ctx, "no seed list")
            return
        n = self._count_lines(seeds)
        for mask in ctx.settings.hybrid_digit_masks:
            est = mask_keyspace(mask) if mask.startswith("?") else 1
            yield AttackSpec(
                kind="hybrid_word_mask",
                label=f"E2: word+{mask}",
                wordlist=seeds,
                mask=mask,
                estimated_candidates=n * est,
            )
            yield AttackSpec(
                kind="hybrid_mask_word",
                label=f"E2: {mask}+word",
                wordlist=seeds,
                mask=mask,
                estimated_candidates=n * est,
            )


class PhraseStage(Stage):
    """E3: two-word (and optional three-word) phrases streamed live."""

    id = "E3"
    label = "Word phrases"

    def enabled(self, ctx: StageContext) -> bool:
        return ctx.settings.enable_combinator

    @staticmethod
    def _phrase_gen(words: list[str], seps: list[str], three: bool):
        for w1 in words:
            for s1 in seps:
                for w2 in words:
                    if not three:
                        yield w1 + s1 + w2
                    else:
                        for s2 in seps:
                            for w3 in words:
                                yield w1 + s1 + w2 + s2 + w3

    def attacks(self, ctx: StageContext) -> Iterable[AttackSpec]:
        seeds = ensure_seeds(ctx.settings)
        if seeds is None:
            self._log_skip(ctx, "no seed list")
            return
        words = _read_words(seeds)
        if not words:
            return
        seps = [s for s in ctx.settings.combo_separators if s != ""] or [""]

        yield AttackSpec(
            kind="stdin",
            label="E3: two-word phrases (stream)",
            generator=lambda: self._phrase_gen(words, seps, False),
            heavy=True,
            estimated_candidates=len(words) ** 2 * len(seps),
        )
        if ctx.settings.enable_three_word:
            core = build_core_seeds(ctx.settings) or seeds
            core_words = _read_words(core)
            yield AttackSpec(
                kind="stdin",
                label="E3b: three-word phrases (stream)",
                generator=lambda: self._phrase_gen(core_words, seps, True),
                heavy=True,
                estimated_candidates=(len(core_words) ** 3 * len(seps) ** 2),
            )
