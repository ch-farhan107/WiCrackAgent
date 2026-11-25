"""Mask-learning stage: derive mask patterns from previously cracked keys.

This is WiCrackAgent's adaptive feature — the tool learns the password
structure habits of the environment and re-attacks with focused masks.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable

from loguru import logger

from wicrack.engines.base import AttackSpec
from wicrack.stages.base import Stage, StageContext
from wicrack.stages.masks import mask_keyspace


def key_to_mask(plain: str) -> str:
    """Convert a plaintext into a structural hashcat mask."""
    out: list[str] = []
    for ch in plain:
        if ch.islower():
            out.append("?l")
        elif ch.isupper():
            out.append("?u")
        elif ch.isdigit():
            out.append("?d")
        elif ch == " ":
            out.append(" ")
        else:
            out.append("?s")
    return "".join(out)


def learn_masks(keys: list[str], top: int = 10, min_count: int = 2) -> list[str]:
    """Most common structural patterns seen at least ``min_count`` times."""
    patterns: Counter[str] = Counter()
    for key in keys:
        plain = key.rsplit(":", 1)[1].strip() if ":" in key else key.strip()
        if plain:
            patterns[key_to_mask(plain)] += 1
    return [mask for mask, cnt in patterns.most_common(top) if cnt >= min_count]


class MaskLearnStage(Stage):
    """H: focus masks learned from this assessment's own crack history."""

    id = "H"
    label = "Learned mask patterns"

    def enabled(self, ctx: StageContext) -> bool:
        return ctx.settings.enable_mask_learning

    def attacks(self, ctx: StageContext) -> Iterable[AttackSpec]:
        keys = ctx.store.keys_for_learning(min_len=8)
        if len(keys) < 3:
            self._log_skip(ctx, "not enough cracked keys to learn from")
            return
        masks = learn_masks(keys)
        if not masks:
            self._log_skip(ctx, "no repeated structural pattern yet")
            return
        logger.info("Stage H learned masks: {}", masks[:5])
        for mask in masks:
            yield AttackSpec(
                kind="mask",
                label=f"H: learned {mask}",
                mask=mask,
                custom_charset=ctx.settings.mask_charset,
                estimated_candidates=mask_keyspace(mask, ctx.settings.mask_charset),
            )
