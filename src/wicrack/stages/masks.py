"""Mask stage with keyspace math (charset sizes, keyspace estimation)."""

from __future__ import annotations

from collections.abc import Iterable

from wicrack.engines.base import AttackSpec
from wicrack.stages.base import Stage, StageContext

CHARSET_SIZES = {"?l": 26, "?u": 26, "?d": 10, "?s": 33, "?h": 16, "?H": 22, "?a": 95, "?b": 256}


def charset_size(decl: str) -> int:
    """Size of a custom charset declaration like ``?l?u?d ``."""
    size, i = 0, 0
    while i < len(decl):
        token = decl[i : i + 2]
        if token in CHARSET_SIZES:
            size += CHARSET_SIZES[token]
            i += 2
        else:
            size += 1
            i += 1
    return max(size, 1)


def mask_keyspace(mask: str, custom_charset: str = "?l?u?d ") -> int:
    """Total candidate count a mask would generate."""
    sizes = dict(CHARSET_SIZES)
    sizes["?1"] = charset_size(custom_charset)
    total, i = 1, 0
    while i < len(mask):
        token = mask[i : i + 2]
        if token in sizes:
            total *= sizes[token]
            i += 2
        else:
            i += 1
    return total


class MaskStage(Stage):
    """D: brute-force mask presets, each gated by its keyspace estimate."""

    id = "D"
    label = "Mask presets"

    def attacks(self, ctx: StageContext) -> Iterable[AttackSpec]:
        s = ctx.settings
        for mask in s.mask_presets:
            yield AttackSpec(
                kind="mask",
                label=f"D: mask {mask}",
                mask=mask,
                custom_charset=s.mask_charset,
                estimated_candidates=mask_keyspace(mask, s.mask_charset),
            )
