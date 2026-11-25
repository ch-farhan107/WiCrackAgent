"""Keyboard-walk stage: qwerty/123 patterns people actually type."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from wicrack.engines.base import AttackSpec
from wicrack.stages.base import Stage, StageContext

KEYBOARD_WALKS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
    "1qaz2wsx",
    "2wsx3edc",
    "3edc4rfv",
    "4rfv5tgb",
    "5tgb6yhn",
    "6yhn7ujm",
    "1q2w3e4r",
    "1q2w3e4r5t",
    "2w3e4r5t",
    "3e4r5t6y",
    "qweasdzxc",
    "asdzxcqwe",
    "qazwsx",
    "edcrfv",
    "tgbyhn",
    "poiuytrewq",
    "lkjhgfdsa",
    "mnbvcxz",
    "0987654321",
    "0p9o8i7u",
    "1qaz2wsx3edc4rfv",
    "qazxswedcvfr",
    "!QAZ@WSX",
    "1qaz@WSX",
    "qwe123",
    "abc123",
    "1234qwer",
    "zaq12wsx",
]


def build_walk_candidates(out_path: Path) -> Path:
    variants: set[str] = set()
    for walk in KEYBOARD_WALKS:
        variants.update({walk, walk[::-1], walk.capitalize(), walk.upper()})
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(sorted(variants)) + "\n", encoding="utf-8")
    return out_path


class KeyboardWalkStage(Stage):
    """F: keyboard walks, reversed and capitalized, then best64 on top."""

    id = "F"
    label = "Keyboard walks"

    def enabled(self, ctx: StageContext) -> bool:
        return ctx.settings.enable_kbwalks

    def attacks(self, ctx: StageContext) -> Iterable[AttackSpec]:
        candidates = build_walk_candidates(ctx.settings.data_dir / "kb_walks.txt")
        yield AttackSpec(kind="straight", label="F: keyboard walks", wordlist=candidates)
        if Path(ctx.settings.rules).exists():
            yield AttackSpec(
                kind="straight",
                label="F: keyboard walks+best64",
                wordlist=candidates,
                rules=ctx.settings.rules,
            )
