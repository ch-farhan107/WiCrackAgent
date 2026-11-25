"""Space-aware rule stage: passwords that contain spaces (unique feature)."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from loguru import logger

from wicrack.engines.base import AttackSpec
from wicrack.stages.base import Stage, StageContext


def make_space_rules(path: Path, max_spaces: int = 3) -> Path:
    """Generate hashcat rules that append/prepend 1..N literal spaces."""
    rules: list[str] = []
    for n in range(1, max_spaces + 1):
        rules.append("$ " * n)
        rules.append("^ " * n)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(rules) + "\n", encoding="utf-8")
    logger.info("Space rules written: {}", path)
    return path


class SpaceRulesStage(Stage):
    """C: wordlist variants with spaces appended/prepended."""

    id = "C"
    label = "Space-aware wordlist rules"

    def attacks(self, ctx: StageContext) -> Iterable[AttackSpec]:
        wordlists = self._available_wordlists(ctx)
        if not wordlists:
            self._log_skip(ctx, "no wordlist files found")
            return
        rules = make_space_rules(ctx.settings.data_dir / "space_rules.rule")
        yield AttackSpec(
            kind="straight", label="C: wordlist+space-rules", wordlist=wordlists[0], rules=rules
        )
