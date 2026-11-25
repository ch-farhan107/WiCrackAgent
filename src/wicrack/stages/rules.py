"""Wordlist + rule stages: best64 (fast), OneRuleToRuleThemAll and dive.rule
(the industry-standard heavy rulesets)."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from wicrack.engines.base import AttackSpec
from wicrack.stages.base import Stage, StageContext


class WordlistRulesStage(Stage):
    """A: every configured wordlist with best64 rules."""

    id = "A"
    label = "Wordlist + best64 rules"

    def attacks(self, ctx: StageContext) -> Iterable[AttackSpec]:
        wordlists = self._available_wordlists(ctx)
        if not wordlists:
            self._log_skip(ctx, "no wordlist files found")
            return
        for wl in wordlists:
            if Path(ctx.settings.rules).exists():
                yield AttackSpec(
                    kind="straight",
                    label=f"A: {wl.name}+best64",
                    wordlist=wl,
                    rules=ctx.settings.rules,
                )
            else:
                yield AttackSpec(kind="straight", label=f"A: {wl.name} (plain)", wordlist=wl)


class OrtraStage(Stage):
    """A2: OneRuleToRuleThemAll — heavy but extremely effective."""

    id = "A2"
    label = "OneRuleToRuleThemAll"

    def enabled(self, ctx: StageContext) -> bool:
        return ctx.settings.enable_ortra

    def attacks(self, ctx: StageContext) -> Iterable[AttackSpec]:
        rules = Path(ctx.settings.rules_ortra)
        wordlists = self._available_wordlists(ctx)
        if not rules.exists() or not wordlists:
            self._log_skip(
                ctx, "rules or wordlist missing (run: wicrack assets download --name ortra)"
            )
            return
        yield AttackSpec(
            kind="straight",
            label="A2: wordlist+OneRuleToRuleThemAll",
            wordlist=wordlists[0],
            rules=rules,
            heavy=True,
            estimated_candidates=(self._count_lines(wordlists[0]) * self._count_lines(rules)),
        )


class DiveStage(Stage):
    """B: hashcat dive.rule (default install) — the deep classic."""

    id = "B"
    label = "dive.rule"

    def attacks(self, ctx: StageContext) -> Iterable[AttackSpec]:
        rules = Path(ctx.settings.rules_heavy)
        wordlists = self._available_wordlists(ctx)
        if not rules.exists() or not wordlists:
            self._log_skip(ctx, "dive.rule or wordlist missing")
            return
        yield AttackSpec(
            kind="straight",
            label="B: wordlist+dive.rule",
            wordlist=wordlists[0],
            rules=rules,
            heavy=True,
            estimated_candidates=(self._count_lines(wordlists[0]) * self._count_lines(rules)),
        )
