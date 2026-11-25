"""Pipeline orchestration: ordered stages, heavy gates, potfile harvesting."""

from __future__ import annotations

from loguru import logger

from wicrack.core.models import CrackResult
from wicrack.engines.base import AttackSpec
from wicrack.stages.base import Stage, StageContext
from wicrack.stages.combinator import CombinatorStage, HybridStage, PhraseStage
from wicrack.stages.essid import EssidStage
from wicrack.stages.kbwalks import KeyboardWalkStage
from wicrack.stages.learn import MaskLearnStage
from wicrack.stages.mangler import ManglerStage
from wicrack.stages.masks import MaskStage
from wicrack.stages.rules import DiveStage, OrtraStage, WordlistRulesStage
from wicrack.stages.space import SpaceRulesStage

# Default execution order: cheapest + highest-probability first.
PIPELINE: list[Stage] = [
    EssidStage(),  # E0
    WordlistRulesStage(),  # A
    OrtraStage(),  # A2 (heavy)
    DiveStage(),  # B  (heavy)
    SpaceRulesStage(),  # C
    MaskStage(),  # D
    KeyboardWalkStage(),  # F
    ManglerStage(),  # G
    MaskLearnStage(),  # H
    CombinatorStage(),  # E1
    HybridStage(),  # E2
    PhraseStage(),  # E3
]


def _needs_confirmation(ctx: StageContext, attack: AttackSpec) -> bool:
    if attack.heavy:
        return True
    if attack.estimated_candidates and not ctx.settings.dry_run:
        est_h = attack.estimated_candidates / max(ctx.settings.est_speed, 1) / 3600
        return est_h > ctx.settings.auto_ok_hours
    return False


def run_pipeline(
    ctx: StageContext,
) -> tuple[bool, list[CrackResult], str]:
    """Run all stages; returns (cracked?, new results, winning attack label)."""
    known = ctx.store.known_keys()
    for stage in PIPELINE:
        if ctx.stop_event.is_set():
            logger.info("[pipeline] stop requested — aborting")
            return False, [], ""
        if not stage.enabled(ctx):
            logger.info("[pipeline] stage {} disabled by config", stage.id)
            continue
        logger.info("[pipeline] stage {} — {}", stage.id, stage.label)

        for attack in stage.attacks(ctx):
            if ctx.stop_event.is_set():
                return False, [], ""
            if not ctx.engine.supports(attack.kind):
                logger.info(
                    "[pipeline] {} not supported by {} — skip {}",
                    attack.kind,
                    ctx.engine.name,
                    attack.label,
                )
                continue
            if _needs_confirmation(ctx, attack) and not ctx.confirm(attack):
                logger.info("[pipeline] heavy attack declined — skip {}", attack.label)
                continue

            logger.info("[pipeline] running: {}", attack.label)
            ctx.state_cb({"current_stage": attack.label})
            ctx.engine.crack(
                attack,
                ctx.source,
                stop_event=ctx.stop_event,
                status_cb=ctx.state_cb,
                session=ctx.next_session(),
            )

            pot_lines = ctx.engine.pot_check(ctx.source)
            fresh: list[CrackResult] = []
            for line in pot_lines:
                result = CrackResult.from_pot_line(line, stage=attack.label)
                if result and result.key not in known:
                    fresh.append(result)
                    known.add(result.key)
            if fresh:
                ctx.store.add_results(fresh)
                logger.success("CRACKED via [{}]: {} key(s)", attack.label, len(fresh))
                return True, fresh, attack.label

    return False, [], ""
