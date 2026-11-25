"""ESSID-as-password stage: fastest win when the network uses its own name."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from loguru import logger

from wicrack.engines.base import AttackSpec
from wicrack.stages.base import Stage, StageContext

_SUFFIXES = ["?d?d?d?d", "123", "1234", "@123", "2024", "2025", "2026"]


def build_essid_list(targets: list[dict], out_path) -> Path | None:
    out_path = Path(out_path)
    words: set[str] = set()
    for t in targets:
        essid = (t.get("essid") or "").strip()
        if not essid or essid == "?":
            continue
        words.update({essid, essid.lower(), essid.upper(), essid.capitalize()})
    if not words:
        return None
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(sorted(words)) + "\n", encoding="utf-8")
    logger.info("ESSID wordlist: {} variant(s)", len(words))
    return out_path


class EssidStage(Stage):
    id = "E0"
    label = "ESSID-derived passwords"

    def attacks(self, ctx: StageContext) -> Iterable[AttackSpec]:
        elist = build_essid_list(ctx.targets, ctx.settings.data_dir / "essid_target.txt")
        if elist is None:
            self._log_skip(ctx, "no ESSID information")
            return
        yield AttackSpec(kind="straight", label="E0: ESSID as password", wordlist=elist)
        for sfx in _SUFFIXES:
            yield AttackSpec(
                kind="hybrid_word_mask", label=f"E0: ESSID+{sfx}", wordlist=elist, mask=sfx
            )
