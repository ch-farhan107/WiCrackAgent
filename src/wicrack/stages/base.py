"""Stage base classes and per-job execution context."""

from __future__ import annotations

import itertools
import threading
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from wicrack.config import Settings
    from wicrack.core.models import CrackSource
    from wicrack.core.store import Store
    from wicrack.engines.base import AttackSpec, Engine


@dataclass
class StageContext:
    """Everything a stage needs to plan and run attacks for one job."""

    settings: Settings
    engine: Engine
    source: CrackSource
    targets: list[dict]
    store: Store
    stop_event: threading.Event
    state_cb: Callable[[dict], None]
    confirm: Callable[[AttackSpec], bool]
    _sessions: itertools.count = field(default_factory=itertools.count)

    def next_session(self) -> str:
        return f"wicrack_{next(self._sessions)}"


class Stage(ABC):
    """One strategy in the pipeline; yields declarative attacks."""

    id: str = "?"
    label: str = "?"

    @abstractmethod
    def attacks(self, ctx: StageContext) -> Iterable[AttackSpec]:
        """Yield the attacks this stage wants to run, in order."""

    def enabled(self, ctx: StageContext) -> bool:
        return True

    # ------------------------------------------------------------ helpers
    @staticmethod
    def _available_wordlists(ctx: StageContext) -> list[Path]:
        return [wl for wl in ctx.settings.wordlists if Path(wl).exists()]

    @staticmethod
    def _count_lines(path: Path) -> int:
        try:
            with Path(path).open("r", encoding="utf-8", errors="ignore") as fh:
                return sum(1 for _ in fh)
        except OSError:
            return 0

    def _log_skip(self, ctx: StageContext, reason: str) -> None:
        logger.info("[stage {}] skipped: {}", self.id, reason)
