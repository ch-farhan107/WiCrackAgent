"""Engine abstractions shared by hashcat and John the Ripper backends."""

from __future__ import annotations

import subprocess
import threading
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from loguru import logger

if TYPE_CHECKING:
    from wicrack.config import Settings
    from wicrack.core.models import CrackSource

AttackKind = Literal[
    "straight",
    "mask",
    "combinator",
    "hybrid_word_mask",
    "hybrid_mask_word",
    "stdin",
]

StatusCallback = Callable[[dict], None]


@dataclass
class AttackSpec:
    """One declarative attack; the active engine turns it into CLI args."""

    kind: AttackKind
    label: str
    wordlist: Path | None = None
    rules: Path | None = None
    mask: str | None = None
    custom_charset: str | None = None
    separator: str | None = None  # combinator joint ("$x" escaped)
    right_wordlist: Path | None = None  # combinator right file
    generator: Callable[[], Iterable[str]] | None = None  # stdin candidates
    heavy: bool = False
    estimated_candidates: int | None = None


class Engine(ABC):
    """A password-recovery backend that executes :class:`AttackSpec` runs."""

    name: str = "base"

    @abstractmethod
    def available(self) -> bool: ...

    def supports(self, kind: str) -> bool:
        """Whether this engine can execute the given attack kind."""
        return True

    def terminate_current(self) -> None:  # noqa: B027 - deliberate hook
        """Stop a running attack (no-op unless the engine overrides it)."""

    @abstractmethod
    def crack(
        self,
        attack: AttackSpec,
        source: CrackSource,
        *,
        stop_event: threading.Event,
        status_cb: StatusCallback | None = None,
        session: str | None = None,
    ) -> int:
        """Run the attack; returns process exit code (dry_run -> 0)."""

    @abstractmethod
    def pot_check(self, source: CrackSource) -> list[str]:
        """Return all cracked ``hash:plain`` lines for this source."""


class BaseEngine(Engine):
    """Common process management: stop handling + live status parsing."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._current_proc: subprocess.Popen[str] | None = None

    # ----------------------------------------------------------- lifecycle
    def terminate_current(self) -> None:
        proc = self._current_proc
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=10)
            except Exception:
                with suppress(Exception):
                    proc.kill()
            logger.info("[{}] terminated running process", self.name)

    def terminate_all(self) -> None:
        self.terminate_current()

    # ------------------------------------------------------------- helpers
    def _run(
        self,
        cmd: list[str],
        *,
        stop_event: threading.Event,
        status_cb: StatusCallback | None = None,
        stdin_iter: Iterable[str] | None = None,
        session: str | None = None,
    ) -> int:
        """Spawn the backend, stream stdout, honour stop_event, parse status."""
        if self.settings.dry_run:
            logger.info("[DRY-RUN] {} -> {}", self.name, " ".join(cmd))
            return 0
        logger.info("[{}] CMD: {}", self.name, " ".join(cmd))

        stdin_arg = subprocess.PIPE if stdin_iter is not None else None
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=stdin_arg,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        except FileNotFoundError:
            logger.error("[{}] binary not found", self.name)
            return -1
        self._current_proc = proc

        writer = None
        if stdin_iter is not None:

            def _feed() -> None:
                try:
                    assert proc.stdin is not None
                    for cand in stdin_iter:
                        if stop_event.is_set():
                            break
                        proc.stdin.write(cand + "\n")
                except (BrokenPipeError, OSError, ValueError):
                    pass
                finally:
                    if proc.stdin is not None:
                        proc.stdin.close()

            writer = threading.Thread(target=_feed, daemon=True)
            writer.start()

        try:
            assert proc.stdout is not None
            for raw in proc.stdout:
                line = raw.rstrip()
                if not line:
                    continue
                self._log_line(line)
                if status_cb:
                    for key, value in self._parse_status(line).items():
                        status_cb({key: value})
                if stop_event.is_set():
                    logger.info("[{}] stop requested — terminating", self.name)
                    proc.terminate()
                    try:
                        proc.wait(timeout=10)
                    except Exception:
                        proc.kill()
                    return -2
            proc.wait()
        finally:
            self._current_proc = None
        return proc.returncode

    def _log_line(self, line: str) -> None:
        logger.debug("[{}] {}", self.name, line)

    def _parse_status(self, line: str) -> dict:  # pragma: no cover - override
        return {}
