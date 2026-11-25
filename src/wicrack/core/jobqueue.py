"""Job queue and worker thread: consumes captures, runs the pipeline."""

from __future__ import annotations

import queue
import threading
import time
from collections.abc import Callable
from pathlib import Path

from loguru import logger

from wicrack.capture.converter import convert_to_22000, convert_to_john
from wicrack.capture.parser import apply_filter, parse_22000_file
from wicrack.capture.sae_detect import detect_sae_frames
from wicrack.core.models import CrackResult, CrackSource
from wicrack.core.store import Store
from wicrack.engines.base import AttackSpec, Engine
from wicrack.stages.pipeline import run_pipeline


class JobManager:
    """Single-worker job queue shared by the CLI and the web console."""

    def __init__(
        self,
        settings,
        engine: Engine,
        store: Store,
        *,
        interactive: bool = False,
        notifier: Callable[[str], None] | None = None,
    ) -> None:
        self.settings = settings
        self.engine = engine
        self.store = store
        self.interactive = interactive
        self.notifier = notifier or (lambda text: None)
        self.queue: queue.Queue[Path] = queue.Queue()
        self.stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._state: dict = {
            "current_file": "-",
            "current_stage": "-",
            "speed": "-",
            "progress": "-",
            "files_done": 0,
            "files_total": 0,
            "cracked": 0,
            "failed": 0,
            "started": time.strftime("%H:%M:%S"),
        }

    # ------------------------------------------------------------- control
    def start_worker(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._worker, name="wicrack-worker", daemon=True)
        self._thread.start()
        logger.info("Job worker thread started")

    def submit(self, paths: list[Path]) -> int:
        for path in paths:
            self.queue.put(path)
        with self._lock:
            self._state["files_total"] += len(paths)
        logger.info("{} job(s) queued", len(paths))
        return len(paths)

    def stop(self) -> None:
        self.stop_event.set()
        self.engine.terminate_current()
        logger.warning(
            "STOP requested — current attack terminated, remaining queue will be cancelled"
        )

    def resume(self) -> None:
        self.stop_event.clear()

    # --------------------------------------------------------------- state
    def _update(self, updates: dict) -> None:
        with self._lock:
            self._state.update(updates)

    def snapshot(self) -> dict:
        with self._lock:
            state = dict(self._state)
        state["queue"] = self.queue.qsize()
        state["stopped"] = self.stop_event.is_set()
        state["engine"] = self.engine.name
        return state

    # -------------------------------------------------------------- worker
    def _worker(self) -> None:
        while True:
            job = self.queue.get()
            try:
                if self.stop_event.is_set():
                    self.store.add_run(job.name, "stopped")
                    continue
                logger.info("Job start: {} (queue remaining: {})", job.name, self.queue.qsize())
                self._update({"current_file": job.name})
                try:
                    self._process(job)
                except Exception as exc:  # keep the worker alive
                    logger.exception("Job crashed: {}", exc)
                    self.store.add_run(job.name, f"error: {exc}")
                    self._update({"failed": self._state["failed"] + 1})
            finally:
                self.queue.task_done()

    # ------------------------------------------------------------ per-file
    def _confirm(self, attack: AttackSpec) -> bool:
        """Heavy-attack gate: schedule window + threshold + mode policy."""
        s = self.settings
        if s.dry_run:
            return True
        if not s.in_schedule_window():
            if not self.interactive or s.assume_yes:
                logger.info(
                    "[schedule] '{}' outside heavy window {} — skip", attack.label, s.heavy_window
                )
                return False
            try:
                answer = input(
                    f"    '{attack.label}' is outside the heavy "
                    f"window {s.heavy_window}. Run anyway? [y/N]: "
                )
                return answer.strip().lower() in ("y", "yes")
            except (EOFError, KeyboardInterrupt):
                return False

        est = attack.estimated_candidates or 0
        est_h = est / max(s.est_speed, 1) / 3600
        if est_h <= s.auto_ok_hours or s.assume_yes:
            return True
        if not self.interactive:
            if s.web_auto_approve_heavy:
                logger.info("[web] '{}' heavy ({:.1f}h est) — auto-approved", attack.label, est_h)
                return True
            logger.info(
                "[web] '{}' heavy ({:.1f}h est) — skipped. Enable "
                "'Auto-approve heavy' in settings or use the CLI.",
                attack.label,
                est_h,
            )
            return False
        logger.warning(
            "'{0}' estimated ~{1:.1f}h (keyspace {2:,} @ {3:,} H/s)",
            attack.label,
            est_h,
            est,
            s.est_speed,
        )
        try:
            answer = input("    Continue? [y/N]: ")
            return answer.strip().lower() in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            return False

    def _process(self, cap: Path) -> bool:
        s = self.settings
        self.store.add_run(cap.name, "started")
        detect_sae_frames(cap)

        hc = convert_to_22000(cap)
        if hc is None:
            self.store.add_run(cap.name, "no-handshake")
            self._update({"failed": self._state["failed"] + 1})
            return False
        source = CrackSource(cap=cap, hc22000=hc)
        if self.engine.name == "john":
            source.john = convert_to_john(cap)

        targets = parse_22000_file(hc)
        for t in targets:
            logger.info("  target: {} | ESSID '{}' | AP {}", t["type"], t["essid"], t["ap"])
        filtered = apply_filter(
            hc, targets, essids=s.filter_essids, bssids=s.filter_bssids, mode=s.filter_mode
        )
        if filtered is None:
            self.store.add_run(cap.name, "filtered-out")
            return False
        source.hc22000 = filtered

        # Already cracked previously? (potfile persists across runs)
        known = self.engine.pot_check(source)
        if known:
            results = [
                r
                for r in (
                    CrackResult.from_pot_line(ln, source="potfile", stage="potfile") for ln in known
                )
                if r
            ]
            self._finish_crack(source, results)
            return True

        ctx = _make_context(self, source, targets)
        cracked, fresh, label = run_pipeline(ctx)
        if cracked:
            self._finish_crack(source, fresh, label)
            return True

        logger.warning("RESULT: {} — not cracked", cap.name)
        self.store.add_run(cap.name, "failed")
        self._update({"failed": self._state["failed"] + 1})
        return False

    def _finish_crack(
        self,
        source: CrackSource,
        results: list[CrackResult],
        label: str = "potfile",
    ) -> None:
        from wicrack.reporting.text_report import append_text_report

        self.store.add_results(results)
        append_text_report(self.settings.text_report_path, source, results)
        self.notifier(
            "CRACKED: "
            + (results[0].essid if results else "?")
            + "\n"
            + "\n".join(r.key for r in results[:3])
        )
        self.store.add_run(source.cap.name, "cracked")
        self._update({"cracked": self._state["cracked"] + 1})
        logger.success("Result saved (stage: {})", label)


def _make_context(mgr: JobManager, source: CrackSource, targets: list[dict]):
    from wicrack.stages.base import StageContext

    return StageContext(
        settings=mgr.settings,
        engine=mgr.engine,
        source=source,
        targets=targets,
        store=mgr.store,
        stop_event=mgr.stop_event,
        state_cb=mgr._update,
        confirm=mgr._confirm,
    )
