"""Structured logging setup (loguru) with stdlib interception."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from types import FrameType

from loguru import logger

_CONSOLE_FMT = "<green>{time:HH:mm:ss}</green> | <level>{level: <7}</level> | {message}"
_FILE_FMT = "{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <7} | {name}:{function} — {message}"


class InterceptHandler(logging.Handler):
    """Route stdlib logging (werkzeug, paramiko, ...) through loguru."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            level: str | int = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno
        frame: FrameType | None = logging.currentframe()
        depth = 2
        while frame is not None and frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1
        logger.opt(depth=depth, exception=record.exc_info).log(level, record.getMessage())


def setup_logging(log_dir: Path, level: str = "INFO") -> None:
    """Configure console + rotating file sinks and capture stdlib logging."""
    logger.remove()
    logger.add(sys.stderr, level=level, format=_CONSOLE_FMT)
    log_dir.mkdir(parents=True, exist_ok=True)
    logger.add(
        log_dir / "wicrack.log",
        level="DEBUG",
        format=_FILE_FMT,
        rotation="20 MB",
        retention=10,
        encoding="utf-8",
    )
    logging.basicConfig(handlers=[InterceptHandler()], level=0, force=True)
    for noisy in ("werkzeug", "engineio", "socketio"):
        lg = logging.getLogger(noisy)
        lg.handlers = [InterceptHandler()]
        lg.propagate = False
