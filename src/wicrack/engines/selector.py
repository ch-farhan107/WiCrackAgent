"""Automatic engine selection: GPU -> hashcat, CPU -> John, fallback chain."""

from __future__ import annotations

from loguru import logger

from wicrack.engines.base import Engine
from wicrack.engines.hardware import device_names, gpu_count
from wicrack.engines.hashcat_engine import HashcatEngine
from wicrack.engines.john_engine import JohnEngine


class EngineUnavailable(RuntimeError):
    pass


def select_engine(settings) -> Engine:
    """Pick the best available engine for this machine.

    Priority (auto mode): GPU hashcat > John (CPU) > hashcat CPU > error.
    """
    hashcat = HashcatEngine(settings)
    john = JohnEngine(settings)

    if settings.engine == "hashcat":
        if not hashcat.available():
            raise EngineUnavailable("hashcat forced but not installed")
        return hashcat
    if settings.engine == "john":
        if not john.available():
            raise EngineUnavailable("john forced but not installed")
        return john

    gpus = gpu_count() if hashcat.available() else 0
    for name in device_names():
        logger.info("OpenCL device: {}", name)

    if gpus > 0:
        logger.success("Engine: hashcat ({} GPU device(s))", gpus)
        return hashcat
    if john.available():
        logger.success("Engine: John the Ripper (CPU mode)")
        return john
    if hashcat.available():
        logger.success("Engine: hashcat (CPU/OpenCL — slow for WPA)")
        return hashcat
    raise EngineUnavailable("No cracking engine found — install hashcat and/or john")
