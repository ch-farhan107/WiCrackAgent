"""Cracking engines: hashcat (GPU/OpenCL) + John the Ripper (CPU)."""

from wicrack.engines.base import AttackSpec, BaseEngine, Engine
from wicrack.engines.hashcat_engine import HashcatEngine
from wicrack.engines.john_engine import JohnEngine
from wicrack.engines.selector import select_engine

__all__ = [
    "AttackSpec",
    "Engine",
    "BaseEngine",
    "HashcatEngine",
    "JohnEngine",
    "select_engine",
]
