"""Engine selection: forced modes + auto fallback chain (mocked tools)."""

import pytest

from wicrack.engines import selector
from wicrack.engines.hashcat_engine import HashcatEngine
from wicrack.engines.john_engine import JohnEngine
from wicrack.engines.selector import EngineUnavailable, select_engine


def _patch_tools(monkeypatch, *, hashcat=False, john=False, gpus=0):
    monkeypatch.setattr(selector, "gpu_count", lambda: gpus)
    monkeypatch.setattr(selector, "device_names", lambda: [])
    monkeypatch.setattr(HashcatEngine, "available", lambda self: hashcat)
    monkeypatch.setattr(JohnEngine, "available", lambda self: john)


def test_forced_hashcat_missing(settings, monkeypatch):
    _patch_tools(monkeypatch, hashcat=False, john=True)
    settings.engine = "hashcat"
    with pytest.raises(EngineUnavailable):
        select_engine(settings)


def test_forced_john(settings, monkeypatch):
    _patch_tools(monkeypatch, hashcat=True, john=True)
    settings.engine = "john"
    assert isinstance(select_engine(settings), JohnEngine)


def test_auto_prefers_gpu(settings, monkeypatch):
    _patch_tools(monkeypatch, hashcat=True, john=True, gpus=2)
    settings.engine = "auto"
    assert isinstance(select_engine(settings), HashcatEngine)


def test_auto_falls_back_to_cpu_john(settings, monkeypatch):
    _patch_tools(monkeypatch, hashcat=True, john=True, gpus=0)
    settings.engine = "auto"
    assert isinstance(select_engine(settings), JohnEngine)


def test_auto_raises_when_nothing_installed(settings, monkeypatch):
    _patch_tools(monkeypatch, hashcat=False, john=False)
    settings.engine = "auto"
    with pytest.raises(EngineUnavailable):
        select_engine(settings)


def test_hashcat_attack_mapping(settings, hc22000_file):
    """AttackSpec -> hashcat args sanity (dry-run path logs, never spawns)."""
    import threading

    from wicrack.capture.parser import parse_22000_file
    from wicrack.core.models import CrackSource
    from wicrack.engines.base import AttackSpec

    settings.dry_run = True
    engine = HashcatEngine(settings)
    source = CrackSource(cap=hc22000_file.with_suffix(".cap"), hc22000=hc22000_file)
    assert parse_22000_file(hc22000_file)

    stop = threading.Event()
    for attack in [
        AttackSpec(kind="mask", label="t-mask", mask="?d?d?d?d", custom_charset="?d"),
        AttackSpec(kind="straight", label="t-straight", wordlist=settings.data_dir / "wl.txt"),
        AttackSpec(
            kind="combinator",
            label="t-combo",
            wordlist=settings.data_dir / "wl.txt",
            right_wordlist=settings.data_dir / "wl.txt",
            separator="$-",
        ),
        AttackSpec(
            kind="hybrid_word_mask",
            label="t-hyb",
            wordlist=settings.data_dir / "wl.txt",
            mask="?d?d",
        ),
    ]:
        assert engine.crack(attack, source, stop_event=stop) == 0


def test_john_rejects_combinator(settings, tmp_path):
    import threading

    from wicrack.capture.converter import convert_to_john  # noqa: F401
    from wicrack.core.models import CrackSource
    from wicrack.engines.base import AttackSpec

    john_hash = tmp_path / "sample.john"
    john_hash.write_text("hash:plain\n")
    settings.dry_run = True
    engine = JohnEngine(settings)
    source = CrackSource(cap=tmp_path / "x.cap", john=john_hash)
    attack = AttackSpec(kind="combinator", label="t", wordlist=john_hash)
    assert engine.crack(attack, source, stop_event=threading.Event()) == -1
