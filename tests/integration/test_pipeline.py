"""Full pipeline integration: MockEngine + real stages + real store."""

import threading

from wicrack.capture.parser import parse_22000_file
from wicrack.core.models import CrackSource
from wicrack.stages import run_pipeline
from wicrack.stages.base import StageContext


def _make_ctx(settings, engine, source, targets, store, confirm=lambda a: True):
    return StageContext(
        settings=settings,
        engine=engine,
        source=source,
        targets=targets,
        store=store,
        stop_event=threading.Event(),
        state_cb=lambda updates: None,
        confirm=confirm,
    )


def test_pipeline_cracks_on_first_attack(settings, mock_engine, store, hc22000_file, wordlist):
    settings.wordlists = [wordlist]
    source = CrackSource(cap=hc22000_file.with_suffix(".cap"), hc22000=hc22000_file)
    targets = parse_22000_file(hc22000_file)
    ctx = _make_ctx(settings, mock_engine, source, targets, store)

    cracked, results, label = run_pipeline(ctx)
    assert cracked is True
    assert results and results[0].key == "TestPass123!"
    assert label == "E0: ESSID as password"  # first stage wins
    assert mock_engine.calls[0].startswith("E0")
    assert store.analytics()["total"] == 1


def test_pipeline_skips_disabled_stages(settings, mock_engine, store, hc22000_file, wordlist):
    settings.wordlists = [wordlist]
    settings.enable_ortra = False
    settings.enable_combinator = False
    source = CrackSource(cap=hc22000_file.with_suffix(".cap"), hc22000=hc22000_file)
    ctx = _make_ctx(settings, mock_engine, source, parse_22000_file(hc22000_file), store)

    run_pipeline(ctx)
    labels = mock_engine.calls
    assert not any("A2" in lbl for lbl in labels)  # ortra disabled
    assert not any("E1" in lbl or "E3" in lbl for lbl in labels)


def test_pipeline_respects_declined_heavy(settings, make_engine, store, hc22000_file, wordlist):
    engine = make_engine(keys=[])  # never cracks -> full pipeline walk
    settings.wordlists = [wordlist]
    # provide the rule files so the heavy stages actually yield attacks
    settings.rules_ortra.write_text("$1\n")
    settings.rules_heavy = settings.data_dir / "dive.rule"
    settings.rules_heavy.write_text("$1\n")
    source = CrackSource(cap=hc22000_file.with_suffix(".cap"), hc22000=hc22000_file)
    declined = []

    def confirm(attack):
        declined.append(attack.label)
        return False

    ctx = _make_ctx(
        settings, engine, source, parse_22000_file(hc22000_file), store, confirm=confirm
    )
    run_pipeline(ctx)
    assert any("A2" in lbl for lbl in declined)
    assert any("dive" in lbl for lbl in declined)
    # heavy attacks were never executed
    assert not any("A2" in lbl or "dive" in lbl for lbl in engine.calls)


def test_pipeline_stop_event_halts(settings, mock_engine, store, hc22000_file, wordlist):
    settings.wordlists = [wordlist]
    source = CrackSource(cap=hc22000_file.with_suffix(".cap"), hc22000=hc22000_file)
    ctx = _make_ctx(settings, mock_engine, source, parse_22000_file(hc22000_file), store)
    ctx.stop_event.set()
    cracked, results, _ = run_pipeline(ctx)
    assert cracked is False
    assert results == []
    assert mock_engine.calls == []
