"""SQLite store: results, runs, analytics."""

from wicrack.core.models import CrackResult
from wicrack.selftest import make_test_22000


def _result(key="TestPass123!", essid="SelfTestNet", stage="A: best64"):
    line, _ = make_test_22000()
    head = line.rsplit(":", 1)[0] if ":" in line else line
    raw = f"{head}:{key}"
    return CrackResult.from_pot_line(raw, source="hashcat", stage=stage)


def test_from_pot_line():
    r = _result()
    assert r is not None
    assert r.essid == "SelfTestNet"
    assert r.key == "TestPass123!"
    assert r.key_len == len("TestPass123!")
    assert r.mode == "PMKID"
    assert r.has_space is False
    assert r.only_digits is False


def test_from_pot_line_with_space_key():
    r = _result(key="pass phrase 1")
    assert r.has_space is True
    assert r.only_digits is False


def test_store_roundtrip(store):
    store.add_results([_result(), _result(key="SecondKey99", stage="D: mask")])
    rows = store.all_results()
    assert len(rows) == 2
    assert rows[0]["essid"] == "SelfTestNet"
    assert {r["key"] for r in rows} == {"TestPass123!", "SecondKey99"}


def test_known_keys_and_learning(store):
    store.add_results([_result("LongPassword1"), _result("LongPassword2"), _result("OtherLong12")])
    assert "LongPassword1" in store.known_keys()
    keys = store.keys_for_learning(min_len=8)
    assert len(keys) == 3


def test_analytics_and_runs(store):
    assert store.analytics() is None  # empty
    store.add_results([_result()])
    store.add_run("cap1.cap", "cracked")
    stats = store.analytics()
    assert stats["total"] == 1
    assert stats["top_stages"][0]["stage"].startswith("A:")
    runs = store.recent_runs()
    assert runs[0]["file"] == "cap1.cap"
    assert runs[0]["result"] == "cracked"
