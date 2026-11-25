"""Shared fixtures: isolated settings, store, sample artifacts, mock engine."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:  # allow pytest without editable install
    sys.path.insert(0, str(SRC))

from wicrack.config import Settings  # noqa: E402
from wicrack.core.store import Store  # noqa: E402
from wicrack.engines.base import BaseEngine  # noqa: E402
from wicrack.selftest import make_test_22000  # noqa: E402


@pytest.fixture
def settings(tmp_path) -> Settings:
    s = Settings(
        data_dir=tmp_path / "data",
        uploads_dir=tmp_path / "data" / "uploads",
        log_dir=tmp_path / "data" / "logs",
        report_dir=tmp_path / "data" / "reports",
        text_report_path=tmp_path / "data" / "cracked_passwords.txt",
        csv_export_path=tmp_path / "data" / "cracked_export.csv",
        capture_dir=tmp_path / "captures",
        wordlists=[],
        benchmark=False,
        web_password="testpw",
        seed_file=tmp_path / "data" / "seeds.txt",
        seed_core_file=tmp_path / "data" / "seeds_core.txt",
        rules_ortra=tmp_path / "data" / "OneRuleToRuleThemAll.rule",
    )
    s.ensure_dirs()
    return s


@pytest.fixture
def store(settings) -> Store:
    return Store(settings.db_path)


@pytest.fixture
def hc22000_file(tmp_path) -> Path:
    line, _ = make_test_22000()
    path = tmp_path / "sample.hc22000"
    path.write_text(line + "\n", encoding="utf-8")
    return path


class MockEngine(BaseEngine):
    """Deterministic in-process engine for pipeline/web tests."""

    name = "mock"

    def __init__(self, settings, keys=("TestPass123!",)):
        super().__init__(settings)
        self.keys = list(keys)
        self.calls: list[str] = []

    def available(self) -> bool:
        return True

    def crack(self, attack, source, *, stop_event, status_cb=None, session=None) -> int:
        self.calls.append(attack.label)
        return 0

    def pot_check(self, source) -> list[str]:
        line, _ = make_test_22000()
        head = line.rsplit(":", 1)[0] if ":" in line else line
        return [f"{head}:{key}" for key in self.keys]


@pytest.fixture
def mock_engine(settings) -> MockEngine:
    return MockEngine(settings)


@pytest.fixture
def make_engine(settings):
    """Factory: MockEngine with custom potfile contents."""

    def _make(keys=("TestPass123!",)) -> MockEngine:
        return MockEngine(settings, keys=keys)

    return _make


@pytest.fixture
def client(settings, store, mock_engine):
    from wicrack.core.jobqueue import JobManager
    from wicrack.web.app import create_app

    mgr = JobManager(settings, mock_engine, store, interactive=False)
    app = create_app(settings, job_manager=mgr, store=store)
    return app.test_client()


@pytest.fixture
def wordlist(tmp_path) -> Path:
    wl = tmp_path / "mini_wordlist.txt"
    wl.write_text("password\nhello\nworld\nTestPass123!\n", encoding="utf-8")
    return wl
