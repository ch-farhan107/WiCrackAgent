"""Settings: defaults, env overrides, schedule window, secrets persistence."""

import time

import pytest

from wicrack.config import Settings


def test_defaults():
    s = Settings()
    assert s.workload == 3
    assert s.engine == "auto"
    assert s.web_port == 5000
    assert len(s.mask_presets) == 5


def test_env_override(monkeypatch):
    monkeypatch.setenv("WICRACK_WEB_PORT", "8080")
    monkeypatch.setenv("WICRACK_FILTER_ESSIDS", '["a", "b", "c"]')
    s = Settings()
    assert s.web_port == 8080
    assert s.filter_essids == ["a", "b", "c"]


def test_csv_string_assignment_via_validator(settings):
    settings.filter_essids = "one, two,three"
    assert settings.filter_essids == ["one", "two", "three"]


def test_heavy_window_validation(settings):
    settings.heavy_window = "22:00-06:00"
    assert settings.heavy_window_range == (22.0, 6.0)
    with pytest.raises(ValueError):
        settings.heavy_window = "invalid"
    settings.heavy_window = None
    assert settings.in_schedule_window() is True


def test_schedule_window_boundaries(settings):
    settings.heavy_window = "22:00-06:00"

    def fake(hour, minute=0):
        return time.struct_time((2026, 1, 1, hour, minute, 0, 0, 1, 0))

    assert settings.in_schedule_window(fake(23)) is True
    assert settings.in_schedule_window(fake(2, 30)) is True
    assert settings.in_schedule_window(fake(12)) is False

    settings.heavy_window = "09:00-17:00"
    assert settings.in_schedule_window(fake(12)) is True
    assert settings.in_schedule_window(fake(20)) is False


def test_web_password_generation(settings):
    fresh = Settings(data_dir=settings.data_dir)  # no pre-set password
    first = fresh.ensure_web_password()
    assert first and first != ""
    second = fresh.ensure_web_password()
    assert first == second  # persisted, not regenerated
    assert settings.web_state_path.exists()


def test_web_overrides_roundtrip(settings):
    settings.workload = 4
    settings.telegram_token = "abc"
    settings.save_web_overrides()
    fresh = Settings(data_dir=settings.data_dir)
    fresh.load_web_overrides()
    assert fresh.workload == 4
    assert fresh.telegram_token == "abc"


def test_change_password_persists(settings):
    settings.change_web_password("newpw123")
    again = Settings(data_dir=settings.data_dir)
    again.load_web_overrides()
    assert again.web_password == "newpw123"
