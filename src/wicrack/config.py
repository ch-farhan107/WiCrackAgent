"""Central configuration (pydantic-settings).

Every field can be overridden via environment variables with the ``WICRACK_``
prefix (e.g. ``WICRACK_WEB_PORT=8080``), a ``.env`` file, or a JSON config
passed programmatically.
"""

from __future__ import annotations

import json
import re
import secrets
import stat
import time
from pathlib import Path
from typing import ClassVar, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_WINDOW_RE = re.compile(r"^\s*(\d{1,2}):(\d{2})\s*-\s*(\d{1,2}):(\d{2})\s*$")


class Settings(BaseSettings):
    """Validated runtime settings for the whole application."""

    model_config = SettingsConfigDict(
        env_prefix="WICRACK_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        validate_assignment=True,
    )

    # ------------------------------------------------------------------ paths
    capture_dir: Path = Path("wifi_captures")
    data_dir: Path = Path("data")
    uploads_dir: Path = Path("data/uploads")
    log_dir: Path = Path("data/logs")
    report_dir: Path = Path("data/reports")
    text_report_path: Path = Path("data/cracked_passwords.txt")
    csv_export_path: Path = Path("data/cracked_export.csv")

    wordlists: list[Path] = Field(
        default_factory=lambda: [Path("/usr/share/wordlists/rockyou.txt")]
    )
    rules: Path = Path("/usr/share/hashcat/rules/best64.rule")
    rules_heavy: Path = Path("/usr/share/hashcat/rules/dive.rule")
    rules_ortra: Path = Path("data/OneRuleToRuleThemAll.rule")

    # seed extraction (combinator / mangler input)
    seed_file: Path = Path("data/seeds.txt")
    seed_core_file: Path = Path("data/seeds_core.txt")
    seed_min_len: int = Field(4, ge=1)
    seed_max_len: int = Field(10, ge=1)
    seed_limit: int = Field(10000, ge=1)
    seed_core_limit: int = Field(300, ge=1)
    alnum_only: bool = True

    # ----------------------------------------------------------------- engine
    engine: Literal["auto", "hashcat", "john"] = "auto"
    workload: int = Field(3, ge=1, le=4)
    optimized: bool = True
    temp_abort: int = Field(85, ge=30, le=120)
    status_timer: int = Field(20, ge=5)
    devices: str = ""
    benchmark: bool = True
    est_speed: int = Field(100_000, ge=1)
    auto_ok_hours: float = Field(2.0, ge=0)
    assume_yes: bool = False
    heavy_window: str | None = None  # "22:00-06:00" (wraps midnight)

    # ----------------------------------------------------------------- stages
    enable_ortra: bool = True
    enable_kbwalks: bool = True
    enable_mangler: bool = True
    enable_mask_learning: bool = True
    enable_combinator: bool = True
    enable_three_word: bool = False
    enable_brain: bool = False
    brain_host: str = "127.0.0.1"
    brain_port: int = Field(13643, ge=1, le=65535)
    brain_password: str = "wicrack"

    # ------------------------------------------------------------------ masks
    mask_charset: str = "?l?u?d "
    mask_presets: list[str] = Field(
        default_factory=lambda: [
            "?d" * 8,
            "?d" * 10,
            "?u?l?l?l?l?l?d?d",
            "?1" * 16,
            "?1" * 8,
        ]
    )
    hybrid_digit_masks: list[str] = Field(
        default_factory=lambda: [
            "?d?d",
            "?d?d?d",
            "?d?d?d?d",
            "123",
            "1234",
            "2024",
            "2025",
            "2026",
        ]
    )
    combo_separators: list[str] = Field(default_factory=lambda: ["", " ", "-", "_", ".", "!", "@"])

    # ---------------------------------------------------------- target filter
    filter_essids: list[str] = Field(default_factory=list)
    filter_bssids: list[str] = Field(default_factory=list)
    filter_mode: Literal["include", "exclude"] = "include"

    # ------------------------------------------------------------------- web
    web_host: str = "0.0.0.0"
    web_port: int = Field(5000, ge=1, le=65535)
    web_password: str = ""  # empty -> generated on first run
    web_auto_approve_heavy: bool = False
    max_upload_mb: int = Field(500, ge=1, le=10240)

    # ---------------------------------------------------------------- notify
    telegram_token: str = ""
    telegram_chat_id: str = ""
    discord_webhook: str = ""

    # ----------------------------------------------------- distributed (exp.)
    worker_id: int = Field(1, ge=1)
    worker_total: int = Field(1, ge=1)

    # ------------------------------------------------------------------ misc
    dry_run: bool = False
    keep_hc22000: bool = True

    # ------------------------------------------------------------ validators
    @field_validator(
        "wordlists",
        "mask_presets",
        "hybrid_digit_masks",
        "combo_separators",
        "filter_essids",
        "filter_bssids",
        mode="before",
    )
    @classmethod
    def _split_csv(cls, v: object) -> object:
        """Accept comma-separated strings (env vars / web form) for lists."""
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return v

    @field_validator("heavy_window")
    @classmethod
    def _validate_window(cls, v: str | None) -> str | None:
        if v is None or not str(v).strip():
            return None
        if not _WINDOW_RE.match(str(v)):
            raise ValueError('heavy_window must look like "22:00-06:00"')
        return str(v).strip()

    # ----------------------------------------------------------- derived paths
    @property
    def potfile_path(self) -> Path:
        return self.data_dir / "potfile"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "wicrack.db"

    @property
    def web_state_path(self) -> Path:
        return self.data_dir / "web_state.json"

    @property
    def benchmark_cache(self) -> Path:
        return self.data_dir / "benchmark.json"

    def ensure_dirs(self) -> None:
        for p in (self.data_dir, self.uploads_dir, self.log_dir, self.report_dir, self.capture_dir):
            p.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------ schedule
    @property
    def heavy_window_range(self) -> tuple[float, float] | None:
        if not self.heavy_window:
            return None
        m = _WINDOW_RE.match(self.heavy_window)
        if not m:
            return None
        h1, m1, h2, m2 = map(int, m.groups())
        return (h1 + m1 / 60) % 24, (h2 + m2 / 60) % 24

    def in_schedule_window(self, now: time.struct_time | None = None) -> bool:
        rng = self.heavy_window_range
        if rng is None:
            return True
        lt = now or time.localtime()
        cur = lt.tm_hour + lt.tm_min / 60
        start, end = rng
        return (cur >= start or cur < end) if start > end else (start <= cur < end)

    # ------------------------------------------------- web state persistence
    WEB_EDITABLE_FIELDS: ClassVar[tuple[str, ...]] = (
        "wordlists",
        "rules",
        "rules_ortra",
        "workload",
        "optimized",
        "temp_abort",
        "auto_ok_hours",
        "enable_ortra",
        "enable_kbwalks",
        "enable_mangler",
        "enable_mask_learning",
        "enable_combinator",
        "enable_three_word",
        "enable_brain",
        "web_auto_approve_heavy",
        "heavy_window",
        "telegram_token",
        "telegram_chat_id",
        "discord_webhook",
        "filter_essids",
        "filter_bssids",
        "filter_mode",
        "web_password",
    )

    def load_web_state(self) -> dict:
        try:
            return json.loads(self.web_state_path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def save_web_state(self, state: dict) -> None:
        self.web_state_path.parent.mkdir(parents=True, exist_ok=True)
        self.web_state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
        self.web_state_path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600

    def save_web_overrides(self) -> None:
        state = self.load_web_state()
        state["config"] = self.model_dump(mode="json", include=set(self.WEB_EDITABLE_FIELDS))
        self.save_web_state(state)

    def load_web_overrides(self) -> None:
        saved = self.load_web_state().get("config")
        if not saved:
            return
        for key, value in saved.items():
            if key in self.WEB_EDITABLE_FIELDS and value is not None:
                setattr(self, key, value)

    # ---------------------------------------------------------------- secrets
    def ensure_web_password(self) -> str:
        """Return configured password, or generate + persist a strong one."""
        if self.web_password:
            return self.web_password
        state = self.load_web_state()
        pw = state.get("web_password")
        if not pw:
            pw = secrets.token_urlsafe(12)
            state["web_password"] = pw
            state.setdefault("session_secret", secrets.token_hex(32))
            self.save_web_state(state)
        self.web_password = pw
        return pw

    def ensure_session_secret(self) -> str:
        state = self.load_web_state()
        secret = state.get("session_secret")
        if not secret:
            secret = secrets.token_hex(32)
            state["session_secret"] = secret
            self.save_web_state(state)
        return secret

    def change_web_password(self, new_password: str) -> None:
        self.web_password = new_password
        self.save_web_overrides()
