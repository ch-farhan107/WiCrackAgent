"""SQLite persistence for results, runs, and analytics."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from loguru import logger

from wicrack.core.models import CrackResult

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cracked (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT, source TEXT, essid TEXT, bssid TEXT, mode TEXT, key TEXT,
    key_len INTEGER, has_space INTEGER, only_digits INTEGER, stage TEXT
);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file TEXT, started TEXT, finished TEXT, result TEXT
);
"""


class Store:
    """Thin sqlite wrapper — one short-lived connection per operation."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.init()

    # ------------------------------------------------------------ lifecycle
    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path)
        con.row_factory = sqlite3.Row
        return con

    def init(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as con:
            con.executescript(_SCHEMA)

    # ------------------------------------------------------------- writes
    def add_results(self, results: list[CrackResult]) -> None:
        if not results:
            return
        with self._connect() as con:
            con.executemany(
                "INSERT INTO cracked (ts, source, essid, bssid, mode, key,"
                " key_len, has_space, only_digits, stage)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                [
                    (
                        r.ts,
                        r.source,
                        r.essid,
                        r.bssid,
                        r.mode,
                        r.key,
                        r.key_len,
                        int(r.has_space),
                        int(r.only_digits),
                        r.stage,
                    )
                    for r in results
                ],
            )
        logger.info("Stored {} result(s)", len(results))

    def add_run(self, filename: str, result: str) -> None:
        now = time.strftime("%H:%M:%S")
        with self._connect() as con:
            con.execute(
                "INSERT INTO runs (file, started, finished, result) VALUES (?,?,?,?)",
                (filename, now, now, result),
            )

    # -------------------------------------------------------------- reads
    def recent(self, limit: int = 15) -> list[sqlite3.Row]:
        with self._connect() as con:
            return list(
                con.execute("SELECT * FROM cracked ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            )

    def all_results(self) -> list[sqlite3.Row]:
        with self._connect() as con:
            return list(
                con.execute(
                    "SELECT ts, essid, bssid, mode, key, key_len, has_space,"
                    " only_digits, stage FROM cracked ORDER BY id"
                ).fetchall()
            )

    def recent_runs(self, limit: int = 25) -> list[sqlite3.Row]:
        with self._connect() as con:
            return list(
                con.execute(
                    "SELECT file, started, finished, result FROM runs ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            )

    def known_keys(self) -> set[str]:
        with self._connect() as con:
            return {row["key"] for row in con.execute("SELECT key FROM cracked").fetchall()}

    def keys_for_learning(self, min_len: int = 8) -> list[str]:
        with self._connect() as con:
            return [
                row["key"]
                for row in con.execute(
                    "SELECT key FROM cracked WHERE key_len >= ?", (min_len,)
                ).fetchall()
            ]

    # ---------------------------------------------------------- analytics
    def analytics(self) -> dict | None:
        with self._connect() as con:
            row = con.execute(
                "SELECT COUNT(*) AS n, AVG(key_len) AS avg_len,"
                " SUM(has_space) AS with_space, SUM(only_digits) AS digits"
                " FROM cracked"
            ).fetchone()
            if not row or row["n"] == 0:
                return None
            stages = con.execute(
                "SELECT stage, COUNT(*) AS c FROM cracked GROUP BY stage ORDER BY c DESC LIMIT 3"
            ).fetchall()
        return {
            "total": row["n"],
            "avg_len": round(row["avg_len"], 1) if row["avg_len"] else 0,
            "with_space": row["with_space"] or 0,
            "only_digits": row["digits"] or 0,
            "top_stages": [{"stage": s["stage"], "count": s["c"]} for s in stages],
        }
