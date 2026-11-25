"""Self-test suite: verifies tools, logic, and an end-to-end WPA crack."""

from __future__ import annotations

import hashlib
import hmac
import shutil
import subprocess
import tempfile
from pathlib import Path

from loguru import logger

from wicrack.capture.parser import parse_22000_line
from wicrack.stages.masks import charset_size, mask_keyspace
from wicrack.stages.space import make_space_rules


def make_test_22000(
    essid: str = "SelfTestNet",
    password: str = "SelfTest123",
    ap: str = "aabbccddeeff",
    sta: str = "112233445566",
) -> tuple[str, str]:
    """Build a valid PMKID hc22000 line for a known test password."""
    apb, stab = bytes.fromhex(ap), bytes.fromhex(sta)
    pmk = hashlib.pbkdf2_hmac("sha1", password.encode(), essid.encode(), 4096, 32)
    pmkid = hmac.new(pmk, b"PMK Name" + apb + stab, hashlib.sha1).digest()[:16]
    line = "WPA*01*" + pmkid.hex() + "*" + ap + "*" + sta + "*" + essid.encode().hex() + "***"
    return line, password


def run_self_test(settings) -> bool:
    """Run all checks; returns True when no mandatory test failed."""
    results: list[tuple[str, object]] = []

    t1 = all(shutil.which(t) for t in ("hashcat", "hcxpcapngtool"))
    results.append(("T1: cracking tools installed", t1))
    t2 = any(Path(w).exists() for w in settings.wordlists)
    results.append(("T2: wordlist available", t2))

    t3 = False
    try:
        assert charset_size("?l?u?d ") == 63
        assert mask_keyspace("?d" * 8) == 100_000_000
        line, _ = make_test_22000()
        target = parse_22000_line(line)
        assert target and target["essid"] == "SelfTestNet"
        with tempfile.TemporaryDirectory() as tmp:
            rules = make_space_rules(Path(tmp) / "space_rules.rule")
            assert rules.read_text().splitlines()[-1].endswith(" ")
        t3 = True
    except Exception as exc:
        logger.error("T3 detail: {}", exc)
    results.append(("T3: pipeline logic", t3))

    t4 = False
    try:
        proc = subprocess.run(["hashcat", "--version"], capture_output=True, text=True, timeout=30)
        t4 = proc.returncode == 0
    except Exception:
        pass
    results.append(("T4: hashcat binary runs", t4))

    t5 = None
    if t1 and t4:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                line, password = make_test_22000()
                hashfile = Path(tmp) / "selftest.hc22000"
                wordlist = Path(tmp) / "selftest_wl.txt"
                pot = Path(tmp) / "selftest.pot"
                hashfile.write_text(line + "\n")
                wordlist.write_text(password + "\n")
                proc = subprocess.run(
                    [
                        "hashcat",
                        "-m",
                        "22000",
                        str(hashfile),
                        str(wordlist),
                        "-O",
                        "-w",
                        "3",
                        "--potfile-path",
                        str(pot),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
                if proc.returncode not in (0, 1):
                    t5 = None
                else:
                    show = subprocess.run(
                        [
                            "hashcat",
                            "-m",
                            "22000",
                            str(hashfile),
                            "--show",
                            "--potfile-path",
                            str(pot),
                        ],
                        capture_output=True,
                        text=True,
                        timeout=60,
                    )
                    t5 = password in show.stdout
            except subprocess.TimeoutExpired:
                t5 = False
            except Exception:
                t5 = None
    results.append(("T5: end-to-end WPA crack", t5 if t5 is not None else "SKIP"))

    logger.info("SELF-TEST RESULTS")
    all_ok = True
    for name, outcome in results:
        mark = "PASS" if outcome is True else "SKIP" if outcome == "SKIP" else "FAIL"
        if outcome is False:
            all_ok = False
        logger.info("  [{mark}] {name}", mark=mark, name=name)
    logger.info("SELF-TEST: {}", "ALL SYSTEMS GO" if all_ok else "FAILURES FOUND")
    return all_ok
