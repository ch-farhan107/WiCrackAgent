"""Report generation, evidence export, and encrypted vault."""

import hashlib

import pytest

from wicrack.core.models import CrackResult
from wicrack.selftest import make_test_22000
from wicrack.vault import encrypt_store, read_vault


@pytest.fixture
def populated_store(store):
    line, _ = make_test_22000()
    head = line.rsplit(":", 1)[0]
    store.add_results(
        [
            CrackResult.from_pot_line(f"{head}:Winter2024", stage="A: best64"),
            CrackResult.from_pot_line(f"{head}:Winter2025", stage="A: best64"),
        ]
    )
    return store


def test_html_report_contains_findings(populated_store, settings):
    from wicrack.reporting.html_report import generate_html_report

    out = settings.report_dir / "report.html"
    path = generate_html_report(populated_store, settings, out, engagement="ACME Wireless Audit")
    html = path.read_text(encoding="utf-8")
    assert "Winter2024" in html  # finding present
    assert "ACME" in html  # engagement echoed
    assert "WPA3-SAE" in html  # recommendations section
    assert "<script" not in html  # standalone, no external js


def test_html_report_empty_store(settings, store):
    from wicrack.reporting.html_report import generate_html_report

    path = generate_html_report(store, settings, settings.report_dir / "empty.html")
    assert "No keys recovered" in path.read_text(encoding="utf-8")


def test_evidence_hashes_plaintext_by_default(populated_store, settings):
    from wicrack.reporting.evidence import export_evidence

    path = export_evidence(populated_store, settings.report_dir / "ev.json")
    data = path.read_text(encoding="utf-8")
    assert "Winter2024" not in data  # plaintext redacted
    assert hashlib.sha256(b"Winter2024").hexdigest() in data
    assert "integrity_sha256" in data


def test_evidence_plaintext_mode(populated_store, settings):
    from wicrack.reporting.evidence import export_evidence

    path = export_evidence(
        populated_store, settings.report_dir / "ev_plain.json", include_plaintext=True
    )
    assert "Winter2024" in path.read_text(encoding="utf-8")


def test_text_report_append(populated_store, settings):
    from wicrack.core.models import CrackSource
    from wicrack.reporting.text_report import append_text_report

    source = CrackSource(cap=settings.data_dir / "acme.cap")
    results = [CrackResult.from_pot_line(make_test_22000()[0].rsplit(":", 1)[0] + ":Winter2024")]
    append_text_report(settings.text_report_path, source, results)
    text = settings.text_report_path.read_text(encoding="utf-8")
    assert "acme.cap" in text and "Winter2024" in text


def test_vault_roundtrip(populated_store, settings):
    vault = encrypt_store(populated_store, settings, "master-secret")
    rows = read_vault(vault, settings.data_dir / "vault.salt", "master-secret")
    assert {r["key"] for r in rows} == {"Winter2024", "Winter2025"}


def test_vault_wrong_password(populated_store, settings):
    from wicrack.vault import encrypt_store

    vault = encrypt_store(populated_store, settings, "correct-horse")
    with pytest.raises(ValueError):
        read_vault(vault, settings.data_dir / "vault.salt", "wrong")
