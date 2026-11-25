# Changelog

All notable changes to WiCrackAgent are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-11-24

First public release. Complete rewrite of the single-file prototype into a
professional, installable framework.

### Added
- Installable Python package (`pip install wicrack`) with Typer CLI:
  `serve`, `crack`, `scan`, `bench`, `report`, `assets`, `vault`, `selftest`.
- **Dual cracking engine** — hashcat (GPU/OpenCL) and John the Ripper (CPU)
  with automatic engine selection and hardware benchmarking (`wicrack bench`).
- Class-based **12-stage attack pipeline**: ESSID targets, wordlist+best64,
  OneRuleToRuleThemAll, dive.rule, space-aware rules, mask presets, keyboard
  walks, mangler, mask learning from previous cracks, combinator, hybrid
  digit masks, 2/3-word phrase generation.
- **Web console v2** — Flask + Jinja2, WebSocket live status/speed chart,
  first-run generated password, drag-and-drop capture upload, job queue with
  start/stop, results browser, config editor, CSV/TXT/HTML report download.
- **REST API** (`/api/v1/...`) with an OpenAPI 3.1 specification.
- **Pentest report generator** — standalone client-ready HTML report with
  executive summary, methodology, findings, and hardening recommendations.
- **Evidence export** — audit-trail JSON with SHA-256 integrity hashing and
  optional plaintext redaction.
- **Encrypted vault** — Fernet (AES-128-CBC + HMAC, PBKDF2-derived key)
  storage for results archival.
- **Assets manager** — `wicrack assets download` fetches rockyou.txt and
  OneRuleToRuleThemAll.rule from verified upstream URLs.
- Telegram / Discord notifications on cracked targets.
- Target filtering (ESSID/BSSID include/exclude), WPA3/SAE detection warning,
  heavy-stage scheduling window, auto-approval thresholds, distributed worker
  splitting (experimental).
- Full test suite (pytest), CI (ruff, mypy, pytest matrix, package build),
  Docker image, mkdocs-material documentation site.

[1.0.0]: https://github.com/ch-farhan107/WiCrackAgent/releases/tag/v1.0.0
