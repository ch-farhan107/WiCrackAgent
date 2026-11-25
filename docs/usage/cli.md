# CLI reference

Every command ships `--help`. Global behaviour comes from environment
variables (`WICRACK_*` prefix) and `data/web_state.json` overrides.

## wicrack serve

| Flag | Meaning |
|------|---------|
| `--host` / `--port` | bind address (default `0.0.0.0:5000`) |
| `--engine auto\|hashcat\|john` | force a backend |
| `--dry-run` | log planned commands without running them |

## wicrack crack

| Flag | Meaning |
|------|---------|
| `-f, --folder` | capture folder (default `wifi_captures/`) |
| `-y, --yes` | approve heavy stages without prompting |
| `--dry-run` | print the plan table and exit |
| `--no-benchmark` | skip the startup benchmark |
| `--engine` | force backend |

Runs the full 12-stage pipeline per capture, stores results in SQLite,
appends `data/cracked_passwords.txt`, exports CSV, and prints analytics.

## wicrack scan

Convert captures and list every target (type, ESSID, BSSID) — useful to
verify a capture actually contains handshakes before burning GPU time.

## wicrack bench

Benchmark WPA (mode 22000) speed; cached for one hour in
`data/benchmark.json` (`--no-cache` to force).

## wicrack report

```
wicrack report --format html --engagement "ACME Wireless Audit"
wicrack report --format evidence        # SHA-256 redacted by default
```

## wicrack assets download

`rockyou` (~135 MB) and `ortra` (OneRuleToRuleThemAll.rule) from verified
upstream URLs, with progress logging.

## wicrack vault export / read

Fernet (AES + HMAC, PBKDF2 480k iterations) archive of every result.
Losing the master password means losing the data — by design.

## wicrack selftest

Six-point verification including a real end-to-end WPA crack (T5).
