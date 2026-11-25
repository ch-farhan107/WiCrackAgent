<p align="center">
  <img src="assets/banner.svg" alt="WiCrackAgent" width="640">
</p>

<h1 align="center">WiCrackAgent</h1>

<p align="center">
  <b>Automated wireless security assessment framework</b><br>
  GPU + CPU dual engine · live web console · client-ready pentest reports
</p>

<p align="center">
  <a href="https://github.com/ch-farhan107/WiCrackAgent/actions/workflows/ci.yml"><img src="https://github.com/ch-farhan107/WiCrackAgent/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/ch-farhan107/WiCrackAgent/releases"><img src="https://img.shields.io/github/v/release/ch-farhan107/WiCrackAgent?include_prereleases" alt="Release"></a>
  <a href="https://github.com/ch-farhan107/WiCrackAgent/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue" alt="Python">
  <img src="https://img.shields.io/badge/code%20style-ruff-261230.svg" alt="Ruff">
  <img src="https://img.shields.io/badge/type%20check-mypy-blue.svg" alt="mypy">
</p>

> ⚠️ **AUTHORIZED USE ONLY** — WiCrackAgent is a security *assessment* tool for
> penetration testers. Run it against networks **you own** or are **contracted
> to test**. Unauthorized use is a crime almost everywhere. See
> [DISCLAIMER.md](DISCLAIMER.md).

---

## Why WiCrackAgent

Most WPA tools stop at "throw rockyou.txt at it". WiCrackAgent runs a **staged,
adaptive attack pipeline** with the polish a real engagement needs: a live web
console your team can watch, automatic GPU/CPU engine selection, and a
**client-ready HTML report** at the end — because a pentest deliverable is not
a terminal dump.

| | WiCrackAgent | Typical CLI tools |
|---|---|---|
| Engine | **hashcat (GPU) + John (CPU), auto-selected** | single engine |
| Attack strategy | **12-stage adaptive pipeline, learns from its own cracks** | one-shot wordlist |
| Interface | **live web console + REST API + CLI** | terminal only |
| Deliverable | **client-ready HTML report + evidence JSON + encrypted vault** | none |
| Space passwords | **dedicated stage** (common in real networks!) | missed |
| Setup | `pip install` + `wicrack serve` | manual tool glue |

## ✨ Features

- 🔌 **Dual cracking engine** — hashcat for NVIDIA/AMD GPUs, John the Ripper
  for CPU-only machines; automatic selection with hardware benchmarking.
- 🧠 **12-stage attack pipeline** — ESSID-derived passwords → wordlist+best64
  → OneRuleToRuleThemAll → dive.rule → space-rules → masks → keyboard walks →
  mangler → **mask learning from recovered keys** → combinator → digit hybrids
  → 2/3-word phrases.
- 🌐 **Web console v2** — drag-and-drop capture upload, WebSocket live speed
  chart, job queue with start/stop, settings editor, results browser.
- 🧾 **Pentest deliverables** — one-click client HTML report (executive
  summary, findings, remediation), SHA-256 evidence export, Fernet-encrypted
  results vault.
- 🔔 Telegram / Discord notifications the moment a key drops.
- 🎯 Target filtering (ESSID/BSSID include/exclude), WPA3/SAE detection,
  heavy-stage scheduling window, distributed worker splitting.
- 🧪 **66-test suite**, ruff + mypy clean, CI matrix (3.10–3.12), Docker image.

## 🚀 Quickstart

```bash
# 1. One-command install (Kali/Debian/Ubuntu)
bash install.sh --with-wordlists

# 2. Verify your setup (recommended first run)
wicrack selftest

# 3. Launch the web console
wicrack serve
```

Open `http://localhost:5000` — the **console password is generated on first
run and printed in the terminal** (also stored in `data/web_state.json`;
change it in *Settings*). Then: **Upload** a `.cap/.pcap/.pcapng` →
**Jobs → START** → watch the live dashboard → download the report.

### CLI alternative

```bash
wicrack crack -f ./wifi_captures          # full pipeline over a folder
wicrack scan -f ./wifi_captures           # just list targets found
wicrack bench                             # benchmark your hardware
wicrack report --format html              # client-ready report from the DB
wicrack vault export                      # encrypted archival of results
```

<details>
<summary><b>Docker</b></summary>

```bash
docker compose up --build      # web console on :5000, data/ + wifi_captures/ mounted
```
</details>

## 🖥️ The pipeline

| Stage | Attack | Heavy |
|-------|--------|-------|
| E0 | ESSID & variants (+digits) as passwords | |
| A | wordlist + best64 | |
| A2 | wordlist + **OneRuleToRuleThemAll** | ⚡ |
| B | wordlist + **dive.rule** | ⚡ |
| C | **space-aware rules** — passphrases with spaces | |
| D | mask presets (digits, Ulllldd, custom charset) | gated |
| F | keyboard walks (qwerty, 1qaz2wsx, …) + best64 | |
| G | mangler: leet/caps/digit mutations (streamed) | ⚡ |
| H | **mask learning from keys cracked in this run** | gated |
| E1 | combinator word+word with separators | ⚡ |
| E2 | word+digit / digit+word hybrids | |
| E3 | 2-word (and optional 3-word) phrases | ⚡ |

Heavy stages are **estimated by keyspace and gated** (schedule window,
auto-approve threshold, or an interactive prompt in CLI mode).

### Engine selection

| Hardware | Engine |
|----------|--------|
| NVIDIA / AMD GPU | hashcat (OpenCL/CUDA, `-O -w3`) |
| CPU-only laptop / VM | **John the Ripper** `wpapsk` (SIMD) |
| No engines found | clear error + install hint |

Override anytime: `wicrack serve --engine john`.

## 🌐 Web console

| Tab | What you do there |
|-----|-------------------|
| **Dashboard** | live speed chart (WebSocket), stage, queue, cracked counters |
| **Upload** | drag-and-drop captures, manage the queue input |
| **Settings** | wordlists, stages on/off, heavy window, notifications, filters |
| **Jobs** | START / STOP the worker, recent run history |
| **Results** | cracked table + CSV / TXT / **client HTML report** download |

REST API (`/api/v1/...`, OpenAPI spec at `/static/openapi.yaml`) drives the
same worker — wire it into your own dashboards:

```bash
curl -s localhost:5000/api/v1/status | jq .
curl -X POST localhost:5000/api/v1/jobs -d '{"action":"start"}'
```

## 📊 Benchmarks

Run `wicrack bench` and [open a PR](CONTRIBUTING.md) to add your hardware —

| Hardware | Engine | WPA speed | Reporter |
|----------|--------|----------:|----------|
| *(be the first — PR your result!)* | | | |

## 🧪 Development

```bash
make dev      # venv + editable install + dev tools
make test     # pytest with coverage   (66 tests)
make lint     # ruff check + format
make type     # mypy (pydantic plugin)
make docs     # mkdocs-material site
```

## 📁 Project layout

```
src/wicrack/
├── cli.py            # Typer CLI (serve, crack, scan, bench, report, …)
├── config.py         # pydantic-settings, validated + env-overridable
├── core/             # models, sqlite store, job queue/worker
├── capture/          # hcxpcapngtool wrapper, 22000 parser, SAE detect
├── engines/          # hashcat + john backends, selector, benchmark
├── stages/           # the 12-stage pipeline (plugin-friendly classes)
├── web/              # Flask console: templates, WebSocket, REST API
├── reporting/        # HTML report, evidence export, text log
├── notify/           # Telegram / Discord
└── vault.py          # Fernet-encrypted results archive
```

## 📚 Documentation

Full docs live at **[ch-farhan107.github.io/WiCrackAgent](https://ch-farhan107.github.io/WiCrackAgent/)**
([source](docs/)): quickstart, web console guide, CLI reference, engine
internals, and the ethics/authorization checklist.

## 🤝 Contributing

PRs welcome — read [CONTRIBUTING.md](CONTRIBUTING.md) (conventional commits,
tests required, **no real captures ever**). For vulnerabilities use
[SECURITY.md](SECURITY.md).

## 🗺️ Roadmap

- [x] v1.0 — package, dual engine, web console, reports, tests, CI
- [ ] v1.1 — stable distributed workers, plugin API for custom stages
- [ ] v2.0 — multi-user RBAC, report templates, FastAPI migration option

## 🙏 Credits

Built on the shoulders of giants: [hashcat](https://hashcat.net/hashcat/),
[John the Ripper](https://www.openwall.com/john/),
[hcxtools](https://github.com/ZerBea/hcxtools),
[OneRuleToRuleThemAll](https://github.com/NotSoSecure/password_cracking_rules)
(NotSoSecure), and the rockyou wordlist.

## 📄 License

MIT — see [LICENSE](LICENSE). **Use it only where you are authorized.**
The authors accept no liability for misuse (see [DISCLAIMER.md](DISCLAIMER.md)).
