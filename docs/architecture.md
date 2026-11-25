# Architecture

```
 capture (.cap/.pcap/.pcapng)
        │
        ▼
 ┌─────────────────┐     hc22000     ┌──────────────────┐
 │ capture/        │ ───────────────►│ capture/parser   │──► targets, filter
 │ converter       │                 └──────────────────┘
 └─────────────────┘                          │
                                              ▼
 ┌────────────────────────────────────────────────────────────┐
 │ core/jobqueue.JobManager (worker thread, stop events)      │
 │   convert → parse → filter → potfile pre-check → pipeline  │
 └────────────────────────────────────────────────────────────┘
            │                              ▲
            ▼                              │ snapshots
 ┌──────────────────────┐         ┌─────────────────┐
 │ stages/pipeline      │         │ web console      │
 │ 12 Stage classes ────┼──attacks─► Flask + WS     │
 │ (AttackSpec objects) │         │ REST /api/v1     │
 └──────────────────────┘         └─────────────────┘
            │
            ▼
 ┌──────────────────────────┐
 │ engines/EngineSelector   │  GPU → hashcat · CPU → john
 │ hashcat_engine / john    │  mode 22000 / wpapsk
 └──────────────────────────┘
            │
            ▼
 potfile → core/store (SQLite) → reporting/ (HTML, evidence, vault)
```

## Key concepts

- **AttackSpec** — a declarative attack (kind, wordlist, rules, mask,
  generator). Stages *plan*; engines *execute*. Adding a new backend means
  implementing one `Engine` class.
- **Stage** — a strategy with `attacks(ctx)` and optional `enabled(ctx)`.
  The pipeline orders them, applies heavy-gates, and harvests potfiles.
- **JobManager** — single worker thread + queue, shared by CLI and web;
  every mode sees identical behaviour.
- **Store** — SQLite for results/runs; the source for reports, analytics
  and stage H's mask learning.
- **Stop semantics** — STOP terminates the current engine process and drops
  queued jobs; the potfile preserves whatever was already cracked, so a
  re-run resumes instead of repeating work.

## Web layer

Flask application factory (`create_app`) with injected engine/manager —
that is also how the test suite runs the whole console without hashcat.
Live updates ride a WebSocket with polling fallback; the REST API is a
plain blueprint documented in `src/wicrack/web/static/openapi.yaml`.
