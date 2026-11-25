# Web console

Start it with `wicrack serve`. The console binds to `0.0.0.0:5000` by default
— keep it on a management network or an SSH tunnel, never the public internet.

## Tabs

| Tab | Purpose |
|-----|---------|
| **Dashboard** | WebSocket live status: speed chart, current stage, queue, counters |
| **Upload** | drag-and-drop `.cap/.pcap/.pcapng` (size limit configurable) |
| **Settings** | wordlists, stage toggles, heavy window, notifications, filters, password |
| **Jobs** | START (queue every uploaded capture) / STOP (kill + cancel queue) |
| **Results** | cracked table + CSV / TXT / client HTML report downloads |

## Live updates

The dashboard opens a WebSocket (`/ws`) and receives a status snapshot every
second. If WebSockets are unavailable (proxy, old browser) it degrades
automatically to 3-second polling of `/api/v1/status`.

## Authentication

- On first run a **random password is generated** and printed to the terminal;
  it is stored (with the session secret) in `data/web_state.json` (mode 0600).
- Change it under *Settings → Security* — persisted across restarts.
- Sessions are HttpOnly cookies with `SameSite=Lax`.

## Console vs CLI behaviour

Heavy stages need a decision the browser cannot make interactively. In web
mode they are **skipped** unless *Auto-approve heavy* is on. Use the CLI when
you want prompts.
