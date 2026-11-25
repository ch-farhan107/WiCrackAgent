"""Standalone client-ready HTML pentest report (print-friendly, no deps)."""

from __future__ import annotations

import html
import time
from pathlib import Path

from loguru import logger

from wicrack import __version__
from wicrack.core.store import Store
from wicrack.stages.pipeline import PIPELINE

_CSS = """
body{font-family:Georgia,'Times New Roman',serif;color:#1a1a1a;margin:0;background:#f6f6f4}
.page{max-width:900px;margin:0 auto;background:#fff;padding:48px 56px;min-height:100vh}
h1{font-size:1.9em;border-bottom:3px solid #111;padding-bottom:10px;margin:0 0 6px}
h2{font-size:1.25em;margin:34px 0 10px;border-bottom:1px solid #ddd;padding-bottom:6px}
.sub{color:#555;font-size:.9em;margin-bottom:26px}
table{border-collapse:collapse;width:100%;font-size:.85em;margin:12px 0}
th{background:#111;color:#fff;text-align:left;padding:8px 10px}
td{border-bottom:1px solid #e4e4e4;padding:7px 10px;vertical-align:top}
.key{font-family:'Courier New',monospace;font-weight:bold;background:#fffbe8}
.kpi{display:flex;gap:18px;flex-wrap:wrap;margin:14px 0}
.kpi div{border:1px solid #ddd;border-radius:6px;padding:12px 20px;
         min-width:120px;text-align:center}
.kpi b{display:block;font-size:1.5em}
.badge{display:inline-block;background:#111;color:#fff;border-radius:4px;
       padding:2px 10px;font-size:.75em;letter-spacing:.5px}
.warn{background:#fff4f4;border-left:4px solid #c0392b;padding:10px 14px;
      font-size:.9em;margin:12px 0}
.note{color:#555;font-size:.85em}
ul{line-height:1.55}
footer{margin-top:40px;border-top:1px solid #ddd;padding-top:12px;color:#777;font-size:.8em}
@media print{.page{padding:24px}}
"""


def _esc(value: object) -> str:
    return html.escape(str(value if value is not None else ""))


def _recommendations() -> str:
    return """
<ul>
  <li><b>Move to WPA3-SAE</b> (or WPA2/WPA3 transition mode) — SAE resists
      offline dictionary attacks against captured handshakes.</li>
  <li><b>Enable Protected Management Frames (802.11w / PMF)</b> to block
      deauthentication-based handshake capture.</li>
  <li><b>Enforce long passphrases (&ge; 16 characters)</b> — every recovered
      key was shorter than the entropy a passphrase manager provides.</li>
  <li><b>Prefer WPA2/WPA3-Enterprise (802.1X)</b> for corporate networks;
      pre-shared keys leak to every user and to this attack.</li>
  <li><b>Rotate any recovered PSK immediately</b> and audit connected clients.</li>
  <li><b>Monitor for deauth floods and rogue APs</b> with a WIDS/WIPS or a
      periodic WiCrackAgent assessment.</li>
</ul>"""


def generate_html_report(
    store: Store,
    settings,
    out_path: Path,
    *,
    engagement: str = "",
    operator: str = "authorized assessor",
) -> Path:
    """Build the standalone report; returns the written path."""
    rows = store.all_results()
    analytics = store.analytics() or {}
    engine = settings.engine
    stage_names = " → ".join(s.id for s in PIPELINE)
    now = time.strftime("%Y-%m-%d %H:%M:%S")

    kpi = "".join(
        f"<div><b>{_esc(v)}</b>{_esc(k)}</div>"
        for k, v in [
            ("Keys recovered", analytics.get("total", len(rows))),
            ("Avg length", analytics.get("avg_len", "-")),
            ("Space-containing", analytics.get("with_space", 0)),
            ("Digit-only", analytics.get("only_digits", 0)),
        ]
    )

    body_rows = (
        "".join(
            f"<tr><td>{_esc(r['ts'])}</td><td>{_esc(r['essid'])}</td>"
            f"<td>{_esc(r['bssid'])}</td><td>{_esc(r['mode'])}</td>"
            f"<td class='key'>{_esc(r['key'])}</td><td>{r['key_len']}</td>"
            f"<td>{_esc(r['stage'])}</td></tr>"
            for r in rows
        )
        or "<tr><td colspan='7'>No keys recovered during this assessment.</td></tr>"
    )

    doc = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Wireless Security Assessment Report</title><style>{_CSS}</style></head>
<body><div class="page">
<span class="badge">CONFIDENTIAL — AUTHORIZED ENGAGEMENT</span>
<h1>Wireless Security Assessment Report</h1>
<div class="sub">Generated {now} &middot; WiCrackAgent v{__version__}
&middot; Operator: {_esc(operator)}
{("&middot; Engagement: " + _esc(engagement)) if engagement else ""}</div>

<h2>1. Executive summary</h2>
<p>This report presents the results of an <b>authorized</b> wireless
security assessment performed with WiCrackAgent v{__version__}. The assessment
captured WPA2 pre-shared-key handshakes/PMKIDs and subjected them to a
staged, dictionary-and-rule based offline attack using the
<b>{_esc(engine)}</b> engine. A total of
<b>{len(rows)}</b> credential(s) were recovered, demonstrating that the
current authentication posture can be compromised with commodity hardware.</p>
<div class="kpi">{kpi}</div>

<h2>2. Scope &amp; methodology</h2>
<table>
<tr><th>Capture analysis</th><td>hcxpcapngtool &rarr; hashcat 22000 format
    (PMKID + EAPOL)</td></tr>
<tr><th>Attack pipeline</th><td>{_esc(stage_names)}</td></tr>
<tr><th>Adaptive stage</th><td>H — masks learned from keys recovered in this
    engagement</td></tr>
<tr><th>Space-aware attacks</th><td>Rules targeting passphrases containing
    spaces (Stage C)</td></tr></table>

<h2>3. Findings — recovered credentials</h2>
<table>
<tr><th>Time</th><th>ESSID</th><th>BSSID</th><th>Mode</th><th>Recovered key</th>
    <th>Len</th><th>Stage</th></tr>
{body_rows}</table>
<div class="warn">Every key listed above grants full network access.
Treat this document as restricted material and distribute it only to the
engagement stakeholders.</div>

<h2>4. Remediation recommendations</h2>
{_recommendations()}

<h2>5. Appendix — audit trail</h2>
<p class="note">Full per-run history, raw capture hashes and SHA-256 evidence
records are available via <code>wicrack vault export</code> and
<code>wicrack report --evidence</code>. This report contains no client data
beyond what the assessment produced.</p>

<footer>WiCrackAgent v{__version__} — automated wireless security assessment.
Authorized use only; misuse may constitute a criminal offence.</footer>
</div></body></html>"""

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(doc, encoding="utf-8")
    logger.success("HTML report written: {}", out_path)
    return out_path
