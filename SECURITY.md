# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅        |
| < 1.0   | ❌        |

## Reporting a vulnerability

**Do not open a public issue for security problems.**

1. Use GitHub's *Report a vulnerability* button on the Security tab, **or**
2. Email the repository owner with `[WiCrackAgent] Security` in the subject.

Please include: affected version, environment, reproduction steps, and impact
assessment. You will get an acknowledgement within **72 hours** and a fix or
mitigation plan within **14 days** for confirmed issues.

## Scope

In scope: the Python package, web console (auth, uploads, session handling),
REST API, report generation, vault, and the release pipeline itself.

Out of scope: vulnerabilities in third-party engines (hashcat, John the
Ripper, hcxtools) — report those upstream; weaknesses inherent to WPA
handshake cracking are the *documented purpose* of this tool and are not
security bugs.

## Hardening notes for operators

- Change the generated web console password immediately.
- Do not expose the web console to the public internet; bind it to a
  management network or tunnel (SSH/WireGuard).
- Reports and the results database contain sensitive material — keep
  `data/` on encrypted storage and use `wicrack vault` for archival.
