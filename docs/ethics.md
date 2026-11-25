# Ethics & authorization

!!! danger "Read this before your first run"

    Cracking a WPA key of a network you do not own — or lack written
    authorization for — is a **criminal offence** in most jurisdictions.

## The authorization checklist

- [ ] Written authorization (SOW / ROE) signed by the network owner
- [ ] Scope documented: SSIDs, BSSIDs, time windows, locations
- [ ] Data handling agreed (where captures and recovered keys live, retention)
- [ ] Local law checked (CFAA, Computer Misuse Act, StGB §202c, IT Act, …)
- [ ] Client informed about deauthentication side effects
- [ ] Artifacts encrypted at rest (`wicrack vault`, full-disk encryption)

## Why this tool ships with reports

A pentest without a deliverable is a hobby. WiCrackAgent generates the
client-facing HTML report (executive summary, findings, remediation) and an
evidence file with SHA-256-hashed keys — so the engagement output is
defensible and the plaintext keys can stay redacted in shared copies.

## Responsible disclosure of results

Every recovered key is a finding, not a trophy: rotate it, document it,
help the owner move to WPA3-SAE / 802.1X. That is the entire point.
