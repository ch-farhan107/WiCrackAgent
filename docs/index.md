# WiCrackAgent

**Automated wireless security assessment framework** — GPU + CPU dual engine,
live web console, and client-ready pentest reports.

```bash
pip install wicrack
wicrack serve          # → http://localhost:5000
```

!!! warning "Authorized use only"
    WiCrackAgent exists for **penetration testing of networks you own or are
    contracted to assess**. Unauthorized access to computer networks is a
    criminal offence in most jurisdictions. Read [ethics](ethics.md) before
    your first run.

## What makes it different

1. **A staged, adaptive pipeline instead of a single wordlist shot.**
   Twelve ordered stages go from cheap-and-likely (ESSID as password,
   best64 rules) to expensive-and-thorough (OneRuleToRuleThemAll, phrase
   generation), with heavy stages gated behind keyspace estimates.
2. **It learns.** Stage H converts keys recovered during the engagement into
   structural masks and re-attacks with them — if the environment uses
   `Word+Year` passwords everywhere, WiCrackAgent finds that pattern itself.
3. **It finishes like a pentest, not a script.** Every run produces a
   client-ready HTML report, a tamper-evident evidence file, and an encrypted
   results vault.

## The 60-second tour

```bash
wicrack selftest                     # verify tools + end-to-end crack
wicrack serve                        # web console (upload → start → report)
wicrack crack -f ./wifi_captures     # CLI pipeline
wicrack bench                        # hardware benchmark
```

Continue with the [Quickstart](usage/quickstart.md), or jump straight to the
[Web console](usage/web.md) and [CLI reference](usage/cli.md).
