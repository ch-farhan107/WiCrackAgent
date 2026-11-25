# Quickstart

## Requirements

| Component | Purpose | Install |
|-----------|---------|---------|
| Python 3.10+ | the framework itself | distro package |
| hashcat | GPU cracking backend | `apt install hashcat` |
| hcxtools / hashcat-utils | capture conversion | `apt install hcxtools hashcat-utils` |
| John the Ripper (jumbo) | CPU backend (optional but recommended) | `apt install john` |
| tshark | WPA3/SAE detection (optional) | `apt install tshark` |

## Install

```bash
# from a clone
git clone https://github.com/ch-farhan107/WiCrackAgent.git
cd WiCrackAgent
bash install.sh --with-wordlists     # tools + rockyou + ORRTA rule

# or straight from pip (after the repo is published)
pip install wicrack
wicrack assets download --all        # wordlist + rule
```

## First run checklist

1. `wicrack selftest` — T5 proves an actual end-to-end WPA crack works.
2. `wicrack serve` — the **generated console password** appears in the
   terminal; log in at `http://localhost:5000` and change it in *Settings*.
3. Upload a capture on the **Upload** tab, press **START** on **Jobs**.

## Getting a test capture (lab only)

Assess **your own** AP in a lab: deauthenticate one of your clients with
aircrack-ng's tooling, capture the re-handshake with `airodump-ng -w lab`,
and drop the `.cap` into the console. Never capture third-party networks.

## Captures with spaces in the passphrase?

That is stage C's whole job — plain tools miss those; WiCrackAgent generates
append/prepend-space rules automatically.

## Heavy stages

Big keyspaces (dive.rule, combinator) are **estimated and gated**:
- CLI: interactive `[y/N]` prompt (or `--yes`)
- Web: skipped unless *Auto-approve heavy* is enabled in Settings
- Either: schedule with *Heavy window* (e.g. `22:00-06:00`)
