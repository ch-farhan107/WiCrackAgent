#!/usr/bin/env bash
# WiCrackAgent installer — Kali / Debian / Ubuntu
set -euo pipefail

BOLD="\033[1m"; GREEN="\033[0;32m"; RED="\033[0;31m"; NC="\033[0m"
info()  { echo -e "${GREEN}[+]${NC} $1"; }
err()   { echo -e "${RED}[-]${NC} $1"; }

if [[ $EUID -eq 0 ]]; then SUDO=""; else SUDO="sudo"; fi

echo -e "${BOLD}WiCrackAgent installer${NC}"

# 1. System cracking tools
if command -v apt-get >/dev/null 2>&1; then
    info "Installing system packages (hashcat, john, hcxtools, wireshark)..."
    $SUDO apt-get update -qq
    $SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        hashcat john hcxtools hashcat-utils tshark python3-pip python3-venv
else
    err "apt-get not found — install manually: hashcat, john, hcxtools, hashcat-utils, tshark"
fi

# 2. Python package
info "Installing WiCrackAgent python package..."
if [[ -f "pyproject.toml" ]]; then
    python3 -m pip install --break-system-packages -e . 2>/dev/null \
        || python3 -m pip install -e .
else
    python3 -m pip install --break-system-packages -e . 2>/dev/null \
        || python3 -m pip install git+https://github.com/ch-farhan107/WiCrackAgent.git
fi

# 3. Optional wordlist / rules download
if [[ "${1:-}" == "--with-wordlists" ]]; then
    info "Downloading rockyou.txt + OneRuleToRuleThemAll.rule (~135 MB)..."
    wicrack assets download --all || err "asset download failed — run 'wicrack assets download --all' later"
fi

info "Running self-test..."
wicrack selftest || true

echo
info "Done. Quick start:"
echo "    wicrack serve          # web console  →  http://localhost:5000"
echo "    wicrack crack -f ./wifi_captures   # CLI pipeline"
echo "    wicrack --help"
