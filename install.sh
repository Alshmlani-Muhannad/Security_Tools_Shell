#!/bin/bash
# install.sh --minimal (default, <150MB) | --full (+ffuf/tshark) | --check-only
# Cloud Shell safe: tries sudo, falls back to user-space; never runs apt upgrade.
set -u
MODE="${1:- --minimal}"
SUDO=""; command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null && SUDO="sudo"
need() { command -v "$1" >/dev/null 2>&1; }
install_apt() { if [ -n "$SUDO" ]; then $SUDO apt-get update -qq && $SUDO apt-get install -y --no-install-recommends "$@"; else echo "[!] no sudo; apt skipped: $*"; fi; }
install_dnf() { if [ -n "$SUDO" ]; then $SUDO dnf install -y "$@" 2>/dev/null || echo "[!] dnf skipped: $*"; else echo "[!] no sudo; dnf skipped: $*"; fi; }
MIN_APT="nmap gobuster dnsutils whois curl wget git jq python3-pip iproute2 iputils-ping" 
MIN_DNF="nmap bind-utils whois wget git jq python3-pip iproute iputils"
FULL_APT="ffuf tshark"; FULL_DNF="gobuster tshark ffuf"
case "$MODE" in --check-only) echo "== check-only =="; for t in nmap gobuster ffuf dig host whois curl wget jq python3 ss go pipx; do need $t && echo "[OK] $t" || echo "[..] $t"; done; du -sh .; exit 0;; --full) FULL=1;; *) FULL=0;; esac
echo "== install $MODE (sudo: ${SUDO:-none}) =="
if need apt-get; then install_apt $MIN_APT; [ "$FULL" = 1 ] && install_apt $FULL_APT || true
elif need dnf; then install_dnf $MIN_DNF; [ "$FULL" = 1 ] && install_dnf $FULL_DNF || true
elif need yum; then echo "[!] yum legacy; trying dnf path"; [ -n "$SUDO" ] && $SUDO yum install -y nmap bind-utils whois wget git jq python3-pip || true
else echo "[!] no apt/dnf/yum; user-space only"; fi
# user-space Go tools (no root needed) if gobuster/ffuf missing and go exists
if ! need gobuster && need go; then GOBIN=~/.local/bin go install github.com/OJ/gobuster/v3@latest 2>/dev/null && echo "[+] gobuster via go" || true; fi
if [ "$FULL" = 1 ] && ! need ffuf && need go; then GOBIN=~/.local/bin go install github.com/ffuf/ffuf/v2@latest 2>/dev/null && echo "[+] ffuf via go" || true; fi
# pipx / user pip helpers (httprobe style, tiny)
[ -f wordlist.txt ] || echo "[!] wordlist.txt missing (repo should include it)"
chmod +x auto_scan.sh shell_init.sh setup_apis.sh scan.sh 2>/dev/null || true
mkdir -p reports; echo "== done =="; ./shell_init.sh --check 2>/dev/null || true
