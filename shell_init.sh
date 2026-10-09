#!/bin/bash
# shell_init.sh — lightweight loader + banner. Source it: source ./shell_init.sh
# Cloud Shell safe: no sudo, no heavy deps, <10KB.
TOOLKIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

# Load API keys if present (never commit .env)
if [ -f "$TOOLKIT_DIR/.env" ]; then
  set -a; . "$TOOLKIT_DIR/.env" 2>/dev/null; set +a
fi

# Aliases / helpers
alias cheat="cat \"$TOOLKIT_DIR/COMMANDS_CHEAT_SHEET.md\" 2>/dev/null | head -n 120; echo \"... full: less $TOOLKIT_DIR/COMMANDS_CHEAT_SHEET.md\""
alias scan="\"$TOOLKIT_DIR/auto_scan.sh\""
export PATH="$TOOLKIT_DIR:$PATH"

__toolkit_check() {
  echo "[*] toolkit check (Cloud Shell, no-root safe)"
  for t in nmap gobuster ffuf dig host nslookup whois curl wget jq python3 openssl ss; do
    if command -v "$t" >/dev/null 2>&1; then echo "  [OK] $t"; else echo "  [..] $t missing (./install.sh --minimal)"; fi
  done
  [ -n "${VT_API_KEY:-}" ] && echo "  [OK] VT_API_KEY set" || echo "  [..] VT_API_KEY not set (./setup_apis.sh)"
  [ -n "${ABUSEIPDB_API_KEY:-}" ] && echo "  [OK] ABUSEIPDB_API_KEY set" || echo "  [..] ABUSEIPDB_API_KEY not set"
  [ -n "${SHODAN_API_KEY:-}" ] && echo "  [OK] SHODAN_API_KEY set" || echo "  [..] SHODAN_API_KEY not set"
  du -sh "$TOOLKIT_DIR" 2>/dev/null
}

if [ "${1:-}" = "--check" ]; then __toolkit_check; return 0 2>/dev/null || exit 0; fi

# Banner — shows on every source (req #1: reminders on load)
cat <<EOF
🛡️  Security_Tools_Shell ready | Cloud Shell safe (<1GB, no-root)
  cheat ............ show cheatsheet top  |  scan -t <IP/domain/email/hash>
  ./auto_scan.sh -t example.com [--fast] [--json] [--out reports/]
  ./install.sh --minimal | ./setup_apis.sh | ./shell_init.sh --check
  nmap tip: always -sT (never -sS) here  |  keys: VT / AbuseIPDB / Shodan via .env
  docs: COMMANDS_CHEAT_SHEET.md
EOF
[ -f "$TOOLKIT_DIR/wordlist.txt" ] || echo "[!] wordlist.txt missing"
