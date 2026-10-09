#!/bin/bash
# setup_apis.sh — configure free API keys (non-root, writes .env, never commits it)
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
ENVF="$DIR/.env"
touch "$ENVF"; chmod 600 "$ENVF"
grep -q '^\.env$' "$DIR/.gitignore" 2>/dev/null || echo ".env" >> "$DIR/.gitignore"

upsert() { # upsert KEY value file
  local k="$1" v="$2"
  grep -q "^${k}=" "$ENVF" 2>/dev/null && sed -i "s|^${k}=.*|${k}=\"${v}\"|" "$ENVF" || echo "${k}=\"${v}\"" >> "$ENVF"
}
ask() { # ask KEY "prompt" -> saves if non-empty
  local k="$1" p="$2" cur="" val=""
  cur=$(grep "^${k}=" "$ENVF" 2>/dev/null | cut -d= -f2- | tr -d '"')
  [ -n "$cur" ] && echo "[*] $k already set (${cur:0:4}****)"
  read -rp "$p (Enter to keep/skip): " val
  [ -n "$val" ] && { upsert "$k" "$val"; echo "[+] $k saved"; }
}
echo "=== Free API setup (all optional, free tiers) ==="
echo " 1) VirusTotal: https://www.virustotal.com/gui/my-apikey (4 req/min free)"
echo " 2) AbuseIPDB : https://www.abuseipdb.com/account/api (1000/day free)"
echo " 3) Shodan    : https://account.shodan.io (free = 100 lookups/mo)"
ask VT_API_KEY "VirusTotal API key"
ask ABUSEIPDB_API_KEY "AbuseIPDB API key"
ask SHODAN_API_KEY "Shodan API key"
echo "[+] Done. Keys in .env (chmod 600, gitignored). Test: source ./shell_init.sh && ./shell_init.sh --check"
