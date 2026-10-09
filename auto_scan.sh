#!/bin/bash
# auto_scan.sh — modular target triage for Cloud Shell (no-root, <1MB script)
# Usage: ./auto_scan.sh -t <domain|IP|email|hash|file> [--fast] [--json] [--out DIR] [--no-apis]
# Detects type, runs CLI + free APIs, prints summary + writes log.
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
[ -f "$DIR/.env" ] && { set -a; . "$DIR/.env" 2>/dev/null; set +a; }
TARGET=""; FAST=0; JSON=0; OUT=""; NOAPIS=0
while [ $# -gt 0 ]; do case "$1" in
  -t|--target) TARGET="${2:-}"; shift 2;;
  --fast) FAST=1; shift;;
  --json) JSON=1; shift;;
  --out) OUT="${2:-}"; shift 2;;
  --no-apis) NOAPIS=1; shift;;
  -h|--help) sed -n '1,12p' "$0"; echo "Ex: ./auto_scan.sh -t example.com | -t 8.8.8.8 --fast | -t user@x.com | -t <sha256> | -t ./file.bin"; exit 0;;
  *) if [ -z "$TARGET" ]; then TARGET="$1"; shift; else echo "Unknown arg: $1"; exit 1; fi;;
esac; done
[ -z "$TARGET" ] && { echo "Usage: ./auto_scan.sh -t <target> [--fast] [--json] [--out DIR]"; exit 1; }
command -v jq >/dev/null 2>&1 || echo "[!] jq missing — JSON parsing limited (./install.sh --minimal)"
command -v curl >/dev/null 2>&1 || { echo "[!] curl required"; exit 1; }

detect_type() { # echo ip|email|hash|file|domain
  local t="$1"
  if [ -f "$t" ]; then echo file;
  elif [[ "$t" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then echo email;
  elif [[ "$t" =~ ^[0-9a-fA-F]{32}$ ]] || [[ "$t" =~ ^[0-9a-fA-F]{40}$ ]] || [[ "$t" =~ ^[0-9a-fA-F]{64}$ ]]; then echo hash;
  elif [[ "$t" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then echo ip;
  else echo domain; fi
}
TYPE=$(detect_type "$TARGET")
TS=$(date +%Y%m%d_%H%M%S)
SAFE=$(echo "$TARGET" | tr -c 'A-Za-z0-9._-' '_')
RDIR="${OUT:-$DIR/reports/scan_${SAFE}_${TS}}"
mkdir -p "$RDIR"
LOG="$RDIR/summary.txt"; JSONF="$RDIR/summary.json"
: > "$LOG"
say() { echo "$@" | tee -a "$LOG"; }
have() { command -v "$1" >/dev/null 2>&1; }
run_timeout() { if have timeout; then timeout "$@"; else shift; "$@"; fi; }
say "=============================================="
say "[+] auto_scan target : $TARGET ($TYPE) fast=$FAST"
say "[+] report dir       : $RDIR"
say "=============================================="
NMAP_OUT=""; DNS_OUT=""; WHOIS_OUT=""; WEB_OUT=""

mod_nmap() {
  have nmap || { say "[-] nmap skip (missing)"; return; }
  [ "$TYPE" = ip ] || [ "$TYPE" = domain ] || return
  say "[*] nmap connect scan (-sT, no-root)..."
  if [ "$FAST" = 1 ]; then run_timeout 120 nmap -sT -T4 -F --open "$TARGET" -oN "$RDIR/nmap.txt" >>"$LOG" 2>&1;
  else run_timeout 300 nmap -sV -sT -T4 -F "$TARGET" -oN "$RDIR/nmap.txt" >>"$LOG" 2>&1; fi
  NMAP_OUT=$(grep -E 'open|closed|filtered' "$RDIR/nmap.txt" 2>/dev/null | head -n 20)
  say "[+] nmap done -> nmap.txt"
}
mod_dns_whois() {
  [ "$TYPE" = ip ] || [ "$TYPE" = domain ] || return
  if have dig; then say "[*] dig..."; { dig "$TARGET" A AAAA MX TXT NS SOA +noall +answer; echo "---PTR---"; dig -x "$TARGET" +short; } >"$RDIR/dns.txt" 2>&1; DNS_OUT=$(head -n 10 "$RDIR/dns.txt"); say "[+] dns -> dns.txt"; fi
  if have whois; then say "[*] whois..."; run_timeout 30 whois "$TARGET" >"$RDIR/whois.txt" 2>&1; WHOIS_OUT=$(grep -iE 'registrar|org|abuse|creation|expir' "$RDIR/whois.txt" 2>/dev/null | head -n 8); say "[+] whois -> whois.txt"; fi
  if [ "$TYPE" = domain ] && have curl; then say "[*] crt.sh subdomains..."; curl -sm 20 "https://crt.sh/?q=%25.${TARGET}&output=json" 2>/dev/null | (have jq && jq -r '.[].name_value' 2>/dev/null || head -c 2000) | tr ' ' '\n' | sort -u | head -n 30 >"$RDIR/subdomains.txt" 2>&1; say "[+] subdomains -> subdomains.txt ($(wc -l <"$RDIR/subdomains.txt" 2>/dev/null) lines)"; fi
}
mod_web() {
  [ "$TYPE" = ip ] || [ "$TYPE" = domain ] || return
  local url="http://$TARGET"; [[ "$TARGET" == http* ]] && url="$TARGET"
  if have curl; then say "[*] http headers..."; curl -skSI -m 20 "$url" >"$RDIR/headers.txt" 2>&1; WEB_OUT=$(head -n 12 "$RDIR/headers.txt"); say "[+] headers -> headers.txt"; fi
  if [ "$FAST" = 0 ] && have gobuster && [ -f "$DIR/wordlist.txt" ]; then say "[*] gobuster dir..."; run_timeout 180 gobuster dir -u "$url" -w "$DIR/wordlist.txt" -b 403,404 --no-error -o "$RDIR/gobuster.txt" >>"$LOG" 2>&1; say "[+] gobuster -> gobuster.txt"; fi
}
VT_OUT=""; ABUSE_OUT=""; SHODAN_OUT=""; MB_OUT=""; GEO_OUT=""
mod_vt() {
  [ "$NOAPIS" = 1 ] && return; [ -z "${VT_API_KEY:-}" ] && { say "[..] VirusTotal skip (no VT_API_KEY)"; return; }
  [ "$TYPE" = ip ] || [ "$TYPE" = domain ] || [ "$TYPE" = hash ] || return
  local ep=""; case "$TYPE" in ip) ep="ip_addresses/$TARGET";; domain) ep="domains/$TARGET";; hash) ep="files/$TARGET";; esac
  say "[*] VirusTotal $TYPE..."
  local r; r=$(curl -sm 20 -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/$ep" 2>/dev/null); echo "$r" >"$RDIR/virustotal.json"
  VT_OUT=$(echo "$r" | (have jq && jq -c '.data.attributes.last_analysis_stats // {note:"no stats"}' 2>/dev/null || head -c 300))
  say "[+] VT -> virustotal.json stats=$VT_OUT"
}
mod_abuse() {
  [ "$NOAPIS" = 1 ] && return; [ "$TYPE" = ip ] || return; [ -z "${ABUSEIPDB_API_KEY:-}" ] && { say "[..] AbuseIPDB skip (no key)"; return; }
  say "[*] AbuseIPDB..."
  local r; r=$(curl -sm 20 -G https://api.abuseipdb.com/api/v2/check --data-urlencode "ipAddress=$TARGET" -d maxAgeInDays=90 -H "Key: $ABUSEIPDB_API_KEY" -H "Accept: application/json" 2>/dev/null); echo "$r" >"$RDIR/abuseipdb.json"
  ABUSE_OUT=$(echo "$r" | (have jq && jq -c '{abuseConfidenceScore, totalReports, countryCode} // .' 2>/dev/null | head -c 300 || head -c 300))
  say "[+] AbuseIPDB -> abuseipdb.json $ABUSE_OUT"
}
mod_shodan_geo() {
  [ "$TYPE" = ip ] || return
  if [ "$NOAPIS" = 0 ] && [ -n "${SHODAN_API_KEY:-}" ]; then say "[*] Shodan..."; curl -sm 20 "https://api.shodan.io/shodan/host/$TARGET?key=$SHODAN_API_KEY" 2>/dev/null >"$RDIR/shodan.json"; SHODAN_OUT=$(have jq && jq -c '{ports, vulns} // .' "$RDIR/shodan.json" 2>/dev/null | head -c 300 || head -c 200 "$RDIR/shodan.json"); say "[+] Shodan -> shodan.json $SHODAN_OUT"; fi
  if have curl; then say "[*] ipinfo geo (no key)..."; curl -sm 15 "https://ipinfo.io/$TARGET/json" 2>/dev/null >"$RDIR/geo.json"; GEO_OUT=$(have jq && jq -c '{city, region, country, org} // .' "$RDIR/geo.json" 2>/dev/null | head -c 200 || head -c 200 "$RDIR/geo.json"); say "[+] geo -> geo.json $GEO_OUT"; fi
}
mod_email_hash() {
  if [ "$TYPE" = email ]; then
    local dom="${TARGET#*@}"
    say "[*] email: domain MX/DMARC..."
    { echo "MX:"; have dig && dig "$dom" MX +short; echo "DMARC:"; have dig && dig "_dmarc.$dom" TXT +short; } >"$RDIR/email.txt" 2>&1
    say "[+] email -> email.txt (HIBP needs key — see cheatsheet)"
  fi
  if [ "$TYPE" = hash ] && [ "$NOAPIS" = 0 ] && have curl; then
    say "[*] MalwareBazaar (no key)..."; curl -sm 20 -d "{\"query\":\"get_info\",\"hash\":\"$TARGET\"}" https://mb-api.abuse.ch/api/v1/ 2>/dev/null >"$RDIR/malwarebazaar.json"
    MB_OUT=$(have jq && jq -c '{query_status, data: (.data[]? | {signature, file_type})}' "$RDIR/malwarebazaar.json" 2>/dev/null | head -c 300 || head -c 200 "$RDIR/malwarebazaar.json"); say "[+] MB -> malwarebazaar.json $MB_OUT"
  fi
  if [ "$TYPE" = file ]; then
    say "[*] file triage..."; { md5sum "$TARGET"; sha1sum "$TARGET"; sha256sum "$TARGET"; file "$TARGET"; } >"$RDIR/file.txt" 2>&1; say "[+] file -> file.txt"
  fi
}

mod_nmap; mod_dns_whois; mod_web; mod_vt; mod_abuse; mod_shodan_geo; mod_email_hash
say ""
say "==================== SUMMARY ===================="
say "target : $TARGET ($TYPE)"
[ -n "$NMAP_OUT" ] && say "--- nmap (top) ---" && echo "$NMAP_OUT" | tee -a "$LOG" | head -n 20
[ -n "$DNS_OUT" ] && say "--- dns (top) ---" && echo "$DNS_OUT" | tee -a "$LOG" | head -n 10
[ -n "$WHOIS_OUT" ] && say "--- whois (top) ---" && echo "$WHOIS_OUT" | tee -a "$LOG" | head -n 8
[ -n "$WEB_OUT" ] && say "--- http (top) ---" && echo "$WEB_OUT" | tee -a "$LOG" | head -n 12
[ -n "$VT_OUT" ] && say "VT stats : $VT_OUT" | tee -a "$LOG"
[ -n "$ABUSE_OUT" ] && say "AbuseIPDB: $ABUSE_OUT" | tee -a "$LOG"
[ -n "$SHODAN_OUT" ] && say "Shodan  : $SHODAN_OUT" | tee -a "$LOG"
[ -n "$GEO_OUT" ] && say "Geo     : $GEO_OUT" | tee -a "$LOG"
[ -n "$MB_OUT" ] && say "MalwareBazaar: $MB_OUT" | tee -a "$LOG"
say "reports : $RDIR/ (summary.txt + raw files)"
say "================================================="
if [ "$JSON" = 1 ]; then
  if have jq; then jq -n --arg t "$TARGET" --arg ty "$TYPE" --arg dir "$RDIR" --arg vt "$VT_OUT" --arg abuse "$ABUSE_OUT" --arg shodan "$SHODAN_OUT" --arg geo "$GEO_OUT" '{target:$t,type:$ty,report_dir:$dir,virustotal:$vt,abuseipdb:$abuse,shodan:$shodan,geo:$geo}' >"$JSONF"; say "[+] json -> $JSONF"; else echo "{\"target\":\"$TARGET\",\"type\":\"$TYPE\"}" >"$JSONF"; fi
fi
ls -lh "$RDIR" | tee -a "$LOG" >/dev/null
echo "[✓] Done. Log: $RDIR/summary.txt"

