#!/bin/bash
# auto_scan.sh — modular target triage for Cloud Shell (no-root, <1MB script)
# Usage: ./auto_scan.sh -t <domain|IP|email|hash|file> [--fast] [--json] [--out DIR] [--no-apis] [--no-html] [--build-index]
# Detects type, runs CLI + free APIs, prints summary + writes log.
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
[ -f "$DIR/.env" ] && { set -a; . "$DIR/.env" 2>/dev/null; set +a; }
TARGET=""; FAST=0; JSON=0; OUT=""; NOAPIS=0; NOHTML=0; BUILD_INDEX_ONLY=0
while [ $# -gt 0 ]; do case "$1" in
  -t|--target) TARGET="${2:-}"; shift 2;;
  --fast) FAST=1; shift;;
  --json) JSON=1; shift;;
  --out) OUT="${2:-}"; shift 2;;
  --no-apis) NOAPIS=1; shift;;
  --no-html) NOHTML=1; shift;;
  --build-index) BUILD_INDEX_ONLY=1; shift;;
  -h|--help) sed -n '1,12p' "$0"; echo "Ex: ./auto_scan.sh -t example.com | -t 8.8.8.8 --fast | -t user@x.com | -t <sha256> | -t ./file.bin"; echo "  ./auto_scan.sh --build-index   rebuild reports/index.html dashboard"; exit 0;;
  *) if [ -z "$TARGET" ]; then TARGET="$1"; shift; else echo "Unknown arg: $1"; exit 1; fi;;
esac; done
[ -z "$TARGET" ] && [ "$BUILD_INDEX_ONLY" = 0 ] && { echo "Usage: ./auto_scan.sh -t <target> [--fast] [--json] [--out DIR] [--no-apis] [--no-html] | --build-index"; exit 1; }
# NOTE: build_index + html helpers are defined further below (pure Bash, no deps).
# In --build-index mode skip all scan setup/side effects (dispatch is after fn defs).
if [ "$BUILD_INDEX_ONLY" = 0 ]; then
command -v jq >/dev/null 2>&1 || echo "[!] jq missing — JSON parsing limited (./install.sh --minimal)"
command -v curl >/dev/null 2>&1 || { echo "[!] curl required"; exit 1; }
fi

detect_type() { # echo ip|email|hash|file|domain
  local t="$1"
  if [ -f "$t" ]; then echo file;
  elif [[ "$t" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then echo email;
  elif [[ "$t" =~ ^[0-9a-fA-F]{32}$ ]] || [[ "$t" =~ ^[0-9a-fA-F]{40}$ ]] || [[ "$t" =~ ^[0-9a-fA-F]{64}$ ]]; then echo hash;
  elif [[ "$t" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then echo ip;
  else echo domain; fi
}
if [ "$BUILD_INDEX_ONLY" = 0 ]; then
TYPE=$(detect_type "$TARGET")
TS=$(date +%Y%m%d_%H%M%S)
SAFE=$(echo "$TARGET" | tr -c 'A-Za-z0-9._-' '_')
RDIR="${OUT:-$DIR/reports/scan_${SAFE}_${TS}}"
mkdir -p "$RDIR"
LOG="$RDIR/summary.txt"; JSONF="$RDIR/summary.json"
: > "$LOG"
HTML="$RDIR/report.html"
fi
say() { if [ "$BUILD_INDEX_ONLY" = 1 ]; then echo "$@"; else echo "$@" | tee -a "$LOG"; fi; }
have() { command -v "$1" >/dev/null 2>&1; }
run_timeout() { if have timeout; then timeout "$@"; else shift; "$@"; fi; }
if [ "$BUILD_INDEX_ONLY" = 0 ]; then
say "=============================================="
say "[+] auto_scan target : $TARGET ($TYPE) fast=$FAST"
say "[+] report dir       : $RDIR"
say "=============================================="
fi
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

# ---------- HTML report engine (pure Bash, standalone, dark mode) ----------
html_escape() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'; }
badge_state() {
  case "$(echo "$1" | tr 'A-Z' 'a-z')" in
    *open*) echo '<span class="badge b-open">OPEN</span>' ;;
    *filtered*) echo '<span class="badge b-warn">FILTERED</span>' ;;
    *closed*) echo '<span class="badge b-gray">CLOSED</span>' ;;
    *) echo '<span class="badge b-gray">N/A</span>' ;;
  esac
}
render_pre() { # render_pre FILE MAXLINES
  if [ -f "$1" ] && [ -s "$1" ]; then head -n "${2:-60}" "$1" | head -c 8192 | html_escape;
  else echo "<i>not collected</i>"; fi
}
render_pills() { # render_pills FILE MAX
  if [ -f "$1" ] && [ -s "$1" ]; then head -n "${2:-50}" "$1" | html_escape | sed 's/^/<li>/;s/$/<\/li>/';
  else echo "<li><i>none</i></li>"; fi
}
render_nmap_rows() {
  if [ -f "$RDIR/nmap.txt" ] && grep -qE '^[0-9]+/tcp' "$RDIR/nmap.txt" 2>/dev/null; then
    grep -E '^[0-9]+/tcp' "$RDIR/nmap.txt" | head -n 50 | while read -r port state svc rest; do
      p=$(echo "$port" | html_escape); s=$(echo "$state" | html_escape)
      v=$(echo "$svc $rest" | head -c 120 | html_escape)
      echo "<tr><td><code>$p</code></td><td>$(badge_state "$state") <small>$s</small></td><td>$v</td></tr>"
    done
  else echo '<tr><td colspan="3"><i>nmap data not available (skipped or host unreachable) — see nmap.txt</i></td></tr>'; fi
}
mod_badge() { # mod_badge VAR_NAME label -> green if non-empty else gray
  local v="${!1:-}"; if [ -n "$v" ]; then echo "<span class=\"badge b-open\">$2 ●</span>"; else echo "<span class=\"badge b-gray\">$2 ○</span>"; fi
}
build_report_html() {
  [ "$NOHTML" = 1 ] && return 0
  local ET GT SUBN VT_BADGE ABUSE_BADGE ASCORE
  ET=$(echo "$TARGET" | html_escape); GT=$(date -u '+%Y-%m-%d %H:%M UTC')
  SUBN=0; [ -f "$RDIR/subdomains.txt" ] && SUBN=$(wc -l <"$RDIR/subdomains.txt" 2>/dev/null || echo 0)
  VT_BADGE='<span class="badge b-gray">VT ○</span>'
  if [ -n "${VT_OUT:-}" ]; then
    if echo "$VT_OUT" | grep -qE '"malicious":[1-9]'; then VT_BADGE='<span class="badge b-red">VT MALICIOUS</span>';
    else VT_BADGE='<span class="badge b-open">VT ●</span>'; fi
  fi
  ABUSE_BADGE='<span class="badge b-gray">AbuseIPDB ○</span>'
  if [ -n "${ABUSE_OUT:-}" ]; then
    ASCORE=$(echo "$ABUSE_OUT" | grep -oE '[0-9]+' | head -n1); ASCORE=${ASCORE:-0}
    if [ "$ASCORE" -ge 50 ] 2>/dev/null; then ABUSE_BADGE="<span class=\"badge b-red\">AbuseIPDB $ASCORE</span>";
    else ABUSE_BADGE="<span class=\"badge b-open\">AbuseIPDB $ASCORE</span>"; fi
  fi
  {
  echo '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
  echo "<title>Scan Report — $ET</title>"
  echo '<style>:root{--bg:#0f172a;--card:#1e293b;--line:#334155;--txt:#e2e8f0;--mut:#94a3b8;--acc:#22d3ee}'
  echo '*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);font:14px/1.55 system-ui,sans-serif;padding:20px}'
  echo '.wrap{max-width:1000px;margin:auto}h1{font-size:20px;margin:0}h2{font-size:14px;color:var(--acc);margin:22px 0 8px;text-transform:uppercase;letter-spacing:.06em}'
  echo '.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin:8px 0}'
  echo '.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:10px}'
  echo '.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:700;margin:2px}'
  echo '.b-open{background:rgba(34,197,94,.18);color:#4ade80;border:1px solid #22c55e}.b-warn{background:rgba(245,158,11,.15);color:#fbbf24;border:1px solid #f59e0b}.b-gray{background:rgba(100,116,139,.15);color:#94a3b8;border:1px solid #64748b}.b-red{background:rgba(239,68,68,.15);color:#f87171;border:1px solid #ef4444}'
  echo 'table{width:100%;border-collapse:collapse;background:var(--card);border-radius:10px;overflow:hidden}th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{background:#0b1226;color:var(--acc);font-size:12px;text-transform:uppercase}'
  echo 'pre{background:#0b1226;border:1px solid var(--line);border-radius:8px;padding:10px;overflow:auto;max-height:320px;white-space:pre-wrap;word-break:break-all}'
  echo 'code{color:var(--acc)}.pills{list-style:none;padding:0;display:flex;flex-wrap:wrap;gap:6px}.pills li{background:#0b1226;border:1px solid var(--line);border-radius:999px;padding:2px 12px;font-size:12px}'
  echo 'a{color:var(--acc)}.mut{color:var(--mut)}details{margin:6px 0}summary{cursor:pointer;color:var(--acc)}.cols{display:grid;grid-template-columns:1fr 1fr;gap:10px}@media(max-width:700px){.cols{grid-template-columns:1fr}}footer{margin-top:24px;color:var(--mut);font-size:12px}</style></head>'
  echo '<body><div class="wrap">'
  echo "<h1>🛡️ Scan Report — <code>$ET</code> <a href=\"../index.html\" style=\"font-size:12px\">← all reports</a></h1>"
  echo '<div class="card grid">'
  echo "<div><b>Target</b><br><code>$ET</code></div><div><b>Type</b><br><span class=\"badge b-open\">$TYPE</span></div>"
  echo "<div><b>Timestamp</b><br>$GT</div><div><b>Flags</b><br><span class=\"mut\">fast=$FAST no-apis=$NOAPIS</span></div></div>"
  echo "<div>$(mod_badge NMAP_OUT NMAP) $(mod_badge DNS_OUT DNS) $(mod_badge WEB_OUT HTTP) $VT_BADGE $ABUSE_BADGE $(mod_badge SHODAN_OUT Shodan) $(mod_badge GEO_OUT Geo)</div>"
  echo '<h2>1 · Nmap — ports &amp; services</h2><table><tr><th>Port</th><th>State</th><th>Service / Version</th></tr>'
  render_nmap_rows
  echo '</table><details><summary>raw nmap.txt</summary><pre>'; render_pre "$RDIR/nmap.txt" 60; echo '</pre></details>'
  echo "<h2>2 · DNS &amp; subdomains ($SUBN)</h2><div class=\"cols\"><div class=\"card\"><b>dns.txt</b><pre>"; render_pre "$RDIR/dns.txt" 30
  echo '</pre><details><summary>whois (top)</summary><pre>'; render_pre "$RDIR/whois.txt" 25; echo '</pre></details></div>'
  echo '<div class="card"><b>subdomains</b><ul class="pills">'; render_pills "$RDIR/subdomains.txt" 50; echo '</ul></div></div>'
  echo '<h2>3 · HTTP headers &amp; TLS notes</h2><div class="card"><pre>'; render_pre "$RDIR/headers.txt" 40; echo '</pre>'
  echo '<small class="mut">Check: Server banner · HSTS · CSP · X-Frame-Options. Missing HSTS/CSP = hardening gap.</small></div>'
  echo '<h2>4 · Reputation &amp; intel</h2><div class="grid">'
  echo '<div class="card"><b>VirusTotal</b><pre>'; echo "${VT_OUT:-not queried}" | html_escape; echo '</pre></div>'
  echo '<div class="card"><b>AbuseIPDB</b><pre>'; echo "${ABUSE_OUT:-not queried}" | html_escape; echo '</pre></div>'
  echo '<div class="card"><b>Shodan</b><pre>'; echo "${SHODAN_OUT:-not queried}" | html_escape; echo '</pre></div>'
  echo '<div class="card"><b>Geo</b><pre>'; echo "${GEO_OUT:-not queried}" | html_escape; echo '</pre></div></div>'
  if [ "$TYPE" = email ] || [ "$TYPE" = file ] || [ "$TYPE" = hash ]; then
    echo '<h2>5 · Triage detail</h2><div class="card"><pre>'
    if [ "$TYPE" = email ]; then render_pre "$RDIR/email.txt" 20
    elif [ "$TYPE" = file ]; then render_pre "$RDIR/file.txt" 20
    else echo "${MB_OUT:-no MalwareBazaar data}" | html_escape; fi
    echo '</pre></div>'
  fi
  echo '<h2>Raw files</h2><div class="card mut">'; ls -1 "$RDIR" 2>/dev/null | html_escape | sed 's/^/· /'; echo '</div>'
  echo "<footer>Generated $GT by auto_scan.sh (non-root, Cloud Shell safe) · $ET ($TYPE)</footer>"
  echo '</div></body></html>'
  } > "$HTML"
  say "[+] html -> report.html"
}

build_index() {
  local IDX="$DIR/reports/index.html"; mkdir -p "$DIR/reports"; touch "$DIR/reports/.gitkeep" 2>/dev/null
  {
  echo '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Scan Reports Index</title>'
  echo '<style>:root{--bg:#0f172a;--card:#1e293b;--line:#334155;--txt:#e2e8f0;--acc:#22d3ee}'
  echo 'body{margin:0;background:var(--bg);color:var(--txt);font:14px/1.5 system-ui,sans-serif;padding:20px}.wrap{max-width:900px;margin:auto}'
  echo 'table{width:100%;border-collapse:collapse;background:var(--card);border-radius:10px;overflow:hidden}th,td{padding:9px 12px;border-bottom:1px solid var(--line);text-align:left}th{color:var(--acc);font-size:12px;text-transform:uppercase}a{color:var(--acc)}code{color:var(--acc)}</style></head>'
  echo '<body><div class="wrap"><h1>🛡️ Scan Reports</h1>'
  echo "<p>Generated $(date -u '+%Y-%m-%d %H:%M UTC') · click a report to open</p>"
  echo '<table><tr><th>Target</th><th>Timestamp</th><th>Size</th><th>Report</th></tr>'
  for r in $(ls -td "$DIR"/reports/scan_*/ 2>/dev/null); do
    [ -f "$r/report.html" ] || continue
    d=$(basename "$r"); tgt=$(echo "$d" | sed -e 's/^scan_//' -e 's/_[0-9]\{8\}_[0-9]\{6\}$//')
    ts=$(echo "$d" | grep -oE '[0-9]{8}_[0-9]{6}$' || echo '?')
    sz=$(du -sh "$r" 2>/dev/null | cut -f1)
    echo "<tr><td><code>$(echo "$tgt" | html_escape)</code></td><td>$ts</td><td>$sz</td><td><a href=\"$d/report.html\">open</a></td></tr>"
  done
  echo '</table><p><code>./auto_scan.sh --build-index</code> to refresh</p></div></body></html>'
  } > "$IDX"
  echo "[+] index -> reports/index.html"
}
# --build-index standalone (no target needed)
if [ "$BUILD_INDEX_ONLY" = 1 ]; then build_index; exit 0; fi

mod_nmap; mod_dns_whois; mod_web; mod_vt; mod_abuse; mod_shodan_geo; mod_email_hash; build_report_html
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
build_index >/dev/null 2>&1 || true
echo "[✓] Done. Log: $RDIR/summary.txt | HTML: $RDIR/report.html"

