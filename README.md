# Security_Tools_Shell 🛡️ — Cloud-Shell ready (<1GB, no-root)

Lightweight network & security toolkit for AWS CloudShell / GCP Cloud Shell.

## Load (shows banner + reminders every time)
```bash
source ./shell_init.sh
./shell_init.sh --check   # tool + API readiness
```

## Install (pick one)
```bash
./install.sh --minimal     # default, ~150MB: nmap gobuster dig whois curl jq + wordlist
./install.sh --full        # + ffuf, tshark (heavy — only if quota allows)
./install.sh --check-only  # dry run, no changes
```

## Scan (auto-detects IP / domain / email / hash / file)
```bash
./auto_scan.sh -t example.com
./auto_scan.sh -t 8.8.8.8 --fast
./auto_scan.sh -t user@example.com --json
./auto_scan.sh -t 44d88612fea8a8f36de82e1278abb02f --no-apis
./scan.sh example.com      # legacy alias → auto_scan.sh
```

## API keys (all optional free tiers)
```bash
./setup_apis.sh            # writes gitignored .env (chmod 600)
```
| API | Free tier | Get key |
|---|---|---|
| VirusTotal | 4 req/min | virustotal.com/gui/my-apikey |
| AbuseIPDB | 1000/day | abuseipdb.com/account/api |
| Shodan | 100 lookups/mo | account.shodan.io |
| No-key extras | — | crt.sh, ipinfo.io, MalwareBazaar, RDAP |

## Files
| File | Purpose |
|---|---|
| `COMMANDS_CHEAT_SHEET.md` | copy-paste commands (nmap, gobuster, ffuf, dig, curl, APIs) |
| `shell_init.sh` | banner + `cheat`/`scan` aliases, loads `.env` — source it |
| `auto_scan.sh` | modular scanner → terminal summary + `reports/` log |
| `install.sh` | non-root installer (`--minimal`/`--full`/`--check-only`) |
| `setup_apis.sh` | interactive `.env` key setup |
| `wordlist.txt` | small dir wordlist (kept tiny for quota) |
| `scan.sh` | legacy wrapper → `auto_scan.sh` |

## Constraints honored
- **<1GB** (hard max 3GB): no `apt upgrade`, `--no-install-recommends`, tshark/ffuf are opt-in only.
- **Non-root**: `-sT` nmap (never `-sS`), sudo-optional installer, Go/pip user-space fallback.
- **Persist**: `grep -q shell_init.sh ~/.bashrc || echo "source ~/Security_Tools_Shell/shell_init.sh" >> ~/.bashrc`

