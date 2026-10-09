# COMMANDS CHEAT SHEET — Security & Network 🛡️
> Cloud-Shell friendly. Copy-paste ready. `source ./shell_init.sh` loads helpers.

Legend: `TARGET` = IP/domain, `URL` = http(s)://host, `WL` = wordlist.txt

## 0. Toolkit helpers (this repo)
```bash
source ./shell_init.sh
./shell_init.sh --check
cheat
./auto_scan.sh -t example.com
./auto_scan.sh -t 8.8.8.8 --fast
./auto_scan.sh -t user@dom.com --json
./install.sh --minimal
./install.sh --full
./setup_apis.sh
```

## 1. Nmap (no-root safe — always use -sT on Cloud Shell)
```bash
nmap -sT -T4 -F --open TARGET
nmap -sT -T4 -p- --open --min-rate 500 TARGET
nmap -sV -sT -T4 -F TARGET
nmap -sV -sT -T4 -p 80,443,22,25,53,3306 TARGET
nmap -Pn -sT -T4 -F TARGET
nmap -p 80,443 --script http-title,http-headers TARGET
nmap -oN reports/nmap_TARGET.txt -sT -T4 -F TARGET
```

## 2. Gobuster
```bash
gobuster dir -u http://TARGET -w wordlist.txt -b 403,404 --no-error
gobuster dir -u https://TARGET -w wordlist.txt -t 30 -b 400,403,404 -o reports/gobuster.txt
gobuster dns -d example.com -w wordlist.txt -t 30
gobuster vhost -u http://TARGET -w wordlist.txt --append-domain
```

## 3. FFUF (via ./install.sh --full)
```bash
ffuf -u http://TARGET/FUZZ -w wordlist.txt -mc 200,301,302 -fc 403,404 -t 40
ffuf -u http://TARGET/FUZZ -w wordlist.txt -mc 200 -o reports/ffuf.json -of json
ffuf -u http://TARGET/?id=FUZZ -w wordlist.txt -mc 200 -fs 1234
```

## 4. DNS — dig / host / nslookup
```bash
dig example.com +short
dig example.com A AAAA MX TXT NS SOA +noall +answer
dig -x 8.8.8.8 +short
dig @8.8.8.8 example.com +short
host example.com
host 8.8.8.8
nslookup example.com
dig axfr example.com @ns1.example.com
```

## 5. Whois / RDAP / ASN
```bash
whois example.com | head -n 60
whois 8.8.8.8 | grep -iE 'org|abuse|route|cidr|netname'
curl -s https://rdap.org/ip/8.8.8.8 | jq .
curl -s https://ipinfo.io/8.8.8.8/json | jq .
curl -s https://ipapi.co/8.8.8.8/json/ | jq .
```

## 6. HTTP / TLS
```bash
curl -sSI http://TARGET | head -n 30
curl -sS http://TARGET -o /dev/null -w '%{http_code} %{size_download} %{time_total}s\n'
curl -sS -L -A 'Mozilla/5.0' http://TARGET | head -n 50
echo | openssl s_client -connect TARGET:443 -servername TARGET 2>/dev/null | openssl x509 -noout -dates -issuer -subject
curl -s 'https://crt.sh/?q=%25.example.com&output=json' | jq -r '.[].name_value' | sort -u | head
wget -qO- http://TARGET/robots.txt
curl -s http://TARGET/.git/HEAD
```

## 7. Sockets / quick net (Cloud Shell safe)
```bash
ss -tulpn | head -n 30
ip -brief addr; ip route
ping -c 3 TARGET
tracepath TARGET
```

## 8. Hash / file triage
```bash
md5sum file.bin; sha1sum file.bin; sha256sum file.bin
file file.bin
strings -n 8 file.bin | head -n 40
curl -s -H "x-apikey: $VT_API_KEY" https://www.virustotal.com/api/v3/files/SHA256 | jq .data.attributes.last_analysis_stats
curl -s -d '{"query":"get_info","hash":"SHA256"}' https://mb-api.abuse.ch/api/v1/ | jq .
```

## 9. Free-API one-liners (keys via ./setup_apis.sh)
```bash
curl -s -H "x-apikey: $VT_API_KEY" https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8 | jq .data.attributes.last_analysis_stats
curl -sG https://api.abuseipdb.com/api/v2/check --data-urlencode "ipAddress=8.8.8.8" -d maxAgeInDays=90 -H "Key: $ABUSEIPDB_API_KEY" -H "Accept: application/json" | jq .
curl -s https://api.shodan.io/shodan/host/8.8.8.8?key=$SHODAN_API_KEY | jq '{ip_str, ports, vulns}'
curl -s "https://urlscan.io/api/v1/search/?q=domain:example.com" | jq '.results[0]'
dig example.com MX +short; dig _dmarc.example.com TXT +short
```

## 10. Combos
```bash
curl -s 'https://crt.sh/?q=%25.example.com&output=json' | jq -r '.[].name_value' | sort -u | head -n 50
curl -sSI https://TARGET | grep -iE 'server|strict|content-security|frame|x-'
while read p; do code=$(curl -sk -o /dev/null -w '%{http_code}' "http://TARGET/$p"); [ "$code" = 200 ] && echo "200 /$p"; done < wordlist.txt | head -n 20
```

## 11. Cloud Shell survival (<1GB rule)
```bash
df -h ~; du -sh . reports/ 2>/dev/null
./shell_init.sh --check
./install.sh --minimal
./install.sh --check-only
grep -q shell_init.sh ~/.bashrc || echo "source ~/Security_Tools_Shell/shell_init.sh" >> ~/.bashrc
```

