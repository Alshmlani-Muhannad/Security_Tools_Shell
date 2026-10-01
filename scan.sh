#!/bin/bash

# Check if target argument is provided
if [ -z "$1" ]; then
    echo "[-] Error: No target specified!"
    echo "Usage: ./scan.sh <target-ip-or-domain>"
    exit 1
fi

TARGET=$1
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="results_${TARGET}_${TIMESTAMP}"

mkdir -p "$OUTPUT_DIR"

echo "=================================================="
echo " [+] Starting Automated Scans for: $TARGET"
echo " [+] Results will be saved in: $OUTPUT_DIR/"
echo "=================================================="

# 1. Nmap Fast Scan & Service Detection
if command -v nmap &> /dev/null; then
    echo "[*] Running Nmap service & port scan..."
    sudo nmap -sV -T4 -F "$TARGET" -oN "$OUTPUT_DIR/nmap_results.txt"
    echo "[+] Nmap scan completed."
else
    echo "[-] Nmap not installed, skipping..."
fi

# 2. Whois & DNS Info
if command -v whois &> /dev/null; then
    echo "[*] Gathering Whois information..."
    whois "$TARGET" > "$OUTPUT_DIR/whois_results.txt" 2>/dev/null
    echo "[+] Whois data saved."
fi

if command -v dig &> /dev/null; then
    echo "[*] Gathering DNS records..."
    dig "$TARGET" ANY +noall +answer > "$OUTPUT_DIR/dns_results.txt" 2>/dev/null
    echo "[+] DNS records saved."
fi

# 3. Gobuster Directory Brute-forcing (if target is a URL/Web server)
if command -v gobuster &> /dev/null && [ -f "wordlist.txt" ]; then
    # Check if target starts with http/https
    if [[ "$TARGET" != http* ]]; then
        URL="http://$TARGET"
    else
        URL="$TARGET"
    fi
    echo "[*] Running Gobuster directory scan on $URL..."
    gobuster dir -u "$URL" -w wordlist.txt -b 403,404 -o "$OUTPUT_DIR/gobuster_results.txt" --no-error
    echo "[+] Gobuster scan completed."
else
    echo "[-] Gobuster or wordlist.txt missing, skipping web scan..."
fi

echo "=================================================="
echo " [✓] All automated scans finished successfully!"
echo " [✓] Check the folder: $OUTPUT_DIR/ for output files."
echo "=================================================="
