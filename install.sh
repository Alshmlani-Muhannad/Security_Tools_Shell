#!/bin/bash

echo "=========================================="
echo "    Starting Security Tools Installation    "
echo "=========================================="

# Detect and use the available package manager
if command -v apt &> /dev/null; then
    echo "[+] Detected APT (Debian / Ubuntu / GCP CloudShell)"
    sudo apt update && sudo apt upgrade -y
    sudo apt install -y nmap gobuster tshark curl wget dnsutils whois net-tools git python3-pip

elif command -v dnf &> /dev/null; then
    echo "[+] Detected DNF (Fedora / RHEL / Amazon Linux / AWS CloudShell)"
    sudo dnf install -y nmap gobuster tshark curl wget bind-utils whois net-tools git python3-pip

elif command -v yum &> /dev/null; then
    echo "[+] Detected YUM (Older RedHat / CentOS)"
    sudo yum install -y nmap gobuster tshark curl wget bind-utils whois net-tools git python3-pip

else
    echo "[!] Warning: No supported package manager (apt, dnf, yum) found. Skipping package installation."
fi

echo "=========================================="
echo "    Creating Default Wordlist File...     "
echo "=========================================="

# Create the default wordlist in the current directory
cat << 'EOF' > wordlist.txt
admin
administrator
login
logon
signin
signup
register
dashboard
panel
cp
cpanel
api
v1
v2
v3
assets
css
js
images
img
uploads
upload
files
media
backup
bak
config
settings
test
tmp
temp
debug
docs
documentation
graphql
swagger
openapi
robots.txt
sitemap.xml
wp-login.php
wp-admin
xmlrpc.php
user
users
account
profile
auth
oauth
token
health
status
metrics
EOF

echo "=========================================="
echo "    All tools and wordlist installed!     "
echo "=========================================="
echo "You can now run gobuster directly using:"
echo "gobuster dir -u <URL> -w wordlist.txt -b 403,404"
