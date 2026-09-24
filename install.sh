#!/bin/bash

echo "=========================================="
echo "    Starting Security Tools Installation    "
echo "=========================================="

# تحديث النظام وحزم التثبيت
sudo apt update && sudo apt upgrade -y

# تثبيت الأدوات الأساسية والشبكات والحماية
sudo apt install -y \
    nmap \
    gobuster \
    tshark \
    curl \
    wget \
    dnsutils \
    whois \
    net-tools \
    git \
    python3-pip

echo "=========================================="
echo "    Creating Default Wordlist File...     "
echo "=========================================="

# إنشاء ملف الكلمات الموسع تلقائياً في نفس المجلد
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
