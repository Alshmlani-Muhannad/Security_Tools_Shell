#!/bin/bash

echo "=========================================="
echo "    Starting Security Tools Installation   "
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
echo "    All tools installed successfully!     "
echo "=========================================="
