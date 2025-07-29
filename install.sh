#!/bin/bash

# ExWiFi - Advanced WiFi Security Testing Tool
# Enhanced Edition 2024 - Installation Script
# Code by ErrorX

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    ExWiFi - Advanced WiFi Security           ║"
echo "║                        Enhanced Edition 2024                 ║"
echo "║                    Code by ErrorX - Modernized              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR] This script must be run as root${NC}"
    echo -e "${YELLOW}Please run: sudo bash install.sh${NC}"
    exit 1
fi

echo -e "${GREEN}[INFO] Starting ExWiFi installation...${NC}"

# Update system
echo -e "${BLUE}[INFO] Updating system packages...${NC}"
apt update && apt upgrade -y

# Install required packages
echo -e "${BLUE}[INFO] Installing required packages...${NC}"
pkg install -y root-repo
pkg install -y git tsu python wpa-supplicant pixiewps iw

# Check Python version
echo -e "${BLUE}[INFO] Checking Python version...${NC}"
python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
required_version="3.6"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" = "$required_version" ]; then
    echo -e "${GREEN}[OK] Python version $python_version is compatible${NC}"
else
    echo -e "${RED}[ERROR] Python version $python_version is too old. Required: $required_version+${NC}"
    exit 1
fi

# Make script executable
echo -e "${BLUE}[INFO] Setting permissions...${NC}"
chmod +x ErrorX.py

# Create necessary directories
echo -e "${BLUE}[INFO] Creating directories...${NC}"
mkdir -p ~/.ErrorX/sessions
mkdir -p ~/.ErrorX/pixiewps
mkdir -p reports

# Test installation
echo -e "${BLUE}[INFO] Testing installation...${NC}"
if python3 ErrorX.py --help > /dev/null 2>&1; then
    echo -e "${GREEN}[OK] Installation successful!${NC}"
else
    echo -e "${RED}[ERROR] Installation test failed${NC}"
    exit 1
fi

# Display usage information
echo -e "${GREEN}"
echo "═══════════════════════════════════════════════════════════════"
echo "                    Installation Complete!                     "
echo "═══════════════════════════════════════════════════════════════"
echo -e "${NC}"

echo -e "${BLUE}Usage Examples:${NC}"
echo -e "${YELLOW}  Basic scan and attack:${NC}"
echo "    sudo python3 ErrorX.py -i wlan0 -K"
echo ""
echo -e "${YELLOW}  Target specific BSSID:${NC}"
echo "    sudo python3 ErrorX.py -i wlan0 -b 00:90:4C:C1:AC:21 -K"
echo ""
echo -e "${YELLOW}  Bruteforce with PIN prefix:${NC}"
echo "    sudo python3 ErrorX.py -i wlan0 -b 00:90:4C:C1:AC:21 -B -p 1234"
echo ""
echo -e "${YELLOW}  Verbose mode:${NC}"
echo "    sudo python3 ErrorX.py -i wlan0 -K -v"
echo ""
echo -e "${YELLOW}  Save credentials:${NC}"
echo "    sudo python3 ErrorX.py -i wlan0 -b 00:90:4C:C1:AC:21 -K -w"
echo ""

echo -e "${GREEN}Configuration:${NC}"
echo "  - Configuration file: exwifi_config.json"
echo "  - Log file: exwifi.log"
echo "  - Reports directory: ./reports/"
echo "  - Sessions directory: ~/.ErrorX/sessions/"
echo ""

echo -e "${YELLOW}Important Notes:${NC}"
echo "  - Always run with sudo/root privileges"
echo "  - Turn off WiFi before starting attacks"
echo "  - Use only on networks you own or have permission to test"
echo "  - Check exwifi.log for detailed information"
echo ""

echo -e "${GREEN}Stay With ErrorX! 🚀${NC}"
echo ""