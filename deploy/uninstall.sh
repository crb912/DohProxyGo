#!/bin/bash
#
# DoH DNS Proxy - Linux uninstall script
#

# Ensure the script is run with bash, not sh
if [ -z "$BASH_VERSION" ]; then
    echo "Error: This script requires bash. Please run with 'bash uninstall.sh' or './uninstall.sh'."
    exit 1
fi

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SERVICE_NAME="dohproxygo"
INSTALL_DIR="/opt/dohproxygo"

echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}  DoH DNS Proxy - Uninstaller${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR]${NC} Please run this script with root privileges"
    echo "Usage: sudo bash uninstall.sh"
    exit 1
fi

echo -e "${YELLOW}[WARNING]${NC} About to uninstall DoH DNS Proxy"
read -p "Confirm uninstall? (y/n): " -n 1 -r
echo

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Uninstall canceled"
    exit 0
fi

echo ""
echo -e "${GREEN}[INFO]${NC} Stopping service..."
systemctl stop ${SERVICE_NAME}.service 2>/dev/null || true

echo -e "${GREEN}[INFO]${NC} Disabling service..."
systemctl disable ${SERVICE_NAME}.service 2>/dev/null || true

echo -e "${GREEN}[INFO]${NC} Removing service file..."
rm -f /etc/systemd/system/${SERVICE_NAME}.service
systemctl daemon-reload

echo -e "${GREEN}[INFO]${NC} Removing installation directory..."
rm -rf "$INSTALL_DIR"

echo -e "${GREEN}[INFO]${NC} Restoring /etc/resolv.conf (if backup exists)..."
if [ -f /etc/resolv.conf.backup ]; then
    mv /etc/resolv.conf.backup /etc/resolv.conf
    echo -e "${GREEN}[SUCCESS]${NC} Original DNS configuration restored"
fi

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✓ Uninstallation complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
