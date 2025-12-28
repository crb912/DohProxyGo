#!/bin/bash
#
# DoH DNS Proxy - Linux one-click installation script
# Supports: Ubuntu, Debian, CentOS, Fedora, Arch Linux
#

# Ensure the script is run with bash, not sh
if [ -z "$BASH_VERSION" ]; then
    echo "Error: This script requires bash. Please run with 'bash install.sh' or './install.sh'."
    exit 1
fi

set -e

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
VERSION="v2.0.0"
INSTALL_DIR="/opt/dohproxygo"
SERVICE_NAME="dohproxygo"
BINARY_URL="https://github.com/crb912/DohProxyGo/releases/download/${VERSION}/dohproxygo-linux-amd64"

# Print functions
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "Please run this script with root privileges"
        echo "Usage: sudo bash install.sh"
        exit 1
    fi
}

# Check system architecture
check_architecture() {
    local arch=$(uname -m)
    if [ "$arch" != "x86_64" ]; then
        print_error "Unsupported architecture: $arch (only x86_64 is supported)"
        exit 1
    fi
}

# Check and stop systemd-resolved (which uses port 53)
check_port_53() {
    print_info "Checking port 53..."

    if command -v systemctl &> /dev/null; then
        if systemctl is-active --quiet systemd-resolved; then
            print_warning "Detected systemd-resolved is running (occupying port 53)"
            read -p "Stop and disable systemd-resolved? (y/n): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                systemctl stop systemd-resolved
                systemctl disable systemd-resolved
                print_success "systemd-resolved has been stopped"

                # Update /etc/resolv.conf
                rm -f /etc/resolv.conf
                echo "nameserver 8.8.8.8" > /etc/resolv.conf
                echo "nameserver 8.8.4.4" >> /etc/resolv.conf
                print_success "/etc/resolv.conf has been updated"
            fi
        fi
    fi

    # Check if port 53 is still in use
    if lsof -Pi :53 -sTCP:LISTEN -t >/dev/null 2>&1 || lsof -Pi :53 -sUDP:LISTEN -t >/dev/null 2>&1; then
        print_error "Port 53 is still in use. Please manually stop the conflicting process:"
        lsof -i :53
        exit 1
    fi
}

# Create installation directories
create_directories() {
    print_info "Creating installation directories..."
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$INSTALL_DIR/logs"
    print_success "Directories created: $INSTALL_DIR"
}

# Download binary file
download_binary() {
    print_info "Downloading DoH DNS Proxy ${VERSION}..."

    if command -v wget &> /dev/null; then
        wget -O "$INSTALL_DIR/dohproxygo" "$BINARY_URL"
    elif command -v curl &> /dev/null; then
        curl -L -o "$INSTALL_DIR/dohproxygo" "$BINARY_URL"
    else
        print_error "wget or curl is required to download the file"
        exit 1
    fi

    chmod +x "$INSTALL_DIR/dohproxygo"
    print_success "Binary downloaded successfully"
}

# Create configuration file
create_config() {
    print_info "Creating configuration file..."

    cat > "$INSTALL_DIR/config.toml" << 'EOF'
[doh_servers]
direct_servers = [
    "https://doh.pub/dns-query",
    "https://dns.alidns.com/dns-query"
]
proxy_servers = [
    "https://dns.google/dns-query",
    "https://1.1.1.1/dns-query"
]
bootstrap_server = "223.5.5.5"

[dns]
host = '0.0.0.0'
port = 53

[cache]
max_size = 5000000
path = 'dns_cache.json'
save_interval = 72

[proxy]
enable_proxy = false
http = "http://127.0.0.1:7890"
https = "http://127.0.0.1:7890"
rule_file = "gfwlist.txt"
rule_file_url = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"

[logging]
default_log_level = "INFO"
query_log_level = "INFO"
EOF

    print_success "Configuration file created: $INSTALL_DIR/config.toml"
}

# Create systemd service
create_service() {
    print_info "Creating systemd service..."

    cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=DoH DNS Proxy
Documentation=https://github.com/crb912/DohProxyGo
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/dohproxygo
Restart=always
RestartSec=5
StandardOutput=append:$INSTALL_DIR/logs/main.log
StandardError=append:$INSTALL_DIR/logs/error.log

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    print_success "systemd service created successfully"
}

# Start the service
start_service() {
    print_info "Starting DoH DNS Proxy service..."

    systemctl enable "${SERVICE_NAME}.service"
    systemctl start "${SERVICE_NAME}.service"

    sleep 2

    if systemctl is-active --quiet "${SERVICE_NAME}.service"; then
        print_success "Service started successfully!"
    else
        print_error "Failed to start service. Check logs:"
        journalctl -u "${SERVICE_NAME}.service" -n 50 --no-pager
        exit 1
    fi
}

# Configure system DNS
configure_system_dns() {
    print_info "Configure system to use local DNS server?"
    read -p "This will modify /etc/resolv.conf (y/n): " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # Backup original file
        cp /etc/resolv.conf /etc/resolv.conf.backup

        cat > /etc/resolv.conf << EOF
# DoH DNS Proxy
nameserver 127.0.0.1

# Fallback (if local DNS fails)
nameserver 8.8.8.8
nameserver 8.8.4.4
EOF

        print_success "System DNS configured to use local server"
        print_info "Original config backed up to: /etc/resolv.conf.backup"
    fi
}

# Test DNS resolution
test_dns() {
    print_info "Testing DNS resolution..."

    sleep 2

    if command -v dig &> /dev/null; then
        if dig @127.0.0.1 google.com +short | grep -q .; then
            print_success "DNS resolution test passed!"
        else
            print_warning "DNS resolution test failed. Please check logs."
        fi
    elif command -v nslookup &> /dev/null; then
        if nslookup google.com 127.0.0.1 | grep -q "Address"; then
            print_success "DNS resolution test passed!"
        else
            print_warning "DNS resolution test failed. Please check logs."
        fi
    else
        print_warning "dig or nslookup not installed. Skipping test."
    fi
}

# Show usage information
show_usage() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${GREEN}✓ DoH DNS Proxy installation complete!${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "📁 Install directory: $INSTALL_DIR"
    echo "⚙️  Config file: $INSTALL_DIR/config.toml"
    echo "📝 Log directory: $INSTALL_DIR/logs/"
    echo ""
    echo "🔧 Common commands:"
    echo "  Start service:   systemctl start $SERVICE_NAME"
    echo "  Stop service:    systemctl stop $SERVICE_NAME"
    echo "  Restart service: systemctl restart $SERVICE_NAME"
    echo "  Check status:    systemctl status $SERVICE_NAME"
    echo "  View logs:       journalctl -u $SERVICE_NAME -f"
    echo "  Edit config:     nano $INSTALL_DIR/config.toml"
    echo ""
    echo "🧪 Test DNS:"
    echo "  dig @127.0.0.1 google.com"
    echo "  nslookup google.com 127.0.0.1"
    echo ""
    echo "🗑️  Uninstall:"
    echo "  bash <(curl -s https://raw.githubusercontent.com/crb912/DohProxyGo/main/uninstall.sh)"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Main function
main() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  DoH DNS Proxy - Linux Installation Script"
    echo "  Version: ${VERSION}"
    echo "  Project: https://github.com/crb912/DohProxyGo"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    check_root
    check_architecture
    check_port_53
    create_directories
    download_binary
    create_config
    create_service
    start_service
    configure_system_dns
    test_dns
    show_usage
}

# Run main function
main
