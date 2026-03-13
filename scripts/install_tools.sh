#!/bin/bash
# Install all required tools for BugBountyTRS pipeline
# Run as: bash scripts/install_tools.sh

set -e

echo "[*] BugBountyTRS Tool Installer"
echo "================================"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

check_installed() {
    if command -v "$1" &>/dev/null; then
        echo -e "${GREEN}[+] $1 already installed$(${NC})"
        return 0
    fi
    return 1
}

install_go_tool() {
    local name=$1
    local pkg=$2
    if ! check_installed "$name"; then
        echo -e "${YELLOW}[*] Installing $name...${NC}"
        go install "$pkg" 2>/dev/null && echo -e "${GREEN}[+] $name installed${NC}" || echo -e "${RED}[-] Failed to install $name${NC}"
    fi
}

# Check Go
if ! command -v go &>/dev/null; then
    echo -e "${YELLOW}[*] Installing Go...${NC}"
    wget -q "https://go.dev/dl/go1.22.2.linux-amd64.tar.gz" -O /tmp/go.tar.gz
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.zshrc
    rm /tmp/go.tar.gz
fi

export PATH=$PATH:$HOME/go/bin:/usr/local/go/bin

# ProjectDiscovery tools
install_go_tool "subfinder"   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool "httpx"       "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go_tool "nuclei"      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
install_go_tool "katana"      "github.com/projectdiscovery/katana/cmd/katana@latest"

# gowitness
install_go_tool "gowitness"   "github.com/sensepost/gowitness@latest"

# System tools
if ! check_installed "nmap"; then
    echo -e "${YELLOW}[*] Installing nmap...${NC}"
    sudo apt-get update -qq && sudo apt-get install -y -qq nmap
fi

if ! check_installed "dig"; then
    echo -e "${YELLOW}[*] Installing dnsutils...${NC}"
    sudo apt-get update -qq && sudo apt-get install -y -qq dnsutils
fi

if ! check_installed "amass"; then
    install_go_tool "amass" "github.com/owasp-amass/amass/v4/...@master"
fi

# Docker (for Redis)
if ! check_installed "docker"; then
    echo -e "${YELLOW}[*] Installing docker...${NC}"
    curl -fsSL https://get.docker.com | sudo sh
    sudo usermod -aG docker $USER
    echo -e "${YELLOW}[!] You may need to log out and back in for docker group to take effect${NC}"
fi

if ! check_installed "docker-compose" && ! docker compose version &>/dev/null 2>&1; then
    echo -e "${YELLOW}[*] Installing docker-compose...${NC}"
    sudo apt-get install -y -qq docker-compose-plugin 2>/dev/null || \
    sudo pip3 install docker-compose 2>/dev/null
fi

# Python deps
echo -e "${YELLOW}[*] Installing Python dependencies...${NC}"
pip3 install -r requirements.txt 2>/dev/null || pip install -r requirements.txt

# Update nuclei templates
if command -v nuclei &>/dev/null; then
    echo -e "${YELLOW}[*] Updating nuclei templates...${NC}"
    nuclei -update-templates 2>/dev/null || true
fi

echo ""
echo -e "${GREEN}[+] Installation complete!${NC}"
echo ""
echo "Next steps:"
echo "  1. Start Redis:        docker compose up -d"
echo "  2. Add a program:      python3 cli.py scope add <name> --wildcard '*.example.com'"
echo "  3. Start the pipeline: python3 cli.py run all"
