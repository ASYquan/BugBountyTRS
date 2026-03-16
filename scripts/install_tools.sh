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
        echo -e "${GREEN}[+] $1 already installed${NC}"
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

# ─── ProjectDiscovery tools ─────────────────────────────────────
install_go_tool "subfinder"   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool "httpx"       "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go_tool "nuclei"      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
install_go_tool "katana"      "github.com/projectdiscovery/katana/cmd/katana@latest"
install_go_tool "naabu"       "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
install_go_tool "asnmap"      "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
install_go_tool "alterx"      "github.com/projectdiscovery/alterx/cmd/alterx@latest"
install_go_tool "dnsx"        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"

# ─── Other Go tools ─────────────────────────────────────────────
install_go_tool "puredns"     "github.com/d3mondev/puredns/v2@latest"
install_go_tool "gowitness"   "github.com/sensepost/gowitness@latest"
install_go_tool "smap"        "github.com/s0md3v/smap/cmd/smap@latest"
install_go_tool "caduceus"    "github.com/g0ldencybersec/Caduceus/cmd/caduceus@latest"

# ─── System tools ───────────────────────────────────────────────
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

# libpcap-dev (required for naabu SYN scans)
if ! dpkg -l libpcap-dev &>/dev/null 2>&1; then
    echo -e "${YELLOW}[*] Installing libpcap-dev (naabu dependency)...${NC}"
    sudo apt-get update -qq && sudo apt-get install -y -qq libpcap-dev
fi

# ─── Web fuzzing tools ──────────────────────────────────────────
if ! check_installed "feroxbuster"; then
    echo -e "${YELLOW}[*] Installing feroxbuster...${NC}"
    sudo apt-get update -qq && sudo apt-get install -y -qq feroxbuster 2>/dev/null || {
        curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s "$HOME/.local/bin" 2>/dev/null
    }
    check_installed "feroxbuster" && echo -e "${GREEN}[+] feroxbuster installed${NC}" || echo -e "${RED}[-] Failed to install feroxbuster${NC}"
fi

install_go_tool "ffuf" "github.com/ffuf/ffuf/v2@latest"

# ─── BBOT ────────────────────────────────────────────────────────
if ! check_installed "bbot"; then
    echo -e "${YELLOW}[*] Installing BBOT...${NC}"
    if command -v pipx &>/dev/null; then
        pipx install bbot && echo -e "${GREEN}[+] bbot installed${NC}" || echo -e "${RED}[-] Failed to install bbot${NC}"
    else
        pip3 install bbot 2>/dev/null && echo -e "${GREEN}[+] bbot installed${NC}" || echo -e "${RED}[-] Failed to install bbot${NC}"
    fi
fi

# ─── Docker (for Redis) ─────────────────────────────────────────
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

# ─── Python deps ────────────────────────────────────────────────
echo -e "${YELLOW}[*] Installing Python dependencies...${NC}"
pip3 install -r requirements.txt 2>/dev/null || pip install -r requirements.txt

# FastAPI + uvicorn for domain ranking API
pip3 install fastapi uvicorn pydantic 2>/dev/null || pip install fastapi uvicorn pydantic

# Shodan Python library
pip3 install shodan 2>/dev/null || pip install shodan

# PyYAML for signature loading
pip3 install pyyaml 2>/dev/null || pip install pyyaml

# Altdns for JS keyword subdomain mutation
if ! check_installed "altdns"; then
    echo -e "${YELLOW}[*] Installing altdns...${NC}"
    pip3 install py-altdns 2>/dev/null || pip install py-altdns 2>/dev/null
    check_installed "altdns" && echo -e "${GREEN}[+] altdns installed${NC}" || echo -e "${RED}[-] Failed to install altdns${NC}"
fi

# Update nuclei templates
if command -v nuclei &>/dev/null; then
    echo -e "${YELLOW}[*] Updating nuclei templates...${NC}"
    nuclei -update-templates 2>/dev/null || true
fi

# ─── Subfinder provider config ──────────────────────────────────
SUBFINDER_CONFIG="$HOME/.config/subfinder/provider-config.yaml"
if [ ! -f "$SUBFINDER_CONFIG" ]; then
    echo -e "${YELLOW}[*] Creating subfinder provider config template...${NC}"
    mkdir -p "$(dirname "$SUBFINDER_CONFIG")"
    cat > "$SUBFINDER_CONFIG" << 'YAML'
# Subfinder API keys — add your keys to enable these sources
# Docs: https://github.com/projectdiscovery/subfinder

# Free — just needs signup
chaos: []           # https://cloud.projectdiscovery.io
dnsdumpster: []     # https://dnsdumpster.com/membership/
urlscan: []         # https://urlscan.io/user/signup
reconeer: []        # https://reconeer.com

# Free tier available
virustotal: []      # https://www.virustotal.com/gui/join-us
shodan: []          # https://account.shodan.io/
censys: []          # https://search.censys.io/register
securitytrails: []  # https://securitytrails.com/app/signup
hackertarget: []    # https://hackertarget.com/ip-tools/

# Paid
binaryedge: []
c99: []
intelx: []
passivetotal: []
whoisxmlapi: []
YAML
    echo -e "${GREEN}[+] Subfinder provider config created at $SUBFINDER_CONFIG${NC}"
    echo -e "${YELLOW}    Add your API keys to enable more passive sources${NC}"
fi

echo ""
echo -e "${GREEN}[+] Installation complete!${NC}"
echo ""
echo "Installed tools:"
echo "  Recon:     subfinder, amass, puredns, alterx, asnmap, dnsx, bbot, altdns"
echo "  Scanning:  smap (passive), naabu (fast), nmap (deep)"
echo "  Web:       httpx, katana, nuclei, gowitness, feroxbuster, ffuf"
echo "  Services:  domain ranking API (FastAPI + uvicorn)"
echo ""
echo "Next steps:"
echo "  1. Start Redis:            docker compose up -d"
echo "  2. Start ranking API:      uvicorn pipeline.services.domain_ranking:app --port 8787 &"
echo "  3. Add API keys:           vim $SUBFINDER_CONFIG"
echo "  4. Add a program:          python3 cli.py scope add <name> --wildcard '*.example.com'"
echo "  5. Start the pipeline:     python3 cli.py run all"
