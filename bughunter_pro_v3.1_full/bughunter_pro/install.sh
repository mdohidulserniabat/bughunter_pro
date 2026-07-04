#!/bin/bash
# ══════════════════════════════════════════════════════
#  BugHunter Pro v3.1 — Fixed Installer
#  FIXED #10: Auto-detect latest Go, no hardcoded version
# ══════════════════════════════════════════════════════

set -uo pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
step() { echo -e "\n${CYAN}${BOLD}━━━━ $1 ━━━━${NC}"; }
ok()   { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${YELLOW}✗${NC} $1 (skipped)"; }

echo -e "${RED}${BOLD}BugHunter Pro v3.1 — Installer${NC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── OS Detection ─────────────────────────────────────
if grep -qi "kali\|debian\|ubuntu" /etc/os-release 2>/dev/null; then
  PKG="apt"; INSTALL="sudo apt-get install -y -qq"
elif grep -qi "centos\|fedora\|rhel" /etc/os-release 2>/dev/null; then
  PKG="yum"; INSTALL="sudo yum install -y -q"
elif [[ "$(uname)" == "Darwin" ]]; then
  PKG="brew"; INSTALL="brew install"
else
  PKG="apt"; INSTALL="sudo apt-get install -y -qq"
fi
log "OS: $(grep PRETTY /etc/os-release 2>/dev/null | cut -d'"' -f2 || uname -s)"

# ── System Packages ──────────────────────────────────
step "System Packages"
[[ "$PKG" == "apt" ]] && sudo apt-get update -qq 2>/dev/null || true

for pkg in curl wget git jq whois dnsutils nmap nikto python3 \
           python3-pip libpcap-dev chromium-browser; do
  cmd=$(echo "$pkg" | sed 's/-browser//')
  if ! command -v "$cmd" &>/dev/null; then
    echo -n "  Installing $pkg... "
    $INSTALL "$pkg" 2>/dev/null && ok "$pkg" || fail "$pkg"
  else
    ok "$pkg"
  fi
done

# ── Go: Auto-detect latest stable version ────────────
step "Go Language (latest stable — auto-detected)"

# Minimum required version
GO_MIN_MAJOR=1; GO_MIN_MINOR=22

# Auto-detect latest stable Go version from official API
log "Fetching latest Go version from go.dev..."
GO_INSTALL_VER=$(curl -s --max-time 10 "https://go.dev/dl/?mode=json" 2>/dev/null | \
  python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    stable = [r for r in data if r.get('stable') and r['version'].startswith('go1')]
    latest = sorted(
        stable,
        key=lambda x: [int(n) for n in x['version'].replace('go','').split('.')],
        reverse=True
    )[0]['version'].replace('go','')
    print(latest)
except:
    print('')
" 2>/dev/null || echo "")

# Fallback if API unreachable
if [[ -z "$GO_INSTALL_VER" ]]; then
  warn "Could not fetch latest version — using known stable: 1.26.4"
  GO_INSTALL_VER="1.26.4"
else
  log "Latest stable Go: $GO_INSTALL_VER"
fi

need_go_install() {
  if ! command -v go &>/dev/null; then return 0; fi
  GOVER=$(go version 2>/dev/null | grep -oP '\d+\.\d+' | head -1)
  GMAJ=$(echo "$GOVER" | cut -d'.' -f1)
  GMIN=$(echo "$GOVER" | cut -d'.' -f2)
  if [[ "$GMAJ" -lt "$GO_MIN_MAJOR" ]] || \
     [[ "$GMAJ" -eq "$GO_MIN_MAJOR" && "$GMIN" -lt "$GO_MIN_MINOR" ]]; then
    warn "Go $GOVER too old (need >= $GO_MIN_MAJOR.$GO_MIN_MINOR) — upgrading to $GO_INSTALL_VER"
    return 0
  fi
  return 1
}

if need_go_install; then
  log "Installing Go $GO_INSTALL_VER..."
  ARCH=$(uname -m)
  [[ "$ARCH" == "x86_64" ]] && GOARCH="amd64" || GOARCH="arm64"
  OS=$(uname -s | tr '[:upper:]' '[:lower:]')
  GO_URL="https://go.dev/dl/go${GO_INSTALL_VER}.${OS}-${GOARCH}.tar.gz"
  wget -q "$GO_URL" -O /tmp/go.tar.gz 2>/dev/null || \
    { warn "Go download failed — check network"; }
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf /tmp/go.tar.gz 2>/dev/null
  rm -f /tmp/go.tar.gz
  for rc in ~/.bashrc ~/.zshrc ~/.profile; do
    [[ -f "$rc" ]] && grep -q '/usr/local/go/bin' "$rc" 2>/dev/null || \
      printf '\nexport PATH=$PATH:/usr/local/go/bin:$HOME/go/bin\nexport GOPATH=$HOME/go\n' >> "$rc"
  done
  ok "Go $GO_INSTALL_VER installed"
else
  ok "Go $(go version | grep -oP '\d+\.\d+\.\d+' | head -1) (up to date)"
fi

export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
mkdir -p "$GOPATH/bin"

go version &>/dev/null || { warn "Go not in PATH — run: source ~/.bashrc"; }

# ── Go Security Tools ─────────────────────────────────
step "Go Security Tools (30+)"

declare -A GO_TOOLS=(
  # ProjectDiscovery Suite
  ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
  ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  ["naabu"]="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  ["dnsx"]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  ["katana"]="github.com/projectdiscovery/katana/cmd/katana@latest"
  ["interactsh-client"]="github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
  ["cdncheck"]="github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"
  # Recon
  ["amass"]="github.com/owasp-amass/amass/v4/...@master"
  ["waybackurls"]="github.com/tomnomnom/waybackurls@latest"
  ["gau"]="github.com/lc/gau/v2/cmd/gau@latest"
  ["hakrawler"]="github.com/hakluke/hakrawler@latest"
  ["gospider"]="github.com/jaeles-project/gospider@latest"
  # Utils
  ["anew"]="github.com/tomnomnom/anew@latest"
  ["gf"]="github.com/tomnomnom/gf@latest"
  ["qsreplace"]="github.com/tomnomnom/qsreplace@latest"
  ["unfurl"]="github.com/tomnomnom/unfurl@latest"
  # Vulnerability
  ["dalfox"]="github.com/hahwul/dalfox/v2@latest"
  ["ffuf"]="github.com/ffuf/ffuf/v2@latest"
  ["gowitness"]="github.com/sensepost/gowitness@latest"
  ["crlfuzz"]="github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
  # Takeover
  ["subjack"]="github.com/haccer/subjack@latest"
  ["subzy"]="github.com/PentestPad/subzy@latest"
  # Permutations
  ["gotator"]="github.com/Josue87/gotator@latest"
  ["puredns"]="github.com/d3mondev/puredns/v2@latest"
  # API
  ["kiterunner"]="github.com/assetnote/kiterunner/cmd/kr@latest"
  # GitHub-specific
  ["github-subdomains"]="github.com/gwen001/github-subdomains@latest"
  ["gitdorks_go"]="github.com/damit5/gitdorks_go@latest"
  # JS analysis
  ["jsluice"]="github.com/BishopFox/jsluice/cmd/jsluice@latest"
  ["cariddi"]="github.com/edoardottt/cariddi/cmd/cariddi@latest"
)

INSTALLED=0; FAILED=0
for tool in "${!GO_TOOLS[@]}"; do
  if ! command -v "$tool" &>/dev/null; then
    echo -n "  Installing $tool... "
    go install "${GO_TOOLS[$tool]}" 2>/dev/null && \
      { ok "$tool"; INSTALLED=$((INSTALLED+1)); } || \
      { fail "$tool"; FAILED=$((FAILED+1)); }
  else
    ok "$tool (present)"; INSTALLED=$((INSTALLED+1))
  fi
done
log "Go tools: $INSTALLED ok, $FAILED failed"

# ── Python Tools ─────────────────────────────────────
step "Python Security Tools"
pip3 install -q --upgrade pip 2>/dev/null || true

for p in requests beautifulsoup4 dnspython colorama mmh3 \
          wafw00f paramspider arjun corsy graphw00f clairvoyance; do
  echo -n "  $p... "
  pip3 install -q "$p" 2>/dev/null && ok "$p" || fail "$p"
done

# sqlmap
if ! command -v sqlmap &>/dev/null; then
  echo -n "  sqlmap... "
  sudo git clone -q https://github.com/sqlmapproject/sqlmap /opt/sqlmap 2>/dev/null && \
    sudo ln -sf /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap && ok "sqlmap" || fail "sqlmap"
else ok "sqlmap"; fi

# jwt_tool
if ! command -v jwt_tool &>/dev/null; then
  echo -n "  jwt_tool... "
  git clone -q https://github.com/ticarpi/jwt_tool /opt/jwt_tool 2>/dev/null && \
    sudo ln -sf /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool && \
    chmod +x /opt/jwt_tool/jwt_tool.py 2>/dev/null && ok "jwt_tool" || fail "jwt_tool"
else ok "jwt_tool"; fi

# trufflehog
if ! command -v trufflehog &>/dev/null; then
  echo -n "  trufflehog... "
  curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    2>/dev/null | sudo sh -s -- -b /usr/local/bin 2>/dev/null && \
    ok "trufflehog" || fail "trufflehog"
else ok "trufflehog"; fi

# gitleaks
if ! command -v gitleaks &>/dev/null; then
  echo -n "  gitleaks... "
  ARCH=$(uname -m); [[ "$ARCH" == "x86_64" ]] && GA="x64" || GA="arm64"
  OS_L=$(uname -s | tr '[:upper:]' '[:lower:]')
  GLVER=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
    2>/dev/null | jq -r '.tag_name' | tr -d 'v' || echo "8.18.0")
  wget -q "https://github.com/gitleaks/gitleaks/releases/download/v${GLVER}/gitleaks_${GLVER}_${OS_L}_${GA}.tar.gz" \
    -O /tmp/gitleaks.tar.gz 2>/dev/null && \
    sudo tar -C /usr/local/bin -xzf /tmp/gitleaks.tar.gz gitleaks 2>/dev/null && \
    ok "gitleaks" || fail "gitleaks"
  rm -f /tmp/gitleaks.tar.gz
else ok "gitleaks"; fi

# smuggler
if ! command -v smuggler &>/dev/null; then
  echo -n "  smuggler... "
  git clone -q https://github.com/defparam/smuggler /opt/smuggler 2>/dev/null && \
    printf '#!/bin/bash\npython3 /opt/smuggler/smuggler.py "$@"\n' | \
      sudo tee /usr/local/bin/smuggler > /dev/null && \
    sudo chmod +x /usr/local/bin/smuggler && ok "smuggler" || fail "smuggler"
else ok "smuggler"; fi

# h2csmuggler
if ! command -v h2csmuggler &>/dev/null; then
  echo -n "  h2csmuggler... "
  pip3 install -q h2 2>/dev/null
  git clone -q https://github.com/BishopFox/h2csmuggler /opt/h2csmuggler 2>/dev/null && \
    printf '#!/bin/bash\npython3 /opt/h2csmuggler/h2csmuggler.py "$@"\n' | \
      sudo tee /usr/local/bin/h2csmuggler > /dev/null && \
    sudo chmod +x /usr/local/bin/h2csmuggler && ok "h2csmuggler" || fail "h2csmuggler"
else ok "h2csmuggler"; fi

# nosqlmap
if ! command -v nosqlmap &>/dev/null; then
  echo -n "  nosqlmap... "
  git clone -q https://github.com/codingo/NoSQLMap /opt/nosqlmap 2>/dev/null && \
    pip3 install -q -r /opt/nosqlmap/requirements.txt 2>/dev/null && \
    printf '#!/bin/bash\npython3 /opt/nosqlmap/nosqlmap.py "$@"\n' | \
      sudo tee /usr/local/bin/nosqlmap > /dev/null && \
    sudo chmod +x /usr/local/bin/nosqlmap && ok "nosqlmap" || fail "nosqlmap"
else ok "nosqlmap"; fi

# tplmap
if ! command -v tplmap &>/dev/null; then
  echo -n "  tplmap (SSTI)... "
  git clone -q https://github.com/epinna/tplmap /opt/tplmap 2>/dev/null && \
    pip3 install -q -r /opt/tplmap/requirements.txt 2>/dev/null && \
    printf '#!/bin/bash\npython3 /opt/tplmap/tplmap.py "$@"\n' | \
      sudo tee /usr/local/bin/tplmap > /dev/null && \
    sudo chmod +x /usr/local/bin/tplmap && ok "tplmap" || fail "tplmap"
else ok "tplmap"; fi

# x8
if ! command -v x8 &>/dev/null; then
  echo -n "  x8... "
  ARCH=$(uname -m)
  [[ "$ARCH" == "x86_64" ]] && X8A="x86_64" || X8A="aarch64"
  wget -q "https://github.com/sh1yo/x8/releases/latest/download/x8-linux-musl-${X8A}" \
    -O /usr/local/bin/x8 2>/dev/null && \
    sudo chmod +x /usr/local/bin/x8 && ok "x8" || fail "x8"
else ok "x8"; fi

pip3 install -q py-altdns 2>/dev/null && ok "altdns" || fail "altdns"

# ── GF Patterns ──────────────────────────────────────
step "GF Patterns"
export PATH=$PATH:$HOME/go/bin
if command -v gf &>/dev/null; then
  mkdir -p ~/.gf
  if [[ ! -d ~/Gf-Patterns ]]; then
    git clone -q https://github.com/1ndianl33t/Gf-Patterns ~/Gf-Patterns 2>/dev/null && \
      cp ~/Gf-Patterns/*.json ~/.gf/ 2>/dev/null && ok "GF patterns" || warn "GF patterns failed"
  else
    ok "GF patterns (present)"
  fi
fi

# ── Nuclei Templates ─────────────────────────────────
step "Nuclei Templates"
command -v nuclei &>/dev/null && \
  { nuclei -update-templates -silent 2>/dev/null && ok "Templates updated"; } || \
  warn "nuclei not available yet"

# ── DNS Resolvers & Wordlists ─────────────────────────
step "DNS Resolvers & Wordlists"
cat > /tmp/resolvers.txt << 'RESOLVERS'
8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
9.9.9.9
149.112.112.112
208.67.222.222
208.67.220.220
RESOLVERS
ok "Resolvers: /tmp/resolvers.txt"

mkdir -p ~/wordlists
declare -A WL=(
  ["subdomains-110k.txt"]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt"
  ["common-dirs.txt"]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
  ["api-endpoints.txt"]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt"
)
for name in "${!WL[@]}"; do
  if [[ ! -f ~/wordlists/$name ]]; then
    echo -n "  $name... "
    wget -q "${WL[$name]}" -O ~/wordlists/$name 2>/dev/null && ok "$name" || fail "$name"
  else
    ok "$name (present)"
  fi
done

# ── Permissions ───────────────────────────────────────
step "Permissions"
chmod +x "$SCRIPT_DIR/bughunter.sh" 2>/dev/null
chmod +x "$SCRIPT_DIR/modules/"*.sh 2>/dev/null || true
ok "All scripts executable"

# ── Final Verification ────────────────────────────────
step "Verification"
echo ""
echo -e "  ${BOLD}Installed Go version:${NC} $(go version 2>/dev/null | grep -oP 'go\d+\.\d+\.\d+' || echo 'not found')"
echo ""
MISSING=()
for tool in subfinder httpx nuclei dnsx katana gau dalfox ffuf \
            subjack subzy gowitness jq python3 nmap; do
  command -v "$tool" &>/dev/null && ok "$tool" || { fail "$tool"; MISSING+=("$tool"); }
done

echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║  BugHunter Pro v3.1 — Install Complete ✓    ║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════╝${NC}"
echo ""
[[ ${#MISSING[@]} -gt 0 ]] && \
  echo -e "${YELLOW}Missing: ${MISSING[*]} — re-run installer${NC}\n"
echo -e "${CYAN}Next steps:${NC}"
echo "  source ~/.bashrc"
echo "  ./setup_keys.sh       ← API keys save করুন (একবার)"
echo "  ./bughunter.sh -d example.com"
echo ""
echo -e "${YELLOW}⚠  Authorized targets only${NC}"
