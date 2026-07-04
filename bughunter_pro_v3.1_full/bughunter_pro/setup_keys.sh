#!/bin/bash
# ══════════════════════════════════════════════════════
#  BugHunter Pro — API Key Setup
#  Run this once to permanently save your API keys
# ══════════════════════════════════════════════════════

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'
BOLD='\033[1m'; NC='\033[0m'

CONFIG_DIR="$HOME/.bughunter"
CONFIG_FILE="$CONFIG_DIR/config.sh"

mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

echo -e "${CYAN}${BOLD}BugHunter Pro — API Key Setup${NC}"
echo -e "${YELLOW}Enter key এর জায়গা blank রাখলে skip হবে${NC}"
echo ""

read_key() {
  local name="$1" desc="$2" url="$3" current="$4"
  echo -e "${BOLD}$name${NC} — $desc"
  echo -e "  URL: ${CYAN}$url${NC}"
  [[ -n "$current" ]] && echo -e "  Current: ${GREEN}${current:0:8}...${NC}"
  read -rp "  Enter $name (blank to skip): " val
  echo "$val"
}

# Load existing config if present
[[ -f "$CONFIG_FILE" ]] && source "$CONFIG_FILE" 2>/dev/null

echo ""
SHODAN=$(read_key "SHODAN_API_KEY" "Subdomain+favicon hash" "https://account.shodan.io/" "${SHODAN_API_KEY:-}")
GITHUB=$(read_key "GITHUB_TOKEN" "GitHub subdomain+secret search" "https://github.com/settings/tokens" "${GITHUB_TOKEN:-}")
CHAOS=$(read_key "CHAOS_KEY" "ProjectDiscovery subdomain dataset" "https://chaos.projectdiscovery.io/" "${CHAOS_KEY:-}")
SECTRAILS=$(read_key "SECURITYTRAILS_KEY" "Best subdomain source" "https://securitytrails.com/app/account/credentials" "${SECURITYTRAILS_KEY:-}")
CENSYS_ID=$(read_key "CENSYS_API_ID" "Certificate-based enum" "https://search.censys.io/account/api" "${CENSYS_API_ID:-}")
CENSYS_SEC=$(read_key "CENSYS_API_SECRET" "Censys secret" "https://search.censys.io/account/api" "${CENSYS_API_SECRET:-}")
FOFA_E=$(read_key "FOFA_EMAIL" "FOFA search engine" "https://fofa.info/" "${FOFA_EMAIL:-}")
FOFA_K=$(read_key "FOFA_KEY" "FOFA API key" "https://fofa.info/" "${FOFA_KEY:-}")
ZOOMEYE=$(read_key "ZOOMEYE_KEY" "ZoomEye search" "https://www.zoomeye.org/profile" "${ZOOMEYE_KEY:-}")
NETLAS=$(read_key "NETLAS_KEY" "Netlas.io" "https://app.netlas.io/profile/" "${NETLAS_KEY:-}")
FULLHUNT=$(read_key "FULLHUNT_KEY" "FullHunt.io" "https://fullhunt.io/user/settings" "${FULLHUNT_KEY:-}")

echo ""
read -rp "Telegram Bot Token (scan শেষে notify, blank to skip): " TG_TOKEN
read -rp "Telegram Chat ID: " TG_CHAT

# Write config — keep existing values if new input is blank
write_val() {
  local new="$1" old="$2"
  [[ -n "$new" ]] && echo "$new" || echo "$old"
}

cat > "$CONFIG_FILE" << CONFIGEOF
#!/bin/bash
# BugHunter Pro — API Keys
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# Edit: nano ~/.bughunter/config.sh

export SHODAN_API_KEY="$(write_val "$SHODAN" "${SHODAN_API_KEY:-}")"
export GITHUB_TOKEN="$(write_val "$GITHUB" "${GITHUB_TOKEN:-}")"
export CHAOS_KEY="$(write_val "$CHAOS" "${CHAOS_KEY:-}")"
export SECURITYTRAILS_KEY="$(write_val "$SECTRAILS" "${SECURITYTRAILS_KEY:-}")"
export CENSYS_API_ID="$(write_val "$CENSYS_ID" "${CENSYS_API_ID:-}")"
export CENSYS_API_SECRET="$(write_val "$CENSYS_SEC" "${CENSYS_API_SECRET:-}")"
export FOFA_EMAIL="$(write_val "$FOFA_E" "${FOFA_EMAIL:-}")"
export FOFA_KEY="$(write_val "$FOFA_K" "${FOFA_KEY:-}")"
export ZOOMEYE_KEY="$(write_val "$ZOOMEYE" "${ZOOMEYE_KEY:-}")"
export NETLAS_KEY="$(write_val "$NETLAS" "${NETLAS_KEY:-}")"
export FULLHUNT_KEY="$(write_val "$FULLHUNT" "${FULLHUNT_KEY:-}")"
export TELEGRAM_BOT_TOKEN="$(write_val "$TG_TOKEN" "${TELEGRAM_BOT_TOKEN:-}")"
export TELEGRAM_CHAT_ID="$(write_val "$TG_CHAT" "${TELEGRAM_CHAT_ID:-}")"
CONFIGEOF

chmod 600 "$CONFIG_FILE"

echo ""
echo -e "${GREEN}✓ Config saved: $CONFIG_FILE${NC}"
echo -e "${YELLOW}Permission: 600 (শুধু আপনি দেখতে পাবেন)${NC}"
echo ""

# Show what's set
echo -e "${BOLD}Set keys:${NC}"
source "$CONFIG_FILE"
for key in SHODAN_API_KEY GITHUB_TOKEN CHAOS_KEY SECURITYTRAILS_KEY \
           CENSYS_API_ID FOFA_KEY ZOOMEYE_KEY NETLAS_KEY FULLHUNT_KEY; do
  val="${!key:-}"
  if [[ -n "$val" ]]; then
    echo -e "  ${GREEN}✓${NC} $key: ${val:0:8}..."
  else
    echo -e "  ${YELLOW}✗${NC} $key: not set"
  fi
done

echo ""
echo -e "${CYAN}এখন থেকে শুধু এটুকু চালালেই হবে:${NC}"
echo "  ./bughunter.sh -d example.com"
echo ""
echo -e "${CYAN}Key আপডেট করতে:${NC}"
echo "  ./setup_keys.sh          # এই script আবার run করুন"
echo "  nano ~/.bughunter/config.sh  # সরাসরি edit করুন"
