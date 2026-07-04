#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║   BUGHUNTER PRO v3.1 — Ultimate Bug Hunting Framework           ║
# ║   All audit issues fixed | Memory-safe | Low FP | OOB support  ║
# ╚══════════════════════════════════════════════════════════════════╝

set -uo pipefail
umask 077

# ── Colors ──────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; MAGENTA='\033[0;35m'
BOLD='\033[1m'; NC='\033[0m'

# ── Globals ─────────────────────────────────────────────────────────
DOMAIN=""; OUTPUT_DIR=""; THREADS=30; TIMEOUT=15; MAX_JOBS=3
PERM_WORDLIST_LIMIT=5000
PERM_TIMEOUT=15
DOMAIN_RE=""
START_TIME=$(date +%s); TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Optional API keys — set via env or -s/-g flags
SHODAN_API_KEY="${SHODAN_API_KEY:-}"
CENSYS_API_ID="${CENSYS_API_ID:-}"; CENSYS_API_SECRET="${CENSYS_API_SECRET:-}"
CHAOS_KEY="${CHAOS_KEY:-}"; GITHUB_TOKEN="${GITHUB_TOKEN:-}"
SECURITYTRAILS_KEY="${SECURITYTRAILS_KEY:-}"
FOFA_EMAIL="${FOFA_EMAIL:-}"; FOFA_KEY="${FOFA_KEY:-}"
ZOOMEYE_KEY="${ZOOMEYE_KEY:-}"; NETLAS_KEY="${NETLAS_KEY:-}"
FULLHUNT_KEY="${FULLHUNT_KEY:-}"

TOTAL_FINDINGS=0

# ── Config Auto-Load ────────────────────────────────────────────────
# ~/.bughunter/config.sh থেকে API keys load করে
# -s/-g flag দিলে সেটা config এর উপর override করে
CONFIG_FILE="${HOME}/.bughunter/config.sh"
if [[ -f "$CONFIG_FILE" ]]; then
  source "$CONFIG_FILE"
fi

# ── Helpers ─────────────────────────────────────────────────────────
log_info()    { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
log_error()   { echo -e "${RED}[-]${NC} $1"; }
log_section() {
  echo -e "\n${BLUE}${BOLD}╔══════════════════════════════════════════════╗${NC}"
  echo -e "${BLUE}${BOLD}║  $1${NC}"
  echo -e "${BLUE}${BOLD}╚══════════════════════════════════════════════╝${NC}\n"
}
log_finding() {
  TOTAL_FINDINGS=$((TOTAL_FINDINGS+1))
  echo -e "${RED}${BOLD}[VULN]${NC} ${RED}$1${NC}"
  echo "[$(date +%T)] $1" >> "$OUTPUT_DIR/findings.txt" 2>/dev/null || true
}
cmd_exists() { command -v "$1" &>/dev/null; }
safe_run()   { "$@" 2>/dev/null || true; }
regex_escape() { printf '%s' "$1" | sed 's/[.[\*^$()+?{|\\]/\\&/g'; }
safe_run_timeout() {
  local seconds="$1"
  shift
  if cmd_exists timeout; then
    timeout "$seconds" "$@" 2>/dev/null || true
  else
    "$@" 2>/dev/null || true
  fi
}

# ── Banner ──────────────────────────────────────────────────────────
banner() {
  clear
  echo -e "${RED}${BOLD}"
  cat << 'BANNER'
  ██████╗ ██╗   ██╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
  ██╔══██╗██║   ██║██╔════╝ ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  ██████╔╝██║   ██║██║  ███╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
  ██╔══██╗██║   ██║██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ██████╔╝╚██████╔╝╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
BANNER
  echo -e "${NC}"
  echo -e "${CYAN}${BOLD}              ULTIMATE FRAMEWORK v3.1 — ALL ISSUES FIXED${NC}"
  echo -e "${YELLOW}  Memory-safe | OOB XXE | Full JWT | All clouds | Low FP | Modern attacks${NC}"
  echo ""
}

# ── Usage ───────────────────────────────────────────────────────────
usage() {
  cat << HELP
${BOLD}Usage:${NC} $0 -d <domain> [options]

${BOLD}Required:${NC}
  -d <domain>        Target domain (e.g. example.com)

${BOLD}Performance:${NC}
  -t <threads>       Threads per tool    (default: 30)
  -T <timeout>       Timeout seconds     (default: 15)
  -j <max_jobs>      Parallel jobs       (default: 3)  ← FIXED #5

${BOLD}Advanced tuning via environment:${NC}
  PERM_WORDLIST_LIMIT   Permutation wordlist cap (default: 5000)
  PERM_TIMEOUT          Timeout for dnsgen/gotator/altdns (default: 15)

${BOLD}Output:${NC}
  -o <dir>           Output directory

${BOLD}Modules (comma-separated, default: all):${NC}
  sub       Subdomain enumeration (20+ sources)
  url       URL + endpoint collection
  js        JavaScript deep analysis
  api       API security testing
  nuclei    Nuclei scanning (priority order)
  web       Web vulnerabilities
  sqli      SQL/NoSQL injection
  xxe       XXE injection (OOB)
  smuggle   HTTP request smuggling (proper tools)
  secrets   Secret detection (entropy-checked)
  takeover  Subdomain takeover
  recon     DNS/infra recon
  modern    Modern attacks (OAuth/SAML/WS/race)
  github    GitHub recon (dedicated tools)
  extra     Extra recon sources
  waf       WAF detection
  report    HTML/MD/TXT report

${BOLD}API Keys (optional, improve results):${NC}
  -s <key>           Shodan
  -g <token>         GitHub token
  -C <key>           Chaos (ProjectDiscovery)
  -c <id:secret>     Censys

${BOLD}Via environment variables:${NC}
  export SECURITYTRAILS_KEY=xxx
  export FOFA_EMAIL=x FOFA_KEY=x
  export ZOOMEYE_KEY=xxx
  export NETLAS_KEY=xxx
  export FULLHUNT_KEY=xxx

${BOLD}Examples:${NC}
  $0 -d example.com
  $0 -d example.com -t 50 -j 5 -s SHODAN_KEY -g GITHUB_TOKEN
  $0 -d example.com -m sub,nuclei,report
  $0 -d example.com -j 2    # low-RAM VPS (512MB)

${BOLD}Resource presets:${NC}
  Low RAM  (512MB):  -t 10 -j 2
  Mid RAM  (2GB):    -t 30 -j 3  (default)
  High RAM (8GB+):   -t 80 -j 8
HELP
  exit 1
}

# ── Parse Args ──────────────────────────────────────────────────────
parse_args() {
  local MODULES_ARG="all"
  while getopts "d:o:t:T:j:m:s:g:c:C:h" opt; do
    case $opt in
      d) DOMAIN="${OPTARG,,}" ;;
      o) OUTPUT_DIR="$OPTARG" ;;
      t) THREADS="$OPTARG" ;;
      T) TIMEOUT="$OPTARG" ;;
      j) MAX_JOBS="$OPTARG" ;;
      m) MODULES_ARG="$OPTARG" ;;
      s) SHODAN_API_KEY="$OPTARG" ;;
      g) GITHUB_TOKEN="$OPTARG" ;;
      c) CENSYS_API_ID="${OPTARG%%:*}"; CENSYS_API_SECRET="${OPTARG##*:}" ;;
      C) CHAOS_KEY="$OPTARG" ;;
      h) usage ;;
      *) usage ;;
    esac
  done
  [[ -z "$DOMAIN" ]] && { log_error "Domain required!"; usage; }
  OUTPUT_DIR="${OUTPUT_DIR:-results_${DOMAIN}_${TIMESTAMP}}"

  # Parse module list
  for m in SUB URL JS API NUCLEI WEB SQLI XXE SMUGGLE SECRETS TAKEOVER \
            RECON MODERN GITHUB EXTRA WAF REPORT; do
    eval "RUN_$m=0"
  done
  eval "RUN_REPORT=1"

  if [[ "$MODULES_ARG" == "all" ]]; then
    for m in SUB URL JS API NUCLEI WEB SQLI XXE SMUGGLE SECRETS TAKEOVER \
              RECON MODERN GITHUB EXTRA WAF REPORT; do
      eval "RUN_$m=1"
    done
  else
    IFS=',' read -ra MODS <<< "$MODULES_ARG"
    for m in "${MODS[@]}"; do
      eval "RUN_${m^^}=1" 2>/dev/null || true
    done
  fi

  export MAX_JOBS
}

# ── Setup ───────────────────────────────────────────────────────────
setup() {
  mkdir -p "$OUTPUT_DIR"/{subdomains,urls,ports,screenshots,recon,takeover,reports}
  mkdir -p "$OUTPUT_DIR"/vulns/{nuclei,xss,sqli,idor,graphql,jwt,cors,headers,ssrf,lfi,ssti,xxe,smuggling,secrets,misc,api,js,waf,modern}
  export PATH="$PATH:$HOME/go/bin:/usr/local/go/bin"
  export GOPATH="$HOME/go"
  DOMAIN_RE="$(regex_escape "$DOMAIN")"
  touch "$OUTPUT_DIR/findings.txt"

  log_info "Target    : ${CYAN}$DOMAIN${NC}"
  log_info "Output    : ${CYAN}$OUTPUT_DIR${NC}"
  log_info "Threads   : $THREADS | Timeout: ${TIMEOUT}s | Max jobs: $MAX_JOBS"
  log_warn "API keys  : $([ -n "$SHODAN_API_KEY" ] && echo "Shodan ✓" || echo "Shodan ✗") $([ -n "$GITHUB_TOKEN" ] && echo "GitHub ✓" || echo "GitHub ✗") $([ -n "$CHAOS_KEY" ] && echo "Chaos ✓" || echo "Chaos ✗")"
}

# ── Load Modules ────────────────────────────────────────────────────
load_modules() {
  for f in "$SCRIPT_DIR/modules/"[0-9]*.sh; do
    [[ -f "$f" ]] && source "$f"
  done
}

# ── Screenshots ─────────────────────────────────────────────────────
run_screenshots() {
  log_section "Screenshots (gowitness)"
  local LIVE="$OUTPUT_DIR/subdomains/live.txt"
  [[ ! -f "$LIVE" ]] && return
  cmd_exists gowitness && \
    safe_run gowitness file -f "$LIVE" \
      --destination "$OUTPUT_DIR/screenshots" \
      --threads "$THREADS" || true
}

# ── Summary ─────────────────────────────────────────────────────────
print_summary() {
  echo ""
  echo -e "${GREEN}${BOLD}"
  echo "  ╔══════════════════════════════════════════╗"
  echo "  ║         SCAN COMPLETE ✓  v3.1            ║"
  echo "  ╚══════════════════════════════════════════╝"
  echo -e "${NC}"
  cat "$OUTPUT_DIR/reports/summary.txt" 2>/dev/null || true
  echo ""
  echo -e "  ${CYAN}► HTML Report :${NC} $OUTPUT_DIR/reports/report.html"
  echo -e "  ${CYAN}► All Findings:${NC} $OUTPUT_DIR/findings.txt"
  echo -e "  ${CYAN}► Total vulns :${NC} $TOTAL_FINDINGS"
  echo ""

  # Telegram notification
  if [[ -n "${TELEGRAM_BOT_TOKEN:-}" && -n "${TELEGRAM_CHAT_ID:-}" ]]; then
    END_T=$(date +%s)
    DUR=$(( (END_T - START_TIME) / 60 ))
    MSG="🔍 *BugHunter Pro v3.1*%0A"
    MSG+="✅ Scan complete: \`$DOMAIN\`%0A"
    MSG+="⏱ Duration: ${DUR}m%0A"
    MSG+="🚨 Findings: $TOTAL_FINDINGS%0A"
    MSG+="📁 Output: \`$OUTPUT_DIR\`"
    curl -s "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
      -d "chat_id=${TELEGRAM_CHAT_ID}&text=${MSG}&parse_mode=Markdown" \
      > /dev/null 2>&1 || true
    echo -e "  ${GREEN}► Telegram notified ✓${NC}"
  fi
}

# ── MAIN ────────────────────────────────────────────────────────────
main() {
  banner
  parse_args "$@"
  load_modules
  setup

  # Recon first (needed by other modules)
  [[ "${RUN_RECON:-0}"    == "1" ]] && mod_recon

  # Subdomain enum
  [[ "${RUN_SUB:-0}"      == "1" ]] && mod_subdomain

  # Extra sources (merges into subdomain list)
  [[ "${RUN_EXTRA:-0}"    == "1" ]] && mod_extra_recon

  # GitHub recon
  [[ "${RUN_GITHUB:-0}"   == "1" ]] && mod_github_recon

  # URL + JS collection
  [[ "${RUN_URL:-0}"      == "1" ]] && mod_urls
  [[ "${RUN_JS:-0}"       == "1" ]] && mod_js_analysis
  [[ "${RUN_JS:-0}"       == "1" ]] && mod_js_deep   # FIXED #12

  # Vulnerability scanning
  [[ "${RUN_SECRETS:-0}"  == "1" ]] && mod_secrets   # FIXED #11
  [[ "${RUN_TAKEOVER:-0}" == "1" ]] && mod_takeover
  [[ "${RUN_NUCLEI:-0}"   == "1" ]] && mod_nuclei    # FIXED #9
  [[ "${RUN_API:-0}"      == "1" ]] && mod_api       # FIXED #6
  [[ "${RUN_WEB:-0}"      == "1" ]] && mod_web_vulns # FIXED #7 #8
  [[ "${RUN_SQLI:-0}"     == "1" ]] && mod_sqli      # FIXED #2
  [[ "${RUN_XXE:-0}"      == "1" ]] && mod_xxe       # FIXED #3
  [[ "${RUN_SMUGGLE:-0}"  == "1" ]] && mod_smuggling # FIXED #1
  [[ "${RUN_MODERN:-0}"   == "1" ]] && mod_modern_attacks # FIXED #14
  [[ "${RUN_WAF:-0}"      == "1" ]] && mod_waf

  run_screenshots

  [[ "${RUN_REPORT:-1}"   == "1" ]] && mod_report

  print_summary
}

main "$@"
