#!/bin/bash
# ══════════════════════════════════════════════════════
#  MOD 01: Maximum Subdomain Enumeration
#  Sources: subfinder, amass, dnsx, puredns, dnsgen,
#  altdns, gotator, crt.sh, wayback, alienvault,
#  hackertarget, urlscan, github, shodan, censys,
#  chaos, rapiddns, bufferover, commoncrawl, ASN recon
# ══════════════════════════════════════════════════════

mod_subdomain() {
  log_section "MOD 01: Maximum Subdomain Enumeration (20+ sources)"
  local D="$OUTPUT_DIR/subdomains"
  local DOMAIN_REGEX="$DOMAIN_RE"

  # ── PASSIVE: API Sources ──────────────────────────────

  log_info "[1/20] subfinder (-all -recursive)..."
  if cmd_exists subfinder; then
    safe_run subfinder -d "$DOMAIN" -all -recursive \
      -silent -t "$THREADS" -o "$D/subfinder.txt"
  fi

  log_info "[2/20] amass passive..."
  if cmd_exists amass; then
    safe_run amass enum -passive -d "$DOMAIN" \
      -o "$D/amass_passive.txt" -timeout 10
  fi

  log_info "[3/20] crt.sh (certificate transparency)..."
  curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null | \
    jq -r '.[].name_value' 2>/dev/null | \
    sed 's/\*\.//g' | tr ',' '\n' | \
    grep -E "^[a-zA-Z0-9._-]+\.${DOMAIN_REGEX}$" | \
    sort -u > "$D/crtsh.txt" || true
  # alternate query
  curl -s "https://crt.sh/?q=$DOMAIN&output=json" 2>/dev/null | \
    jq -r '.[].common_name,.name_value' 2>/dev/null | \
    sed 's/\*\.//g' | grep -E "\.${DOMAIN_REGEX}$" | \
    sort -u >> "$D/crtsh.txt" || true

  log_info "[4/20] Wayback Machine subdomains..."
  curl -s "http://web.archive.org/cdx/search/cdx?url=*.$DOMAIN&output=text&fl=original&collapse=urlkey&limit=50000" \
    2>/dev/null | grep -oP "https?://\K[a-zA-Z0-9._-]+" | \
    grep -E "\.${DOMAIN_REGEX}$" | sort -u > "$D/wayback_subs.txt" || true

  log_info "[5/20] AlienVault OTX..."
  curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$DOMAIN/passive_dns" \
    2>/dev/null | jq -r '.passive_dns[].hostname' 2>/dev/null | \
    grep -E "\.${DOMAIN_REGEX}$" | sort -u > "$D/alienvault.txt" || true

  log_info "[6/20] HackerTarget..."
  curl -s "https://api.hackertarget.com/hostsearch/?q=$DOMAIN" 2>/dev/null | \
    cut -d',' -f1 | grep -E "\.${DOMAIN_REGEX}$" | \
    sort -u > "$D/hackertarget.txt" || true

  log_info "[7/20] URLScan.io..."
  curl -s "https://urlscan.io/api/v1/search/?q=domain:$DOMAIN&size=10000" \
    2>/dev/null | jq -r '.results[].page.domain' 2>/dev/null | \
    grep -E "\.${DOMAIN_REGEX}$" | sort -u > "$D/urlscan.txt" || true

  log_info "[8/20] ThreatCrowd..."
  curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$DOMAIN" \
    2>/dev/null | jq -r '.subdomains[]' 2>/dev/null | \
    grep -E "\.${DOMAIN_REGEX}$" | sort -u > "$D/threatcrowd.txt" || true

  log_info "[9/20] RapidDNS..."
  curl -s "https://rapiddns.io/subdomain/$DOMAIN?full=1#result" 2>/dev/null | \
    grep -oP "[a-zA-Z0-9._-]+\.${DOMAIN_REGEX}" | \
    sort -u > "$D/rapiddns.txt" || true

  log_info "[10/20] BufferOver DNS..."
  curl -s "https://dns.bufferover.run/dns?q=.$DOMAIN" 2>/dev/null | \
    jq -r '.FDNS_A[],.RDNS[]' 2>/dev/null | \
    cut -d',' -f2 | grep -E "\.${DOMAIN_REGEX}$" | \
    sort -u > "$D/bufferover.txt" || true

  log_info "[11/20] CommonCrawl..."
  for index in CC-MAIN-2024-10 CC-MAIN-2023-50 CC-MAIN-2023-40; do
    curl -s "http://index.commoncrawl.org/${index}-index?url=*.$DOMAIN&output=json&limit=5000" \
      2>/dev/null | grep -oP '"url":"https?://\K[a-zA-Z0-9._-]+(?=\.' | \
      awk -v d=".$DOMAIN" '{print $0d}' >> "$D/commoncrawl.txt" || true
  done
  sort -u "$D/commoncrawl.txt" -o "$D/commoncrawl.txt" 2>/dev/null || true

  log_info "[12/20] ThreatMiner..."
  curl -s "https://api.threatminer.org/v2/domain.php?q=$DOMAIN&rt=5" \
    2>/dev/null | jq -r '.results[]' 2>/dev/null | \
    grep -E "\.${DOMAIN_REGEX}$" | sort -u > "$D/threatminer.txt" || true

  log_info "[13/20] GitHub subdomains..."
  if [[ -n "$GITHUB_TOKEN" ]]; then
    curl -s "https://api.github.com/search/code?q=$DOMAIN+in:file&per_page=100" \
      -H "Authorization: token $GITHUB_TOKEN" \
      -H "Accept: application/vnd.github.v3+json" 2>/dev/null | \
      grep -oP "[a-zA-Z0-9._-]+\.${DOMAIN_REGEX}" | sort -u > "$D/github.txt" || true
    # Also search commits and issues
    for type in commits issues; do
      curl -s "https://api.github.com/search/$type?q=$DOMAIN&per_page=100" \
        -H "Authorization: token $GITHUB_TOKEN" 2>/dev/null | \
        grep -oP "[a-zA-Z0-9._-]+\.${DOMAIN_REGEX}" | \
        sort -u >> "$D/github.txt" || true
    done
  else
    curl -s "https://api.github.com/search/code?q=$DOMAIN+in:file&per_page=100" \
      2>/dev/null | grep -oP "[a-zA-Z0-9._-]+\.${DOMAIN_REGEX}" | \
      sort -u > "$D/github.txt" || true
  fi

  log_info "[14/20] Shodan..."
  if [[ -n "$SHODAN_API_KEY" ]]; then
    curl -s "https://api.shodan.io/dns/domain/$DOMAIN?key=$SHODAN_API_KEY" \
      2>/dev/null | jq -r '.subdomains[]' 2>/dev/null | \
      awk -v d=".$DOMAIN" '{print $0d}' | \
      sort -u > "$D/shodan.txt" || true
    # Shodan search for IPs
    curl -s "https://api.shodan.io/shodan/host/search?key=$SHODAN_API_KEY&query=hostname:$DOMAIN&facets=ip" \
      2>/dev/null | jq -r '.matches[].hostnames[]' 2>/dev/null | \
      grep -E "\.${DOMAIN_REGEX}$" >> "$D/shodan.txt" || true
  fi

  log_info "[15/20] Censys..."
  if [[ -n "$CENSYS_API_ID" ]]; then
    curl -s "https://search.censys.io/api/v2/certificates/search" \
      -u "$CENSYS_API_ID:$CENSYS_API_SECRET" \
      -H "Content-Type: application/json" \
      -d "{\"q\":\"$DOMAIN\",\"per_page\":100}" 2>/dev/null | \
      jq -r '.result.hits[].parsed.names[]' 2>/dev/null | \
      grep -E "\.${DOMAIN_REGEX}$" | sed 's/\*\.//g' | \
      sort -u > "$D/censys.txt" || true
  fi

  log_info "[16/20] Chaos (ProjectDiscovery)..."
  if [[ -n "$CHAOS_KEY" ]]; then
    curl -s "https://dns.projectdiscovery.io/dns/$DOMAIN/subdomains" \
      -H "Authorization: $CHAOS_KEY" 2>/dev/null | \
      jq -r '.subdomains[]' 2>/dev/null | \
      awk -v d=".$DOMAIN" '{print $0d}' | \
      sort -u > "$D/chaos.txt" || true
  fi

  log_info "[17/20] ASN → IP ranges → Reverse DNS..."
  IP=$(dig +short A "$DOMAIN" 2>/dev/null | head -1)
  if [[ -n "$IP" ]]; then
    ASN=$(curl -s "https://ipinfo.io/$IP/org" 2>/dev/null | grep -oP 'AS\d+' | head -1)
    if [[ -n "$ASN" ]]; then
      log_info "ASN: $ASN — fetching IP ranges..."
      curl -s "https://api.bgpview.io/asn/${ASN//AS/}/prefixes" 2>/dev/null | \
        jq -r '.data.ipv4_prefixes[].prefix' 2>/dev/null | \
        head -5 | while read -r cidr; do
          if cmd_exists nmap; then
            nmap -sn "$cidr" --open 2>/dev/null | \
              grep -oP '\d+\.\d+\.\d+\.\d+' | while read -r rip; do
              PTR=$(dig +short -x "$rip" 2>/dev/null | head -1)
              echo "$PTR" | grep -E "\.${DOMAIN_REGEX}$" >> "$D/asn_reverse.txt" || true
            done
          fi
        done
    fi
  fi

  log_info "[18/20] Favicon hash → Shodan/Censys correlate..."
  if [[ -n "$SHODAN_API_KEY" ]]; then
    FAVICON_URL="https://$DOMAIN/favicon.ico"
    FAVICON_DATA=$(curl -sk --max-time 10 "$FAVICON_URL" 2>/dev/null | base64 -w0 2>/dev/null)
    if [[ -n "$FAVICON_DATA" ]]; then
      FAVICON_HASH=$(python3 -c "
import mmh3, base64, sys
data = base64.b64decode('$FAVICON_DATA')
print(mmh3.hash(data))
" 2>/dev/null || echo "")
      if [[ -n "$FAVICON_HASH" ]]; then
        curl -s "https://api.shodan.io/shodan/host/search?key=$SHODAN_API_KEY&query=http.favicon.hash:$FAVICON_HASH" \
          2>/dev/null | jq -r '.matches[].hostnames[]' 2>/dev/null | \
          grep -E "\.${DOMAIN_REGEX}$" >> "$D/favicon_hash.txt" || true
        log_info "Favicon hash: $FAVICON_HASH"
      fi
    fi
  fi

  # ── ACTIVE: DNS Bruteforce ────────────────────────────

  log_info "[19/20] DNS Bruteforce (puredns + 110k wordlist)..."
  WORDLIST="/tmp/subs_110k.txt"
  if [[ ! -f "$WORDLIST" ]]; then
    wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt" \
      -O "$WORDLIST" 2>/dev/null || \
    wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt" \
      -O "$WORDLIST" 2>/dev/null || true
  fi

  if cmd_exists puredns && [[ -f "$WORDLIST" ]]; then
    safe_run puredns bruteforce "$WORDLIST" "$DOMAIN" \
      -r /tmp/resolvers.txt \
      --write "$D/puredns_brute.txt" \
      --threads "$THREADS"
  elif cmd_exists dnsx && [[ -f "$WORDLIST" ]]; then
    safe_run dnsx -d "$DOMAIN" -w "$WORDLIST" \
      -silent -t "$THREADS" \
      -r 8.8.8.8,1.1.1.1,8.8.4.4,9.9.9.9,208.67.222.222 \
      -o "$D/dnsx_brute.txt"
  fi

  # amass active
  if cmd_exists amass; then
    log_info "amass active (brute)..."
    safe_run amass enum -active -brute -d "$DOMAIN" \
      -o "$D/amass_active.txt" -timeout 20
  fi

  # ── PERMUTATIONS ─────────────────────────────────────

  log_info "[20/20] Permutation generation (dnsgen + gotator + altdns)..."

  PERM_WORDLIST="$D/perm_wordlist.txt"
  local PERM_LIMIT="${PERM_WORDLIST_LIMIT:-5000}"
  local PERM_TMO="${PERM_TIMEOUT:-$TIMEOUT}"

  # First merge what we have
  cat "$D/"*.txt 2>/dev/null | \
    grep -E "^[a-zA-Z0-9._-]+\.${DOMAIN_REGEX}$" | \
    sed 's/\*\.//g' | sort -u > "$D/pre_merge.txt" || true

  if [[ -s "$WORDLIST" ]]; then
    head -n "$PERM_LIMIT" "$WORDLIST" > "$PERM_WORDLIST" 2>/dev/null || cp "$WORDLIST" "$PERM_WORDLIST" 2>/dev/null || true
  fi

  if cmd_exists dnsgen && [[ -s "$D/pre_merge.txt" ]]; then
    safe_run_timeout "$PERM_TMO" dnsgen "$D/pre_merge.txt" | \
      sort -u > "$D/dnsgen_perms.txt"
  fi

  if cmd_exists gotator && [[ -s "$D/pre_merge.txt" && -s "$PERM_WORDLIST" ]]; then
    safe_run_timeout "$PERM_TMO" gotator -sub "$D/pre_merge.txt" -perm "$PERM_WORDLIST" \
      -depth 1 -numbers 3 -mindup -adv -md -silent | \
      sort -u > "$D/gotator_perms.txt"
  fi

  if cmd_exists altdns && [[ -s "$D/pre_merge.txt" && -s "$PERM_WORDLIST" ]]; then
    safe_run_timeout "$PERM_TMO" altdns -i "$D/pre_merge.txt" \
      -w "$PERM_WORDLIST" \
      -o "$D/altdns_perms.txt"
  fi

  # Resolve permutations
  if cmd_exists dnsx; then
    cat "$D/dnsgen_perms.txt" "$D/gotator_perms.txt" "$D/altdns_perms.txt" \
      2>/dev/null | sort -u | \
    dnsx -silent -t "$THREADS" \
      -r 8.8.8.8,1.1.1.1 \
      -o "$D/resolved_perms.txt" 2>/dev/null || true
  fi

  # ── MERGE + RESOLVE ───────────────────────────────────

  log_info "Merging + deduplicating all subdomains..."
  cat "$D/"*.txt 2>/dev/null | \
    grep -E "^[a-zA-Z0-9._-]+\.${DOMAIN_REGEX}$|^${DOMAIN_REGEX}$" | \
    sed 's/\*\.//g' | tr '[:upper:]' '[:lower:]' | \
    grep -v "^#\|^$" | sort -u > "$D/all_subdomains.txt"
  echo "$DOMAIN" >> "$D/all_subdomains.txt"
  sort -u "$D/all_subdomains.txt" -o "$D/all_subdomains.txt"

  TOTAL=$(wc -l < "$D/all_subdomains.txt")
  log_info "Total unique subdomains: ${CYAN}$TOTAL${NC}"

  # ── HTTPX Probe ───────────────────────────────────────

  log_info "Probing live hosts with httpx..."
  if cmd_exists httpx; then
    httpx -l "$D/all_subdomains.txt" \
      -silent -follow-redirects \
      -status-code -title -tech-detect \
      -content-length -server \
      -threads "$THREADS" -timeout "$TIMEOUT" \
      -json -o "$D/httpx_full.json" 2>/dev/null || true

    # Extract live URLs
    jq -r '.url' "$D/httpx_full.json" 2>/dev/null | \
      sort -u > "$D/live.txt" || \
    httpx -l "$D/all_subdomains.txt" -silent \
      -threads "$THREADS" -timeout "$TIMEOUT" \
      -o "$D/live.txt" 2>/dev/null || true

    # Extract tech
    jq -r 'select(.tech!=null) | "\(.url) [\(.tech|join(","))]"' \
      "$D/httpx_full.json" 2>/dev/null > "$D/technologies.txt" || true

    # Interesting status codes
    jq -r 'select(.status_code==403 or .status_code==401) | .url' \
      "$D/httpx_full.json" 2>/dev/null > "$D/forbidden_hosts.txt" || true
  fi

  LIVE=$(wc -l < "$D/live.txt" 2>/dev/null || echo 0)
  log_info "Live hosts: ${GREEN}$LIVE${NC}"
}
