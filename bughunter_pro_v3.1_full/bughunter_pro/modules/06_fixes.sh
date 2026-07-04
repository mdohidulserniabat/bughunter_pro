#!/bin/bash
# ══════════════════════════════════════════════════════
#  FIXES MODULE: Issues #1, #4, #5, #12, #13, #14
#  #1  HTTP Smuggling — proper tools only
#  #4  GitHub — dedicated tools, not raw API
#  #5  Memory/job control — MAX_JOBS semaphore
#  #12 JS DOM sinks — complete list
#  #13 Extra recon sources
#  #14 Modern attack classes
# ══════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════
#  JOB CONTROL — FIXED #5 (memory exhaustion)
#  Wrap heavy tools with semaphore
# ══════════════════════════════════════════════════════
MAX_JOBS="${MAX_JOBS:-3}"
_job_count=0

run_controlled() {
  # Simple job semaphore — waits if MAX_JOBS active
  while [[ $(jobs -r | wc -l) -ge $MAX_JOBS ]]; do
    sleep 2
  done
  "$@" &
}

wait_all_jobs() {
  wait
  _job_count=0
}

# ══════════════════════════════════════════════════════
#  HTTP SMUGGLING — FIXED #1
#  Use proper tools: smuggler.py, h2csmuggler, desyncer
#  Removed broken manual curl approach
# ══════════════════════════════════════════════════════
mod_smuggling() {
  log_section "MOD: HTTP Request Smuggling (Proper Tools)"
  local SM="$OUTPUT_DIR/vulns/smuggling"
  mkdir -p "$SM"
  local LIVE="$OUTPUT_DIR/subdomains/live.txt"
  [[ ! -f "$LIVE" ]] && return

  # 1. smuggler.py — CL.TE / TE.CL / TE.TE detection
  if cmd_exists smuggler; then
    log_info "smuggler.py (CL.TE / TE.CL / TE.TE)..."
    head -10 "$LIVE" | while read -r url; do
      safe_run smuggler -u "$url" \
        -t "$THREADS" \
        --no-color 2>/dev/null >> "$SM/smuggler.txt" || true
    done
  else
    log_warn "smuggler not found — install: pip3 install requests && git clone github.com/defparam/smuggler"
  fi

  # 2. h2csmuggler — HTTP/2 cleartext upgrade smuggling
  if cmd_exists h2csmuggler; then
    log_info "h2csmuggler (HTTP/2 smuggling)..."
    head -10 "$LIVE" | while read -r url; do
      safe_run h2csmuggler \
        --wordlist /tmp/api_clean.txt \
        "$url" 2>/dev/null >> "$SM/h2c.txt" || true
    done
  else
    log_warn "h2csmuggler not found — install: pip3 install h2 && git clone github.com/BishopFox/h2csmuggler"
  fi

  # 3. http-request-smuggler nuclei templates
  if cmd_exists nuclei; then
    log_info "nuclei smuggling templates..."
    safe_run nuclei -l "$LIVE" \
      -tags smuggling \
      -silent -c "$THREADS" \
      -o "$SM/nuclei_smuggling.txt" 2>/dev/null || true
  fi

  log_info "Smuggling scan done. Manual verification needed for any findings."
}

# ══════════════════════════════════════════════════════
#  GITHUB RECON — FIXED #4
#  Use dedicated tools instead of raw API
# ══════════════════════════════════════════════════════
mod_github_recon() {
  log_section "MOD: GitHub Recon (Dedicated Tools)"
  local GH="$OUTPUT_DIR/recon/github"
  mkdir -p "$GH"

  # 1. github-subdomains — purpose-built subdomain finder
  if cmd_exists github-subdomains; then
    log_info "github-subdomains..."
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
      safe_run github-subdomains -d "$DOMAIN" \
        -t "$GITHUB_TOKEN" \
        -o "$GH/github_subdomains.txt" 2>/dev/null || true
    else
      safe_run github-subdomains -d "$DOMAIN" \
        -o "$GH/github_subdomains.txt" 2>/dev/null || true
    fi
    # Merge into main subdomain list
    [[ -f "$GH/github_subdomains.txt" ]] && \
      cat "$GH/github_subdomains.txt" >> \
        "$OUTPUT_DIR/subdomains/all_subdomains.txt" 2>/dev/null || true
  else
    log_warn "github-subdomains not found — install: go install github.com/gwen001/github-subdomains@latest"
  fi

  # 2. trufflehog github org scan
  if cmd_exists trufflehog; then
    log_info "trufflehog GitHub org/user scan..."
    ORG=$(echo "$DOMAIN" | cut -d'.' -f1)
    safe_run trufflehog github \
      --org="$ORG" \
      --json \
      --no-verification \
      2>/dev/null | head -200 > "$GH/trufflehog_github.json" || true

    HITS=$(grep -c "Raw" "$GH/trufflehog_github.json" 2>/dev/null || echo 0)
    [[ "$HITS" -gt 0 ]] && log_finding "trufflehog GitHub: $HITS secrets found"
  fi

  # 3. gitdorks_go — GitHub dork search
  if cmd_exists gitdorks_go; then
    log_info "gitdorks_go..."
    safe_run gitdorks_go -gd /tmp/gitdorks.txt \
      -org "$DOMAIN" \
      -nws 2>/dev/null > "$GH/gitdorks.txt" || true
  fi

  # 4. gitleaks on any cloned repos found
  if cmd_exists gitleaks && [[ -d "$GH/repos" ]]; then
    log_info "gitleaks on cloned repos..."
    safe_run gitleaks detect \
      --source "$GH/repos" \
      -r "$GH/gitleaks.json" \
      --no-banner 2>/dev/null || true
  fi
}

# ══════════════════════════════════════════════════════
#  JS ANALYSIS — FIXED #12
#  Complete DOM sink list + postMessage + prototype pollution
# ══════════════════════════════════════════════════════
mod_js_deep() {
  log_section "MOD: Deep JS Analysis (Complete DOM Sink List)"
  local J="$OUTPUT_DIR/vulns/js"
  mkdir -p "$J"
  local JS_FILES="$OUTPUT_DIR/urls/js_files.txt"
  [[ ! -f "$JS_FILES" ]] && return

  # FIXED #12: Complete DOM XSS sink list
  declare -A DOM_SINKS=(
    # Direct write sinks
    ["innerHTML"]="\.innerHTML\s*="
    ["outerHTML"]="\.outerHTML\s*="
    ["insertAdjacentHTML"]="\.insertAdjacentHTML\s*\("
    ["document.write"]="document\.write\s*\("
    ["document.writeln"]="document\.writeln\s*\("
    # Execution sinks
    ["eval"]="[^a-zA-Z]eval\s*\("
    ["setTimeout_str"]="setTimeout\s*\(\s*['\`\"]"
    ["setInterval_str"]="setInterval\s*\(\s*['\`\"]"
    ["Function_constructor"]="new\s+Function\s*\("
    ["execScript"]="execScript\s*\("
    # Navigation sinks
    ["location_href"]="location\.href\s*="
    ["location_assign"]="location\.assign\s*\("
    ["location_replace"]="location\.replace\s*\("
    ["location_hash"]="location\.hash"
    ["window_open"]="window\.open\s*\("
    # Source → sink patterns
    ["document_URL"]="document\.URL"
    ["document_documentURI"]="document\.documentURI"
    ["document_baseURI"]="document\.baseURI"
    ["location_search"]="location\.search"
    ["window_name"]="window\.name"
    # postMessage
    ["postMessage"]="\.postMessage\s*\("
    ["addEventListener_message"]="addEventListener\s*\(\s*['\"]message['\"]"
    # jQuery sinks
    ["jquery_html"]="\$\([^)]+\)\.html\s*\("
    ["jquery_append"]="\$\([^)]+\)\.append\s*\("
    ["jquery_prepend"]="\$\([^)]+\)\.prepend\s*\("
    ["jquery_after"]="\$\([^)]+\)\.after\s*\("
    ["jquery_before"]="\$\([^)]+\)\.before\s*\("
  )

  # FIXED #12: Complete prototype pollution source/sink list
  declare -A PP_PATTERNS=(
    ["__proto__"]="__proto__\s*\["
    ["constructor_prototype"]="constructor\s*\[\s*['\"]prototype"
    ["Object_assign"]="Object\.assign\s*\("
    ["merge_deep"]="(deepmerge|merge|extend|defaults|lodash\.merge|_\.merge)\s*\("
    ["JSON_parse_assign"]="Object\.assign.*JSON\.parse"
    ["prototype_direct"]="prototype\[.*\]\s*="
    ["Object_create"]="Object\.create\s*\(null\)"
  )

  log_info "Scanning $(wc -l < "$JS_FILES") JS files for sinks..."

  head -300 "$JS_FILES" | while read -r jsurl; do
    CONTENT=$(curl -sk --max-time "$TIMEOUT" "$jsurl" 2>/dev/null)
    [[ -z "$CONTENT" ]] && continue

    # DOM XSS sinks
    for sink_name in "${!DOM_SINKS[@]}"; do
      PATTERN="${DOM_SINKS[$sink_name]}"
      if echo "$CONTENT" | grep -qP "$PATTERN"; then
        LINES=$(echo "$CONTENT" | grep -nP "$PATTERN" | head -2)
        echo "[DOM-XSS:$sink_name] $jsurl" >> "$J/dom_sinks.txt"
        echo "  → $LINES" >> "$J/dom_sinks.txt"
      fi
    done

    # Prototype pollution
    for pp_name in "${!PP_PATTERNS[@]}"; do
      PATTERN="${PP_PATTERNS[$pp_name]}"
      if echo "$CONTENT" | grep -qP "$PATTERN"; then
        echo "[PROTO-POLLUTION:$pp_name] $jsurl" >> "$J/proto_pollution.txt"
      fi
    done

    # postMessage origin check missing
    if echo "$CONTENT" | grep -qP "addEventListener.*message"; then
      if ! echo "$CONTENT" | grep -qP "event\.origin|message\.origin|e\.origin"; then
        log_finding "postMessage without origin check: $jsurl"
        echo "[HIGH] postMessage no origin check: $jsurl" >> "$J/postmessage_no_origin.txt"
      fi
    fi
  done

  DOM_COUNT=$(grep -c "DOM-XSS" "$J/dom_sinks.txt" 2>/dev/null || echo 0)
  PP_COUNT=$(grep -c "PROTO-POLLUTION" "$J/proto_pollution.txt" 2>/dev/null || echo 0)
  log_info "DOM XSS sinks: ${YELLOW}$DOM_COUNT${NC} | Prototype pollution: ${YELLOW}$PP_COUNT${NC}"
}

# ══════════════════════════════════════════════════════
#  EXTRA RECON SOURCES — FIXED #13
#  SecurityTrails, FOFA, ZoomEye, Netlas, LeakIX, etc.
# ══════════════════════════════════════════════════════
mod_extra_recon() {
  log_section "MOD: Extra Recon Sources"
  local D="$OUTPUT_DIR/subdomains"

  # SecurityTrails (needs API key)
  if [[ -n "${SECURITYTRAILS_KEY:-}" ]]; then
    log_info "SecurityTrails..."
    curl -s "https://api.securitytrails.com/v1/domain/$DOMAIN/subdomains" \
      -H "APIKEY: $SECURITYTRAILS_KEY" 2>/dev/null | \
      jq -r '.subdomains[]' 2>/dev/null | \
      awk -v d=".$DOMAIN" '{print $0d}' | \
      sort -u > "$D/securitytrails.txt" || true
    COUNT=$(wc -l < "$D/securitytrails.txt" 2>/dev/null || echo 0)
    log_info "SecurityTrails: $COUNT subdomains"
  else
    log_warn "SECURITYTRAILS_KEY not set — export SECURITYTRAILS_KEY=xxx"
  fi

  # FOFA (needs API key)
  if [[ -n "${FOFA_EMAIL:-}" && -n "${FOFA_KEY:-}" ]]; then
    log_info "FOFA..."
    QUERY=$(echo -n "domain=\"$DOMAIN\"" | base64 -w0 2>/dev/null)
    curl -s "https://fofa.info/api/v1/search/all?email=${FOFA_EMAIL}&key=${FOFA_KEY}&qbase64=${QUERY}&fields=host&page=1&size=1000" \
      2>/dev/null | jq -r '.results[][]' 2>/dev/null | \
      grep -E "\.$DOMAIN$" | sort -u > "$D/fofa.txt" || true
  else
    log_warn "FOFA_EMAIL/FOFA_KEY not set — export FOFA_EMAIL=x FOFA_KEY=x"
  fi

  # ZoomEye (needs API key)
  if [[ -n "${ZOOMEYE_KEY:-}" ]]; then
    log_info "ZoomEye..."
    curl -s "https://api.zoomeye.org/domain/search?q=$DOMAIN&type=1&page=1" \
      -H "API-KEY: $ZOOMEYE_KEY" 2>/dev/null | \
      jq -r '.list[].name' 2>/dev/null | \
      grep -E "\.$DOMAIN$" | sort -u > "$D/zoomeye.txt" || true
  fi

  # Netlas (needs API key)
  if [[ -n "${NETLAS_KEY:-}" ]]; then
    log_info "Netlas..."
    curl -s "https://app.netlas.io/api/domains/?q=*.${DOMAIN}&page=1" \
      -H "X-API-Key: $NETLAS_KEY" 2>/dev/null | \
      jq -r '.items[].data.domain' 2>/dev/null | \
      sort -u > "$D/netlas.txt" || true
  fi

  # LeakIX (free, no key needed for basic)
  log_info "LeakIX..."
  curl -s "https://leakix.net/api/subdomains/$DOMAIN" \
    -H "Accept: application/json" 2>/dev/null | \
    jq -r '.[].subdomain' 2>/dev/null | \
    sort -u > "$D/leakix.txt" || true

  # FullHunt (needs API key)
  if [[ -n "${FULLHUNT_KEY:-}" ]]; then
    log_info "FullHunt..."
    curl -s "https://fullhunt.io/api/v1/domain/$DOMAIN/subdomains" \
      -H "X-API-KEY: $FULLHUNT_KEY" 2>/dev/null | \
      jq -r '.hosts[]' 2>/dev/null | \
      sort -u > "$D/fullhunt.txt" || true
  fi

  # Merge new sources into main list
  cat "$D/securitytrails.txt" "$D/fofa.txt" "$D/zoomeye.txt" \
      "$D/netlas.txt" "$D/leakix.txt" "$D/fullhunt.txt" 2>/dev/null | \
    grep -E "\.$DOMAIN$" | sort -u >> "$D/all_subdomains.txt" || true
  sort -u "$D/all_subdomains.txt" -o "$D/all_subdomains.txt" 2>/dev/null || true

  log_info "Extra recon sources merged."
}

# ══════════════════════════════════════════════════════
#  MODERN ATTACKS — FIXED #14
#  Cache deception, race condition, WebSocket,
#  OAuth, SAML, CSP bypass, HTTP/2 desync
# ══════════════════════════════════════════════════════
mod_modern_attacks() {
  log_section "MOD: Modern Attack Classes"
  local MA="$OUTPUT_DIR/vulns/modern"
  mkdir -p "$MA"
  local LIVE="$OUTPUT_DIR/subdomains/live.txt"
  [[ ! -f "$LIVE" ]] && return

  # ── Web Cache Deception ──────────────────────────────
  log_info "Web Cache Deception..."
  # Append static extension to authenticated path
  CACHE_EXTS=(".css" ".jpg" ".png" ".js" ".ico" ".woff")
  head -10 "$LIVE" | while IFS= read -r url; do
    for auth_path in "/account" "/profile" "/dashboard" "/settings" "/api/me"; do
      for ext in "${CACHE_EXTS[@]}"; do
        TARGET="${url}${auth_path}/test${ext}"
        # Request 1 (unauthenticated)
        RESP1=$(curl -sk --max-time "$TIMEOUT" "$TARGET" 2>/dev/null)
        # Check if sensitive data returned
        if echo "$RESP1" | grep -qiE '"email"|"user"|"account"|"profile"|"token"'; then
          log_finding "Web Cache Deception: $TARGET"
          echo "[HIGH] $TARGET" >> "$MA/cache_deception.txt"
        fi
      done
    done
  done

  # ── Race Condition ───────────────────────────────────
  log_info "Race Condition (parallel requests)..."
  # Send 20 simultaneous requests to state-changing endpoints
  head -5 "$LIVE" | while IFS= read -r url; do
    for endpoint in "/api/redeem" "/api/coupon" "/api/vote" \
                    "/api/transfer" "/api/purchase" "/api/claim"; do
      TARGET="$url$endpoint"
      STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
        --max-time 3 "$TARGET" 2>/dev/null)
      if [[ "$STATUS" =~ ^(200|201|400|422) ]]; then
        log_info "Race condition candidate: $TARGET"
        echo "[CANDIDATE] $TARGET" >> "$MA/race_condition_candidates.txt"
        # Send 15 parallel requests
        for i in $(seq 1 15); do
          curl -sk -o /dev/null -X POST \
            --max-time 5 "$TARGET" &
        done
        wait
        echo "[TESTED] $TARGET — check application state manually" >> "$MA/race_condition_tested.txt"
      fi
    done
  done

  # ── WebSocket Testing ────────────────────────────────
  log_info "WebSocket endpoint detection..."
  head -15 "$LIVE" | while IFS= read -r url; do
    # Detect WebSocket upgrade endpoints
    WS_URL=$(echo "$url" | sed 's/https/wss/;s/http/ws/')
    for ws_path in "/ws" "/websocket" "/socket" "/socket.io" \
                   "/cable" "/actioncable" "/hub" "/signalr"; do
      RESP=$(curl -sk --max-time "$TIMEOUT" \
        -H "Upgrade: websocket" \
        -H "Connection: Upgrade" \
        -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
        -H "Sec-WebSocket-Version: 13" \
        "${url}${ws_path}" 2>/dev/null)
      STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
        -H "Upgrade: websocket" \
        -H "Connection: Upgrade" \
        -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
        -H "Sec-WebSocket-Version: 13" \
        --max-time "$TIMEOUT" "${url}${ws_path}" 2>/dev/null)
      if [[ "$STATUS" == "101" || "$STATUS" == "200" ]]; then
        log_finding "WebSocket found: ${url}${ws_path}"
        echo "[INFO] WebSocket: ${WS_URL}${ws_path}" >> "$MA/websockets.txt"
      fi
    done
    # Check page source for WebSocket usage
    HTML=$(curl -sk --max-time "$TIMEOUT" "$url" 2>/dev/null)
    echo "$HTML" | grep -qiE "new WebSocket|io\.connect|socket\.connect" && \
      echo "[INFO] WebSocket usage detected: $url" >> "$MA/websockets.txt" || true
  done

  # ── OAuth Testing ────────────────────────────────────
  log_info "OAuth misconfiguration testing..."
  head -10 "$LIVE" | while IFS= read -r url; do
    # Discover OAuth endpoints
    for oauth_path in "/oauth" "/oauth2" "/oauth/authorize" \
                      "/auth/oauth" "/api/oauth" "/.well-known/openid-configuration"; do
      RESP=$(curl -sk --max-time "$TIMEOUT" "${url}${oauth_path}" 2>/dev/null)
      if echo "$RESP" | grep -qiE "client_id|response_type|authorization_endpoint|token_endpoint"; then
        echo "[INFO] OAuth endpoint: ${url}${oauth_path}" >> "$MA/oauth_endpoints.txt"

        # Check for redirect_uri validation bypass
        for redir in "https://evil.com" "https://${DOMAIN}.evil.com" \
                     "https://evil.com%40${DOMAIN}" "https://${DOMAIN}%0d%0aLocation:https://evil.com"; do
          TEST_URL="${url}${oauth_path}?response_type=code&client_id=test&redirect_uri=${redir}"
          TEST_RESP=$(curl -sk -I --max-time "$TIMEOUT" \
            --max-redirs 0 "$TEST_URL" 2>/dev/null)
          if echo "$TEST_RESP" | grep -qi "location:.*evil.com"; then
            log_finding "OAuth redirect_uri bypass: ${url}${oauth_path}"
            echo "[CRITICAL] redirect_uri bypass: ${url}${oauth_path}" >> "$MA/oauth_bypass.txt"
          fi
        done
      fi
    done
  done

  # ── SAML Testing ─────────────────────────────────────
  log_info "SAML endpoint detection..."
  head -10 "$LIVE" | while IFS= read -r url; do
    for saml_path in "/saml" "/saml2" "/sso/saml" "/auth/saml" \
                     "/api/saml" "/saml/metadata" "/saml/consume"; do
      STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
        --max-time "$TIMEOUT" "${url}${saml_path}" 2>/dev/null)
      if [[ "$STATUS" =~ ^(200|302|400|500) ]]; then
        echo "[INFO] SAML endpoint: ${url}${saml_path} [$STATUS]" >> "$MA/saml_endpoints.txt"
        # Check for XML signature wrapping (XXE + signature bypass)
        SAML_RESP=$(curl -sk --max-time "$TIMEOUT" "${url}${saml_path}" 2>/dev/null)
        echo "$SAML_RESP" | grep -qi "SAMLResponse\|<saml\|Assertion" && \
          echo "[CHECK] SAML response present at ${url}${saml_path}" >> "$MA/saml_endpoints.txt" || true
      fi
    done
  done

  # ── CSP Analysis & Bypass ────────────────────────────
  log_info "CSP analysis & bypass opportunities..."
  head -20 "$LIVE" | while IFS= read -r url; do
    CSP=$(curl -sk -I --max-time "$TIMEOUT" "$url" 2>/dev/null | \
      grep -i "content-security-policy:" | head -1)
    [[ -z "$CSP" ]] && { echo "[MISSING] No CSP: $url" >> "$MA/csp_analysis.txt"; continue; }

    # Check for unsafe directives
    echo "$CSP" | grep -qi "unsafe-inline" && \
      echo "[HIGH] unsafe-inline CSP: $url" >> "$MA/csp_bypass.txt"
    echo "$CSP" | grep -qi "unsafe-eval" && \
      echo "[HIGH] unsafe-eval CSP: $url" >> "$MA/csp_bypass.txt"
    echo "$CSP" | grep -qi "\*" && \
      echo "[HIGH] Wildcard CSP: $url" >> "$MA/csp_bypass.txt"
    # data: URI bypass
    echo "$CSP" | grep -qi "data:" && \
      echo "[MEDIUM] data: allowed in CSP: $url" >> "$MA/csp_bypass.txt"
    # CDN bypass (cdn.jsdelivr.net, cdnjs.cloudflare.com allow XSS)
    for bypass_cdn in "cdn.jsdelivr.net" "cdnjs.cloudflare.com" \
                       "ajax.googleapis.com" "unpkg.com"; do
      echo "$CSP" | grep -qi "$bypass_cdn" && \
        echo "[MEDIUM] CSP bypass via $bypass_cdn: $url" >> "$MA/csp_bypass.txt"
    done
    echo "[INFO] $url | $CSP" >> "$MA/csp_analysis.txt"
  done

  # ── HTTP/2 Desync ────────────────────────────────────
  log_info "HTTP/2 desync (h2csmuggler)..."
  if cmd_exists h2csmuggler; then
    head -5 "$LIVE" | while read -r url; do
      safe_run h2csmuggler \
        --wordlist /tmp/api_clean.txt \
        "$url" 2>/dev/null >> "$MA/h2_desync.txt" || true
    done
  fi

  log_info "Modern attack modules complete!"
  log_info "WebSockets: $(wc -l < "$MA/websockets.txt" 2>/dev/null || echo 0) found"
  log_info "OAuth endpoints: $(wc -l < "$MA/oauth_endpoints.txt" 2>/dev/null || echo 0) found"
  log_info "CSP issues: $(wc -l < "$MA/csp_bypass.txt" 2>/dev/null || echo 0) found"
}

# ══════════════════════════════════════════════════════
#  WAF Detection — bonus
# ══════════════════════════════════════════════════════
mod_waf() {
  log_section "MOD: WAF Detection & Basic Bypass"
  local W="$OUTPUT_DIR/vulns/waf"
  mkdir -p "$W"
  local LIVE="$OUTPUT_DIR/subdomains/live.txt"
  [[ ! -f "$LIVE" ]] && return

  # wafw00f
  if cmd_exists wafw00f; then
    log_info "wafw00f detection..."
    head -20 "$LIVE" | while read -r url; do
      safe_run wafw00f "$url" \
        -o "$W/wafw00f_$(echo "$url" | md5sum | cut -c1-8).txt" \
        -f text 2>/dev/null || true
    done
    cat "$W"/wafw00f_*.txt 2>/dev/null | sort -u > "$W/waf_summary.txt" || true
  else
    log_warn "wafw00f not found — install: pip3 install wafw00f"
    # Manual WAF detection
    head -10 "$LIVE" | while IFS= read -r url; do
      RESP=$(curl -sk -I --max-time "$TIMEOUT" \
        -H "X-Forwarded-For: 1.1.1.1" \
        "${url}/?test=<script>alert(1)</script>" 2>/dev/null)
      for waf_sig in "cloudflare" "akamai" "sucuri" "imperva" \
                     "barracuda" "f5" "aws-waf" "incapsula"; do
        echo "$RESP" | grep -qi "$waf_sig" && \
          echo "[WAF] $url → $waf_sig" >> "$W/waf_summary.txt" || true
      done
    done
  fi

  if [[ -s "$W/waf_summary.txt" ]]; then
    log_info "WAFs detected: $(sort -u "$W/waf_summary.txt" | wc -l)"
  fi
}
