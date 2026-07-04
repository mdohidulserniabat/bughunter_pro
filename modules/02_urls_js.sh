#!/bin/bash
# ══════════════════════════════════════════════════════
#  MOD 02: URL Collection (passive + active + SPA-aware)
#  MOD 03: Deep JavaScript Analysis (JSluice + cariddi)
# ══════════════════════════════════════════════════════

mod_urls() {
  log_section "MOD 02: URL Collection"
  local U="$OUTPUT_DIR/urls"
  local LIVE="$OUTPUT_DIR/subdomains/live.txt"
  [[ ! -f "$LIVE" ]] && return

  # ── Passive ──────────────────────────────────────────

  log_info "waybackurls..."
  if cmd_exists waybackurls; then
    sed 's|https\?://||' "$LIVE" 2>/dev/null | \
      safe_run waybackurls | sort -u > "$U/wayback.txt" || true
  else
    curl -s "http://web.archive.org/cdx/search/cdx?url=*.$DOMAIN/*&output=text&fl=original&collapse=urlkey&limit=100000" \
      2>/dev/null | sort -u > "$U/wayback.txt" || true
  fi

  log_info "gau (getallurls)..."
  if cmd_exists gau; then
    safe_run gau --threads "$THREADS" \
      --providers wayback,commoncrawl,otx,urlscan \
      --subs "$DOMAIN" | sort -u > "$U/gau.txt" || true
  fi

  log_info "urlscan.io URLs..."
  curl -s "https://urlscan.io/api/v1/search/?q=domain:$DOMAIN&size=10000" \
    2>/dev/null | jq -r '.results[].page.url' 2>/dev/null | \
    sort -u > "$U/urlscan.txt" || true

  # ── Active crawlers ───────────────────────────────────

  log_info "katana (JS-aware)..."
  if cmd_exists katana; then
    safe_run katana -list "$LIVE" \
      -jc -jsl -kf all -d 5 -c "$THREADS" \
      -timeout "$TIMEOUT" -aff \
      -ef woff,css,png,svg,jpg,woff2,jpeg,gif,ico,ttf,eot \
      -o "$U/katana.txt"
  fi

  log_info "gospider..."
  if cmd_exists gospider; then
    safe_run gospider -S "$LIVE" \
      -c "$THREADS" -d 4 \
      --include-subs \
      -o "$U/gospider_dir" 2>/dev/null
    find "$U/gospider_dir" -type f 2>/dev/null | \
      xargs cat 2>/dev/null | \
      grep -oP 'https?://[^\s"'"'"'>]+' | \
      sort -u > "$U/gospider.txt" || true
  fi

  log_info "hakrawler..."
  if cmd_exists hakrawler; then
    cat "$LIVE" | safe_run hakrawler -d 4 -t "$THREADS" -insecure | \
      sort -u > "$U/hakrawler.txt" || true
  fi

  log_info "cariddi (endpoint + secret extractor)..."
  if cmd_exists cariddi; then
    safe_run cariddi -l "$LIVE" \
      -s -e -ext 1 \
      -c "$THREADS" \
      -o "$U/cariddi.txt" 2>/dev/null || true
  fi

  # ── Next.js / React specific ──────────────────────────

  log_info "Next.js / React route discovery..."
  while IFS= read -r url; do
    H="${url%/}"

    # Build manifest → all routes
    for manifest in \
      "_next/static/development/_buildManifest.js" \
      "_next/static/production/_buildManifest.js" \
      "_next/static/chunks/pages/_app.js"; do
      DATA=$(curl -sk --max-time "$TIMEOUT" "$H/$manifest" 2>/dev/null)
      echo "$DATA" | grep -oP '"(/[^"]*)"' | \
        tr -d '"' >> "$U/nextjs_routes.txt" 2>/dev/null || true
    done

    # __NEXT_DATA__ embedded JSON (SSR props)
    HTML=$(curl -sk --max-time "$TIMEOUT" "$H" 2>/dev/null)
    echo "$HTML" | grep -oP '(?<=__NEXT_DATA__" type="application/json">)[^<]+' | \
      jq -r '.props,.buildId,.page,.query' 2>/dev/null >> "$U/nextjs_data.txt" || true

    # React router routes from JS
    echo "$HTML" | grep -oP '"path"\s*:\s*"(/[^"]*)"' | \
      grep -oP '"(/[^"]*)"' | tr -d '"' >> "$U/react_routes.txt" 2>/dev/null || true

  done < <(head -15 "$LIVE") 2>/dev/null || true

  # ── Merge ─────────────────────────────────────────────

  cat "$U/"*.txt 2>/dev/null | \
    grep -E "^https?://" | sort -u > "$U/all_urls.txt"

  TOTAL=$(wc -l < "$U/all_urls.txt" 2>/dev/null || echo 0)
  log_info "Total URLs: ${CYAN}$TOTAL${NC}"

  # JS files list
  grep -iE "\.js(\?|$)" "$U/all_urls.txt" 2>/dev/null | \
    sort -u > "$U/js_files.txt" || true

  # GF patterns
  if cmd_exists gf; then
    log_info "GF pattern extraction..."
    for p in xss sqli ssrf redirect lfi rce idor debug ssti interestingparams aws-keys; do
      safe_run gf "$p" "$U/all_urls.txt" | sort -u > "$U/gf_${p}.txt" || true
    done
  fi

  # Parameter discovery
  log_info "paramspider..."
  if cmd_exists paramspider; then
    safe_run paramspider -d "$DOMAIN" \
      --level high --subs \
      -o "$U/paramspider.txt" 2>/dev/null || true
  fi

  log_info "arjun (hidden parameter discovery)..."
  if cmd_exists arjun; then
    head -10 "$LIVE" | while read -r target; do
      safe_run arjun -u "$target" \
        -t "$THREADS" --stable \
        -oJ "$U/arjun_$(echo "$target" | md5sum | cut -c1-8).json" 2>/dev/null || true
    done
  fi

  # Merge discovered params
  grep -oP '\?[^#\s]+' "$U/all_urls.txt" 2>/dev/null | \
    tr '&' '\n' | grep '=' | cut -d'=' -f1 | \
    sed 's/^\?//' | sort -u > "$U/unique_params.txt" || true

  log_info "Unique params: $(wc -l < "$U/unique_params.txt" 2>/dev/null || echo 0)"
}

# ══════════════════════════════════════════════════════
#  MOD 03: Deep JavaScript Analysis
# ══════════════════════════════════════════════════════

mod_js_analysis() {
  log_section "MOD 03: Deep JavaScript Analysis"
  local J="$OUTPUT_DIR/vulns/js"
  local JS_FILES="$OUTPUT_DIR/urls/js_files.txt"
  [[ ! -f "$JS_FILES" ]] && return

  TOTAL_JS=$(wc -l < "$JS_FILES" 2>/dev/null || echo 0)
  log_info "Analyzing $TOTAL_JS JavaScript files..."

  # ── JSluice (Burp author's JS analysis) ──────────────

  if cmd_exists jsluice; then
    log_info "JSluice analysis..."
    head -300 "$JS_FILES" | while read -r jsurl; do
      curl -sk --max-time "$TIMEOUT" "$jsurl" 2>/dev/null | \
        jsluice urls 2>/dev/null >> "$J/jsluice_urls.txt" || true
      curl -sk --max-time "$TIMEOUT" "$jsurl" 2>/dev/null | \
        jsluice secrets 2>/dev/null >> "$J/jsluice_secrets.txt" || true
    done
  fi

  # ── Source Map Analysis ───────────────────────────────

  log_info "Source map detection..."
  head -200 "$JS_FILES" | while read -r jsurl; do
    MAP_URL="${jsurl}.map"
    STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
      --max-time "$TIMEOUT" "$MAP_URL" 2>/dev/null)
    if [[ "$STATUS" == "200" ]]; then
      log_finding "Source map exposed: $MAP_URL"
      echo "[HIGH] $MAP_URL" >> "$J/sourcemaps.txt"
      # Extract original sources
      curl -sk --max-time "$TIMEOUT" "$MAP_URL" 2>/dev/null | \
        jq -r '.sources[]' 2>/dev/null >> "$J/sourcemap_sources.txt" || true
      # Extract source content (original code)
      curl -sk --max-time "$TIMEOUT" "$MAP_URL" 2>/dev/null | \
        jq -r '.sourcesContent[]' 2>/dev/null | head -200 >> "$J/sourcemap_content.txt" || true
    fi
  done

  # ── DOM XSS Pattern Detection ─────────────────────────

  log_info "DOM XSS sink detection..."
  DOM_SINKS=(
    "document\.write" "innerHTML" "outerHTML" "insertAdjacentHTML"
    "eval\(" "setTimeout.*user" "setInterval.*user"
    "location\.href\s*=" "location\.replace\s*\(" "location\.assign\s*\("
    "document\.URL" "document\.documentURI" "document\.baseURI"
    "location\.hash" "location\.search" "window\.name"
  )

  head -200 "$JS_FILES" | while read -r jsurl; do
    CONTENT=$(curl -sk --max-time "$TIMEOUT" "$jsurl" 2>/dev/null)
    for sink in "${DOM_SINKS[@]}"; do
      if echo "$CONTENT" | grep -qE "$sink"; then
        MATCHES=$(echo "$CONTENT" | grep -nE "$sink" | head -3)
        log_finding "DOM XSS sink [$sink]: $jsurl"
        echo "[DOM-XSS] $jsurl | sink: $sink" >> "$J/dom_xss_sinks.txt"
        echo "  → $MATCHES" >> "$J/dom_xss_sinks.txt"
      fi
    done
  done

  # ── Prototype Pollution Sources ───────────────────────

  log_info "Prototype pollution source detection..."
  PP_SOURCES=(
    "__proto__" "constructor\[prototype\]" "Object\.prototype"
    "prototype\[" "\.prototype\." "merge\(" "extend\(" "clone\("
  )
  head -200 "$JS_FILES" | while read -r jsurl; do
    CONTENT=$(curl -sk --max-time "$TIMEOUT" "$jsurl" 2>/dev/null)
    for src in "${PP_SOURCES[@]}"; do
      if echo "$CONTENT" | grep -qE "$src"; then
        echo "[PP-SOURCE] $jsurl | $src" >> "$J/prototype_pollution_sources.txt"
      fi
    done
  done

  # ── Hardcoded Secrets in JS ───────────────────────────

  log_info "Secret extraction from JS files..."
  declare -A JS_SECRETS=(
    ["AWS_KEY"]="AKIA[0-9A-Z]{16}"
    ["GOOGLE_KEY"]="AIza[0-9A-Za-z\\-_]{35}"
    ["GITHUB_TOKEN"]="ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}"
    ["STRIPE"]="sk_live_[0-9a-zA-Z]{24}"
    ["FIREBASE"]="AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"
    ["JWT"]="eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+"
    ["SLACK"]="xox[baprs]-[0-9A-Za-z-]+"
    ["GENERIC_SECRET"]="(secret|password|passwd|token|apikey|api_key|private_key)[\"']?\\s*[:=]\\s*[\"'][A-Za-z0-9+/=_\\-]{8,}"
    ["SENDGRID"]="SG\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9_-]{43}"
    ["TWILIO"]="SK[0-9a-fA-F]{32}"
    ["NPM"]="npm_[A-Za-z0-9]{36}"
    ["PRIVATE_KEY"]="-----BEGIN (RSA |EC )?PRIVATE KEY"
    ["MONGODB"]="mongodb(\\+srv)?://[^\\s\"']+"
    ["MYSQL"]="mysql://[^\\s\"']+"
  )

  head -300 "$JS_FILES" | while read -r jsurl; do
    CONTENT=$(curl -sk --max-time "$TIMEOUT" "$jsurl" 2>/dev/null)
    for name in "${!JS_SECRETS[@]}"; do
      MATCH=$(echo "$CONTENT" | grep -oP "${JS_SECRETS[$name]}" 2>/dev/null | head -3)
      if [[ -n "$MATCH" ]]; then
        log_finding "[$name] secret in JS: $jsurl"
        echo "[SECRET:$name] $jsurl | $MATCH" >> "$J/js_secrets.txt"
      fi
    done
  done

  # ── Endpoint Extraction from JS ───────────────────────

  log_info "Endpoint extraction from JS..."
  head -300 "$JS_FILES" | while read -r jsurl; do
    CONTENT=$(curl -sk --max-time "$TIMEOUT" "$jsurl" 2>/dev/null)
    # REST endpoints
    echo "$CONTENT" | \
      grep -oP '["'"'"'`](/api/[a-zA-Z0-9/_.-]{2,100})["'"'"'`]' | \
      tr -d '"'"'"'`' | sort -u >> "$J/js_endpoints.txt" || true
    # GraphQL queries/mutations
    echo "$CONTENT" | \
      grep -oP '(query|mutation)\s+[A-Z][a-zA-Z]+' | \
      sort -u >> "$J/graphql_operations.txt" || true
  done

  sort -u "$J/js_endpoints.txt" -o "$J/js_endpoints.txt" 2>/dev/null || true
  ENDPOINTS=$(wc -l < "$J/js_endpoints.txt" 2>/dev/null || echo 0)
  log_info "JS endpoints found: ${CYAN}$ENDPOINTS${NC}"
}
