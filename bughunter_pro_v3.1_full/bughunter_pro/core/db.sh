#!/bin/bash
# SQLite helpers for asset persistence.

bh_db_sqlite_available() {
  command -v sqlite3 &>/dev/null
}

bh_sql_escape() {
  printf '%s' "$1" | sed "s/'/''/g"
}

bh_db_init() {
  bh_db_sqlite_available || { bh_log_warn "sqlite3 not found; DB features disabled"; return 1; }
  mkdir -p "$(dirname "$BH_DB_FILE")"
  sqlite3 "$BH_DB_FILE" < "$SCRIPT_DIR/db/assets_schema.sql" >/dev/null 2>&1 || return 1
  bh_db_apply_migrations
  return 0
}

bh_db_apply_migrations() {
  bh_db_sqlite_available || return 0
  local migration
  for migration in "$SCRIPT_DIR/db/migrations/"*.sql; do
    [[ -f "$migration" ]] || continue
    sqlite3 "$BH_DB_FILE" < "$migration" >/dev/null 2>&1 || true
  done
}

bh_db_exec() {
  bh_db_sqlite_available || return 0
  sqlite3 "$BH_DB_FILE" "$@"
}

bh_db_insert_scan() {
  bh_db_sqlite_available || return 0
  local started_at="$(bh_timestamp)"
  local domain_esc output_esc profile_esc resume_esc memory_esc cpu_esc
  domain_esc="$(bh_sql_escape "$DOMAIN")"
  output_esc="$(bh_sql_escape "$OUTPUT_DIR")"
  profile_esc="$(bh_sql_escape "${BH_MEMORY_PROFILE:-}")"
  resume_esc="$(bh_sql_escape "${BH_LAST_STEP:-}")"
  memory_esc="$(bh_sql_escape "${BH_MEMORY_LIMIT:-}")"
  cpu_esc="$(bh_sql_escape "${BH_CPU_LIMIT:-}")"
  sqlite3 "$BH_DB_FILE" <<EOF >/dev/null 2>&1
INSERT INTO scans(domain, output_dir, profile, started_at, status, resume_from, memory_profile, cpu_limit, threads, max_jobs)
VALUES('$domain_esc', '$output_esc', '$profile_esc', '$started_at', 'running', '$resume_esc', '$memory_esc', '$cpu_esc', ${THREADS:-0}, ${MAX_JOBS:-0});
EOF
}

bh_db_current_scan_id() {
  bh_db_sqlite_available || return 1
  local domain_esc
  domain_esc="$(bh_sql_escape "$DOMAIN")"
  sqlite3 -noheader "$BH_DB_FILE" "SELECT id FROM scans WHERE domain='$domain_esc' ORDER BY id DESC LIMIT 1;"
}

bh_db_import_lines() {
  local asset_type="$1"
  local source="$2"
  local file_path="$3"
  local scan_id
  scan_id="$(bh_db_current_scan_id 2>/dev/null || echo "")"
  [[ -n "$scan_id" ]] || return 0
  [[ -f "$file_path" ]] || return 0
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    local value_esc source_esc
    value_esc="$(bh_sql_escape "$line")"
    source_esc="$(bh_sql_escape "$source")"
    sqlite3 "$BH_DB_FILE" <<EOF >/dev/null 2>&1
INSERT OR IGNORE INTO assets(scan_id, asset_type, value, source, confidence, score)
VALUES($scan_id, '$asset_type', '$value_esc', '$source_esc', 0.5, 0.5);
EOF
  done < "$file_path"
}

bh_db_import_outputs() {
  bh_db_sqlite_available || return 0
  bh_db_insert_scan
  local scan_id
  scan_id="$(bh_db_current_scan_id 2>/dev/null || echo "")"
  [[ -n "$scan_id" ]] || return 0

  bh_db_import_lines subdomain "subdomains/all_subdomains.txt" "$OUTPUT_DIR/subdomains/all_subdomains.txt"
  bh_db_import_lines url "urls/all_urls.txt" "$OUTPUT_DIR/urls/all_urls.txt"
  bh_db_import_lines js "urls/js_files.txt" "$OUTPUT_DIR/urls/js_files.txt"
  bh_db_import_lines secret "vulns/secrets" "$OUTPUT_DIR/vulns/secrets/js_secrets.txt"
  bh_db_import_lines vuln "vulns" "$OUTPUT_DIR/findings.txt"
}

bh_db_upsert_asset_score() {
  bh_db_sqlite_available || return 0
  local asset_type="$1"
  local asset_value="$2"
  local criticality_score="${3:-0}"
  local exposure_score="${4:-0}"
  local attack_surface_score="${5:-0}"
  local confidence="${6:-0}"
  local scan_id
  scan_id="$(bh_db_current_scan_id 2>/dev/null || echo "")"
  [[ -n "$scan_id" ]] || return 0
  sqlite3 "$BH_DB_FILE" <<EOF >/dev/null 2>&1
INSERT INTO asset_scores(scan_id, asset_type, asset_value, criticality_score, exposure_score, attack_surface_score, confidence)
VALUES($scan_id, '$(bh_sql_escape "$asset_type")', '$(bh_sql_escape "$asset_value")', $criticality_score, $exposure_score, $attack_surface_score, $confidence)
ON CONFLICT(asset_type, asset_value) DO UPDATE SET
  criticality_score=excluded.criticality_score,
  exposure_score=excluded.exposure_score,
  attack_surface_score=excluded.attack_surface_score,
  confidence=excluded.confidence;
EOF
}

bh_db_insert_relationship() {
  bh_db_sqlite_available || return 0
  local source_asset="$1"
  local target_asset="$2"
  local relationship_type="$3"
  local confidence="${4:-0}"
  local evidence="${5:-}"
  local scan_id
  scan_id="$(bh_db_current_scan_id 2>/dev/null || echo "")"
  [[ -n "$scan_id" ]] || return 0
  sqlite3 "$BH_DB_FILE" <<EOF >/dev/null 2>&1
INSERT INTO asset_relationships(scan_id, source_asset, target_asset, relationship_type, confidence, evidence)
VALUES($scan_id, '$(bh_sql_escape "$source_asset")', '$(bh_sql_escape "$target_asset")', '$(bh_sql_escape "$relationship_type")', $confidence, '$(bh_sql_escape "$evidence")');
EOF
}

bh_db_insert_history() {
  bh_db_sqlite_available || return 0
  local asset_type="$1"
  local asset_value="$2"
  local event_type="$3"
  local previous_value="${4:-}"
  local new_value="${5:-}"
  local scan_id
  scan_id="$(bh_db_current_scan_id 2>/dev/null || echo "")"
  [[ -n "$scan_id" ]] || return 0
  sqlite3 "$BH_DB_FILE" <<EOF >/dev/null 2>&1
INSERT INTO asset_history(scan_id, asset_type, asset_value, event_type, previous_value, new_value)
VALUES($scan_id, '$(bh_sql_escape "$asset_type")', '$(bh_sql_escape "$asset_value")', '$(bh_sql_escape "$event_type")', '$(bh_sql_escape "$previous_value")', '$(bh_sql_escape "$new_value")');
EOF
}

bh_db_insert_findings_history() {
  bh_db_sqlite_available || return 0
  local title="$1"
  local severity="$2"
  local confidence="${3:-0}"
  local evidence="${4:-}"
  local reproduction="${5:-}"
  local source="${6:-}"
  local scan_id
  scan_id="$(bh_db_current_scan_id 2>/dev/null || echo "")"
  [[ -n "$scan_id" ]] || return 0
  sqlite3 "$BH_DB_FILE" <<EOF >/dev/null 2>&1
INSERT INTO findings_history(scan_id, title, severity, confidence, evidence, reproduction, source)
VALUES($scan_id, '$(bh_sql_escape "$title")', '$(bh_sql_escape "$severity")', $confidence, '$(bh_sql_escape "$evidence")', '$(bh_sql_escape "$reproduction")', '$(bh_sql_escape "$source")');
EOF
}

bh_record_finding() {
  bh_db_sqlite_available || return 0
  local severity="$1"
  local title="$2"
  local confidence="$3"
  local evidence="$4"
  local reproduction="$5"
  local source="$6"
  local scan_id
  scan_id="$(bh_db_current_scan_id 2>/dev/null || echo "")"
  [[ -n "$scan_id" ]] || return 0

  local title_esc evidence_esc reproduction_esc source_esc
  title_esc="$(bh_sql_escape "$title")"
  evidence_esc="$(bh_sql_escape "$evidence")"
  reproduction_esc="$(bh_sql_escape "$reproduction")"
  source_esc="$(bh_sql_escape "$source")"

  sqlite3 "$BH_DB_FILE" <<EOF >/dev/null 2>&1
INSERT INTO findings(scan_id, title, severity, confidence, evidence, reproduction, source)
VALUES($scan_id, '$title_esc', '$severity', ${confidence:-0}, '$evidence_esc', '$reproduction_esc', '$source_esc');
EOF
  bh_db_insert_findings_history "$title" "$severity" "${confidence:-0}" "$evidence" "$reproduction" "$source" || true
}

bh_db_upsert_attack_surface() {
  bh_db_sqlite_available || return 0
  local surface_type="$1"
  local surface_value="$2"
  local confidence="${3:-0}"
  local evidence="${4:-}"
  local scan_id
  scan_id="$(bh_db_current_scan_id 2>/dev/null || echo "")"
  [[ -n "$scan_id" ]] || return 0
  sqlite3 "$BH_DB_FILE" <<EOF >/dev/null 2>&1
INSERT INTO attack_surface(scan_id, surface_type, surface_value, confidence, evidence)
VALUES($scan_id, '$(bh_sql_escape "$surface_type")', '$(bh_sql_escape "$surface_value")', $confidence, '$(bh_sql_escape "$evidence")')
ON CONFLICT(surface_type, surface_value) DO UPDATE SET confidence=excluded.confidence, evidence=excluded.evidence;
EOF
}

bh_db_upsert_risk_score() {
  bh_db_sqlite_available || return 0
  local asset_type="$1"
  local asset_value="$2"
  local risk_score="${3:-0}"
  local confidence="${4:-0}"
  local evidence="${5:-}"
  local scan_id
  scan_id="$(bh_db_current_scan_id 2>/dev/null || echo "")"
  [[ -n "$scan_id" ]] || return 0
  sqlite3 "$BH_DB_FILE" <<EOF >/dev/null 2>&1
INSERT INTO risk_scores_v4(scan_id, asset_type, asset_value, risk_score, confidence, evidence)
VALUES($scan_id, '$(bh_sql_escape "$asset_type")', '$(bh_sql_escape "$asset_value")', $risk_score, $confidence, '$(bh_sql_escape "$evidence")')
ON CONFLICT(asset_type, asset_value) DO UPDATE SET risk_score=excluded.risk_score, confidence=excluded.confidence, evidence=excluded.evidence;
EOF
}
