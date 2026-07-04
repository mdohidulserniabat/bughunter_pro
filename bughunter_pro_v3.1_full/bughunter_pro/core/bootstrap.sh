#!/bin/bash
# Shared runtime bootstrap for BugHunter Pro.

bh_set_strict_mode() {
  set -Eeuo pipefail
  shopt -s nullglob 2>/dev/null || true
}

bh_timestamp() {
  date '+%Y-%m-%d %H:%M:%S'
}

bh_init_paths() {
  : "${BH_LOG_DIR:=$OUTPUT_DIR/logs}"
  : "${BH_STATE_DIR:=$OUTPUT_DIR/state}"
  : "${BH_CACHE_DIR:=$OUTPUT_DIR/cache}"
  : "${BH_DB_DIR:=$OUTPUT_DIR/db}"
  mkdir -p "$BH_LOG_DIR" "$BH_STATE_DIR" "$BH_CACHE_DIR" "$BH_DB_DIR"
  : "${BH_LOG_FILE:=$BH_LOG_DIR/framework.log}"
  : "${BH_CHECKPOINT_FILE:=$BH_STATE_DIR/checkpoint.json}"
  : "${BH_DB_FILE:=$BH_DB_DIR/assets.db}"
}

bh_log_line() {
  local level="$1"
  shift
  local message="$*"
  printf '[%s] [%s] %s\n' "$(bh_timestamp)" "$level" "$message" >> "$BH_LOG_FILE"
}

bh_log_info() {
  printf '%s[+]%s %s\n' "${GREEN:-}" "${NC:-}" "$*"
  bh_log_line INFO "$*"
}

bh_log_warn() {
  printf '%s[!]%s %s\n' "${YELLOW:-}" "${NC:-}" "$*"
  bh_log_line WARN "$*"
}

bh_log_error() {
  printf '%s[-]%s %s\n' "${RED:-}" "${NC:-}" "$*"
  bh_log_line ERROR "$*"
}

bh_log_section() {
  printf '\n%s%s╔══════════════════════════════════════════════╗%s\n' "${BLUE:-}" "${BOLD:-}" "${NC:-}"
  printf '%s%s║  %s%s\n' "${BLUE:-}" "${BOLD:-}" "$*" "${NC:-}"
  printf '%s%s╚══════════════════════════════════════════════╝%s\n\n' "${BLUE:-}" "${BOLD:-}" "${NC:-}"
  bh_log_line SECTION "$*"
}

bh_log_finding() {
  TOTAL_FINDINGS=$((TOTAL_FINDINGS + 1))
  printf '%s%s[VULN]%s %s%s\n' "${RED:-}" "${BOLD:-}" "${NC:-}" "${RED:-}" "$*${NC:-}"
  printf '[%s] %s\n' "$(date +%T)" "$*" >> "$OUTPUT_DIR/findings.txt" 2>/dev/null || true
  bh_log_line FINDING "$*"
  if command -v bh_record_finding >/dev/null 2>&1; then
    bh_record_finding "info" "$*" "50" "$*" "manual review" "bootstrap"
  fi
}

log_info() { bh_log_info "$@"; }
log_warn() { bh_log_warn "$@"; }
log_error() { bh_log_error "$@"; }
log_section() { bh_log_section "$@"; }
log_finding() { bh_log_finding "$@"; }

cmd_exists() { command -v "$1" &>/dev/null; }
safe_run() { "$@" 2>/dev/null || true; }
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

bh_hash8() {
  printf '%s' "$1" | md5sum | cut -c1-8
}

bh_init_runtime() {
  bh_set_strict_mode
  bh_init_paths
  bh_log_line INFO "runtime initialized"
}

bh_checkpoint_save() {
  local step="$1"
  local status="${2:-ok}"
  cat > "$BH_CHECKPOINT_FILE" <<EOF
{"domain":"$DOMAIN","output_dir":"$OUTPUT_DIR","last_step":"$step","status":"$status","updated_at":"$(bh_timestamp)"}
EOF
}

bh_checkpoint_load() {
  [[ -f "$BH_CHECKPOINT_FILE" ]] || return 1
  BH_LAST_STEP="$(grep -o '"last_step":"[^"]*"' "$BH_CHECKPOINT_FILE" 2>/dev/null | cut -d'"' -f4)"
  [[ -n "${BH_LAST_STEP:-}" ]]
}

bh_should_run_step() {
  local step="$1"
  [[ "${RESUME:-0}" == "1" ]] || return 0
  [[ -z "${BH_LAST_STEP:-}" ]] && return 0
  [[ "$BH_LAST_STEP" == "$step" ]] && return 0

  local seen=0
  local item
  for item in "${BH_STEP_ORDER[@]}"; do
    [[ "$item" == "$BH_LAST_STEP" ]] && seen=1 && continue
    [[ "$item" == "$step" ]] && [[ "$seen" == "1" ]] && return 0
    [[ "$item" == "$step" ]] && [[ "$seen" == "0" ]] && return 1
  done
  return 0
}

bh_handle_crash() {
  local exit_code=$?
  local line=${1:-0}
  bh_log_error "crash detected at line $line (exit=$exit_code)"
  [[ -n "${BH_CURRENT_STEP:-}" ]] && bh_checkpoint_save "$BH_CURRENT_STEP" "crash"
  exit "$exit_code"
}

bh_install_traps() {
  trap 'bh_handle_crash $LINENO' ERR
  trap 'bh_checkpoint_save "${BH_CURRENT_STEP:-unknown}" "interrupted"; bh_log_warn "interrupted"' INT TERM
  trap 'bh_checkpoint_save "${BH_CURRENT_STEP:-unknown}" "exit"' EXIT
}

bh_setup_job_env() {
  : "${BH_MEMORY_LIMIT:=}"
  : "${BH_CPU_LIMIT:=}"
  : "${MAX_JOBS:=3}"
  : "${THREADS:=30}"
}
