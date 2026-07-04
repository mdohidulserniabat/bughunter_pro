#!/bin/bash
# Async queue and resource-aware scheduling helpers.

bh_detect_system_limits() {
  local mem_hint="${BH_MEMORY_LIMIT:-}"
  if [[ -n "$mem_hint" ]]; then
    case "$mem_hint" in
      512MB|512m|512) BH_MEMORY_PROFILE="512MB"; MAX_JOBS=${MAX_JOBS:-2}; THREADS=${THREADS:-10} ;;
      1GB|1g|1) BH_MEMORY_PROFILE="1GB"; MAX_JOBS=${MAX_JOBS:-3}; THREADS=${THREADS:-20} ;;
      2GB|2g|2) BH_MEMORY_PROFILE="2GB"; MAX_JOBS=${MAX_JOBS:-4}; THREADS=${THREADS:-30} ;;
      4GB|4g|4) BH_MEMORY_PROFILE="4GB"; MAX_JOBS=${MAX_JOBS:-5}; THREADS=${THREADS:-40} ;;
      8GB|8g|8) BH_MEMORY_PROFILE="8GB+"; MAX_JOBS=${MAX_JOBS:-8}; THREADS=${THREADS:-60} ;;
      *) BH_MEMORY_PROFILE="$mem_hint" ;;
    esac
    return 0
  fi

  if command -v free &>/dev/null; then
    local mem_kb
    mem_kb=$(free -k | awk '/Mem:/ {print $2}')
    if [[ -n "$mem_kb" ]]; then
      if (( mem_kb < 900000 )); then
        BH_MEMORY_PROFILE="512MB"
        MAX_JOBS=${MAX_JOBS:-2}
        THREADS=${THREADS:-10}
      elif (( mem_kb < 1800000 )); then
        BH_MEMORY_PROFILE="1GB"
        MAX_JOBS=${MAX_JOBS:-3}
        THREADS=${THREADS:-20}
      elif (( mem_kb < 3600000 )); then
        BH_MEMORY_PROFILE="2GB"
        MAX_JOBS=${MAX_JOBS:-4}
        THREADS=${THREADS:-30}
      elif (( mem_kb < 7200000 )); then
        BH_MEMORY_PROFILE="4GB"
        MAX_JOBS=${MAX_JOBS:-5}
        THREADS=${THREADS:-40}
      else
        BH_MEMORY_PROFILE="8GB+"
        MAX_JOBS=${MAX_JOBS:-8}
      fi
    fi
  fi

  if [[ -n "${BH_CPU_LIMIT:-}" ]]; then
    local cpus
    cpus=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
    if [[ "$BH_CPU_LIMIT" =~ ^[0-9]+%$ ]]; then
      local pct=${BH_CPU_LIMIT%%%}
      local scaled=$(( (cpus * pct) / 100 ))
      (( scaled < 1 )) && scaled=1
      MAX_JOBS=$scaled
    elif [[ "$BH_CPU_LIMIT" =~ ^[0-9]+$ ]]; then
      MAX_JOBS=$BH_CPU_LIMIT
    fi
  fi
}

bh_parallel_pids=()

bh_queue_run() {
  while [[ ${#bh_parallel_pids[@]} -ge ${MAX_JOBS:-3} ]]; do
    bh_queue_reap
    sleep 1
  done
  "$@" &
  bh_parallel_pids+=("$!")
}

bh_queue_reap() {
  local alive=()
  local pid
  for pid in "${bh_parallel_pids[@]:-}"; do
    if kill -0 "$pid" 2>/dev/null; then
      alive+=("$pid")
    fi
  done
  bh_parallel_pids=("${alive[@]:-}")
}

bh_queue_wait() {
  local pid
  for pid in "${bh_parallel_pids[@]:-}"; do
    wait "$pid" 2>/dev/null || true
  done
  bh_parallel_pids=()
}
