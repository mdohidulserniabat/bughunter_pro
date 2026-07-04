#!/bin/bash
# Simple disk cache helpers.

bh_cache_key() {
  printf '%s' "$1" | sha256sum | cut -c1-32
}

bh_cache_path() {
  printf '%s/%s.cache' "$BH_CACHE_DIR" "$(bh_cache_key "$1")"
}

bh_cache_get() {
  [[ "${BH_CACHE_ENABLED:-0}" == "1" ]] || return 1
  local key="$1"
  local path
  path="$(bh_cache_path "$key")"
  [[ -f "$path" ]] || return 1
  cat "$path"
}

bh_cache_put() {
  [[ "${BH_CACHE_ENABLED:-0}" == "1" ]] || return 0
  local key="$1"
  local value="$2"
  local path
  path="$(bh_cache_path "$key")"
  printf '%s' "$value" > "$path"
}
