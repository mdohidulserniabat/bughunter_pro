#!/bin/bash
# Dependency manager helpers.

BH_REQUIRED_TOOLS=(curl jq dig grep sed awk sort uniq cut tr head tail md5sum)
BH_OPTIONAL_TOOLS=(subfinder amass httpx nuclei katana sqlmap trufflehog interactsh-client ffuf dalfox gowitness)

bh_check_dependencies() {
  local missing=()
  local tool
  for tool in "${BH_REQUIRED_TOOLS[@]}"; do
    cmd_exists "$tool" || missing+=("$tool")
  done
  if ((${#missing[@]})); then
    bh_log_warn "Missing required base tools: ${missing[*]}"
    return 1
  fi

  local optional_missing=()
  for tool in "${BH_OPTIONAL_TOOLS[@]}"; do
    cmd_exists "$tool" || optional_missing+=("$tool")
  done
  [[ ${#optional_missing[@]} -gt 0 ]] && bh_log_warn "Optional tools not found: ${optional_missing[*]}"
  return 0
}
