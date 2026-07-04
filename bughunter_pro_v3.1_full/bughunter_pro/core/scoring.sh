#!/bin/bash
# Confidence and risk helpers.

bh_confidence_label() {
  local score="${1:-0}"
  if (( score < 20 )); then
    printf '%s' "LOW"
  elif (( score < 50 )); then
    printf '%s' "MEDIUM"
  elif (( score < 80 )); then
    printf '%s' "HIGH"
  else
    printf '%s' "VERIFIED"
  fi
}

bh_confidence_score() {
  local base="${1:-0}"
  local evidence_count="${2:-0}"
  local oob="${3:-0}"
  local score=$base
  (( score += evidence_count * 10 ))
  (( oob > 0 )) && score=$((score + 25))
  (( score > 100 )) && score=100
  printf '%s' "$score"
}

bh_similarity_band() {
  local ratio="${1:-0}"
  if (( ratio >= 90 )); then
    printf '%s' "near-identical"
  elif (( ratio >= 70 )); then
    printf '%s' "similar"
  elif (( ratio >= 40 )); then
    printf '%s' "weakly-similar"
  else
    printf '%s' "different"
  fi
}