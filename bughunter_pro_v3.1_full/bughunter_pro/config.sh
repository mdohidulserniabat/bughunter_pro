#!/bin/bash
# ══════════════════════════════════════════════════════
#  BugHunter Pro — API Key Configuration
#  File: ~/.bughunter/config.sh
#  এই ফাইলে একবার key দিলে সব scan এ কাজ করবে
# ══════════════════════════════════════════════════════

# ── Free API Keys (সহজে পাওয়া যায়) ──────────────────

# Shodan — https://account.shodan.io/
export SHODAN_API_KEY=""

# GitHub Token — https://github.com/settings/tokens
# Permission: read:org, public_repo
export GITHUB_TOKEN=""

# Chaos (ProjectDiscovery) — https://chaos.projectdiscovery.io/
export CHAOS_KEY=""

# ── Paid / Registration Required ──────────────────────

# SecurityTrails — https://securitytrails.com/app/account/credentials
export SECURITYTRAILS_KEY=""

# Censys — https://search.censys.io/account/api
export CENSYS_API_ID=""
export CENSYS_API_SECRET=""

# FOFA — https://fofa.info/user/users/my_info
export FOFA_EMAIL=""
export FOFA_KEY=""

# ZoomEye — https://www.zoomeye.org/profile
export ZOOMEYE_KEY=""

# Netlas — https://app.netlas.io/profile/
export NETLAS_KEY=""

# FullHunt — https://fullhunt.io/user/settings
export FULLHUNT_KEY=""

# ── Notification (Optional) ───────────────────────────
# Scan শেষ হলে Telegram notify করবে
export TELEGRAM_BOT_TOKEN=""
export TELEGRAM_CHAT_ID=""

# ── Permutation Tuning ────────────────────────────────
# 5000 lines is a sane default for low-RAM boxes.
# Increase only if you want more permutation coverage.
export PERM_WORDLIST_LIMIT="5000"
export PERM_TIMEOUT="15"
