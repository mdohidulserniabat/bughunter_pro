#!/bin/bash
# Plugin discovery and loader.

bh_load_plugins() {
  local plugin_dir="${BH_PLUGIN_DIR:-$SCRIPT_DIR/plugins}"
  [[ -d "$plugin_dir" ]] || return 0
  local plugin
  for plugin in "$plugin_dir"/*.sh; do
    [[ -f "$plugin" ]] || continue
    source "$plugin"
    bh_log_info "Loaded plugin: $(basename "$plugin")"
  done
}
