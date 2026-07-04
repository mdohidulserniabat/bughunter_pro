-- BugHunter Pro v4 database migration

CREATE TABLE IF NOT EXISTS asset_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER,
  asset_type TEXT NOT NULL,
  asset_value TEXT NOT NULL,
  event_type TEXT NOT NULL,
  previous_value TEXT,
  new_value TEXT,
  confidence INTEGER DEFAULT 0,
  evidence TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS asset_relationships (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER,
  source_asset TEXT NOT NULL,
  target_asset TEXT NOT NULL,
  relationship_type TEXT NOT NULL,
  confidence INTEGER DEFAULT 0,
  evidence TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS asset_scores (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER,
  asset_type TEXT NOT NULL,
  asset_value TEXT NOT NULL,
  criticality_score REAL DEFAULT 0.0,
  exposure_score REAL DEFAULT 0.0,
  attack_surface_score REAL DEFAULT 0.0,
  confidence INTEGER DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(asset_type, asset_value)
);

CREATE TABLE IF NOT EXISTS attack_surface (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER,
  surface_type TEXT NOT NULL,
  surface_value TEXT NOT NULL,
  confidence INTEGER DEFAULT 0,
  evidence TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(surface_type, surface_value)
);

CREATE TABLE IF NOT EXISTS risk_scores_v4 (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER,
  asset_type TEXT NOT NULL,
  asset_value TEXT NOT NULL,
  risk_score REAL DEFAULT 0.0,
  confidence INTEGER DEFAULT 0,
  evidence TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(asset_type, asset_value)
);

CREATE TABLE IF NOT EXISTS findings_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence INTEGER DEFAULT 0,
  evidence TEXT,
  reproduction TEXT,
  source TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
