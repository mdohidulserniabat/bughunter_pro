PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain TEXT NOT NULL,
  output_dir TEXT NOT NULL,
  profile TEXT,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  status TEXT NOT NULL DEFAULT 'running',
  resume_from TEXT,
  memory_profile TEXT,
  cpu_limit TEXT,
  threads INTEGER,
  max_jobs INTEGER,
  notes TEXT
);

CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER,
  asset_type TEXT NOT NULL,
  value TEXT NOT NULL,
  source TEXT,
  severity TEXT,
  confidence REAL DEFAULT 0.0,
  score REAL DEFAULT 0.0,
  evidence TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(asset_type, value)
);

CREATE TABLE IF NOT EXISTS technologies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER,
  host TEXT NOT NULL,
  technology TEXT NOT NULL,
  version TEXT,
  source TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(host, technology, IFNULL(version, ''))
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER,
  host TEXT,
  vuln_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence REAL DEFAULT 0.0,
  evidence TEXT,
  reproduction TEXT,
  source TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS urls (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER,
  url TEXT NOT NULL UNIQUE,
  host TEXT,
  path TEXT,
  parameter_count INTEGER DEFAULT 0,
  source TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS parameters (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER,
  url TEXT,
  param_name TEXT NOT NULL,
  source TEXT,
  UNIQUE(url, param_name)
);

CREATE TABLE IF NOT EXISTS js_files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER,
  url TEXT NOT NULL UNIQUE,
  host TEXT,
  risk_score REAL DEFAULT 0.0,
  fingerprint TEXT,
  source TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS secrets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER,
  source_url TEXT,
  secret_type TEXT NOT NULL,
  secret_value TEXT NOT NULL,
  confidence REAL DEFAULT 0.0,
  evidence TEXT,
  source TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS screenshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER,
  host TEXT NOT NULL,
  path TEXT NOT NULL,
  hash TEXT,
  source TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(host, path)
);

CREATE TABLE IF NOT EXISTS services (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER,
  host TEXT NOT NULL,
  service TEXT NOT NULL,
  port INTEGER,
  protocol TEXT,
  source TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence INTEGER DEFAULT 0,
  evidence TEXT,
  reproduction TEXT,
  source TEXT,
  asset TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER,
  asset_type TEXT NOT NULL,
  asset_value TEXT NOT NULL,
  event_type TEXT NOT NULL,
  previous_value TEXT,
  new_value TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS changes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER,
  asset_type TEXT NOT NULL,
  asset_value TEXT NOT NULL,
  change_type TEXT NOT NULL,
  diff_summary TEXT,
  confidence INTEGER DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS relationships (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER,
  source_asset TEXT NOT NULL,
  target_asset TEXT NOT NULL,
  relationship_type TEXT NOT NULL,
  confidence INTEGER DEFAULT 0,
  evidence TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS risk_scores (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER,
  asset_type TEXT NOT NULL,
  asset_value TEXT NOT NULL,
  exposure_score REAL DEFAULT 0.0,
  attack_surface_score REAL DEFAULT 0.0,
  confidence INTEGER DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(asset_type, asset_value)
);

CREATE INDEX IF NOT EXISTS idx_assets_type_value ON assets(asset_type, value);
CREATE INDEX IF NOT EXISTS idx_urls_host ON urls(host);
CREATE INDEX IF NOT EXISTS idx_vulns_host_severity ON vulnerabilities(host, severity);
CREATE INDEX IF NOT EXISTS idx_js_risk ON js_files(risk_score);
CREATE INDEX IF NOT EXISTS idx_secrets_type ON secrets(secret_type);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_risk_scores_asset ON risk_scores(asset_type, asset_value);
