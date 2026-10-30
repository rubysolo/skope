CREATE TABLE projects (
  id               INTEGER PRIMARY KEY,
  name             TEXT NOT NULL UNIQUE,
  token_hash       TEXT UNIQUE,              -- NULL once archived
  stale_after_days INTEGER NOT NULL DEFAULT 30,
  created_at       TEXT NOT NULL,
  archived_at      TEXT,
  last_report_at   TEXT,
  stale_alerted_at TEXT
);

-- A project's current inventory; replaced wholesale by each report.
CREATE TABLE inventory (
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  ecosystem  TEXT NOT NULL,
  name_key   TEXT NOT NULL,
  name       TEXT NOT NULL,
  version    TEXT NOT NULL,
  PRIMARY KEY (project_id, ecosystem, name_key, version)
);
CREATE INDEX inventory_by_package ON inventory (ecosystem, name_key);

CREATE TABLE reports (
  id            INTEGER PRIMARY KEY,
  project_id    INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  received_at   TEXT NOT NULL,
  commit_sha    TEXT NOT NULL DEFAULT '',
  ref           TEXT NOT NULL DEFAULT '',
  run_url       TEXT NOT NULL DEFAULT '',
  package_count INTEGER NOT NULL
);
CREATE INDEX reports_by_time ON reports (received_at);

CREATE TABLE advisories (
  id        TEXT PRIMARY KEY,
  modified  TEXT NOT NULL,
  severity  TEXT NOT NULL,
  withdrawn INTEGER NOT NULL DEFAULT 0,
  summary   TEXT NOT NULL DEFAULT '',
  raw       BLOB NOT NULL
);

CREATE TABLE advisory_packages (
  advisory_id TEXT NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
  ecosystem   TEXT NOT NULL,
  name_key    TEXT NOT NULL,
  PRIMARY KEY (ecosystem, name_key, advisory_id)
);
CREATE INDEX advisory_packages_by_advisory ON advisory_packages (advisory_id);

-- One row per finding. A resolved finding is never reopened; recurrence
-- inserts a new row.
CREATE TABLE findings (
  id                   INTEGER PRIMARY KEY,
  project_id           INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  advisory_id          TEXT NOT NULL,
  ecosystem            TEXT NOT NULL,
  name_key             TEXT NOT NULL,
  name                 TEXT NOT NULL,
  versions             TEXT NOT NULL,      -- affected versions present, comma-separated
  severity             TEXT NOT NULL,
  opened_at            TEXT NOT NULL,
  resolved_at          TEXT,
  introduced_report_id INTEGER REFERENCES reports(id) ON DELETE SET NULL,
  ignored_reason       TEXT,
  ignored_until        TEXT,
  ignored_modified     TEXT                -- advisory.modified when ignored
);
CREATE UNIQUE INDEX findings_open ON findings (project_id, advisory_id, ecosystem, name_key)
  WHERE resolved_at IS NULL;
CREATE INDEX findings_by_advisory ON findings (advisory_id) WHERE resolved_at IS NULL;

CREATE TABLE sync_state (
  ecosystem    TEXT PRIMARY KEY,
  last_modified TEXT NOT NULL              -- newest advisory.modified applied
);
