-- Inventories are per source: the repository ('repo') or a container image
-- ('image:<name>'). A report replaces only its own source's packages.
CREATE TABLE inventory_v3 (
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  source     TEXT NOT NULL,
  ecosystem  TEXT NOT NULL,
  name_key   TEXT NOT NULL,
  name       TEXT NOT NULL,
  version    TEXT NOT NULL,
  PRIMARY KEY (project_id, source, ecosystem, name_key, version)
);
INSERT INTO inventory_v3 (project_id, source, ecosystem, name_key, name, version)
  SELECT project_id, 'repo', ecosystem, name_key, name, version FROM inventory;
DROP TABLE inventory;
ALTER TABLE inventory_v3 RENAME TO inventory;
CREATE INDEX inventory_by_package ON inventory (ecosystem, name_key);

ALTER TABLE reports ADD COLUMN source TEXT NOT NULL DEFAULT 'repo';

-- Which sources contain the affected package, comma-separated.
ALTER TABLE findings ADD COLUMN sources TEXT NOT NULL DEFAULT 'repo';
-- 0 while no advisory names a fixed version (an unfixed finding). Findings
-- from before this migration were all alerted on, so they count as fixable.
ALTER TABLE findings ADD COLUMN fixable INTEGER NOT NULL DEFAULT 1;
