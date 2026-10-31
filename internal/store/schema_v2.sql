-- Findings are per vulnerability: the group of advisories that alias each
-- other. vuln_id is the group's key (its smallest identifier).
ALTER TABLE findings RENAME COLUMN advisory_id TO vuln_id;
ALTER TABLE findings ADD COLUMN advisory_ids TEXT NOT NULL DEFAULT '';  -- matching advisories, comma-separated
ALTER TABLE findings ADD COLUMN summary TEXT NOT NULL DEFAULT '';
UPDATE findings SET advisory_ids = vuln_id;

-- Every identifier an advisory answers to: its own id and its aliases.
CREATE TABLE advisory_aliases (
  alias       TEXT NOT NULL,
  advisory_id TEXT NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
  PRIMARY KEY (alias, advisory_id)
);
CREATE INDEX advisory_aliases_by_advisory ON advisory_aliases (advisory_id);

INSERT INTO advisory_aliases (alias, advisory_id) SELECT id, id FROM advisories;
INSERT OR IGNORE INTO advisory_aliases (alias, advisory_id)
  SELECT j.value, a.id FROM advisories a, json_each(CAST(a.raw AS TEXT), '$.aliases') j;
