package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"slices"
	"testing"

	"github.com/rubysolo/skope/internal/osv"
)

func upsert(t *testing.T, tx *Tx, id, modified string, aliases ...string) {
	t.Helper()
	if _, err := tx.UpsertAdvisory(&osv.Advisory{ID: id, Modified: modified, Aliases: aliases}); err != nil {
		t.Fatal(err)
	}
}

func TestVulnGroupFollowsAliasesTransitively(t *testing.T) {
	st := open(t)
	st.Tx(context.Background(), func(tx *Tx) error {
		// EEF lists GHSA; GHSA lists the CVE; PYSEC is unrelated.
		upsert(t, tx, "EEF-CVE-2026-1", "2026-01-02T00:00:00Z", "GHSA-aaaa")
		upsert(t, tx, "GHSA-aaaa", "2026-01-03T00:00:00Z", "CVE-2026-1")
		upsert(t, tx, "PYSEC-2026-9", "2026-01-01T00:00:00Z")
		// Go's shape: the GO- advisory's aliases include Bitnami's BIT- id,
		// which sorts before CVE- but must not become the key.
		upsert(t, tx, "GO-2025-4010", "2026-01-01T00:00:00Z", "BIT-golang-2025-47912", "CVE-2025-47912")
		upsert(t, tx, "GO-2025-4011", "2026-01-01T00:00:00Z", "BIT-golang-2025-1")

		for _, start := range []string{"EEF-CVE-2026-1", "GHSA-aaaa", "CVE-2026-1"} {
			g, err := tx.VulnGroup(start)
			if err != nil {
				t.Fatal(err)
			}
			if g.Key != "CVE-2026-1" || !slices.Equal(g.Advisories, []string{"EEF-CVE-2026-1", "GHSA-aaaa"}) {
				t.Errorf("VulnGroup(%s) = %+v", start, g)
			}
		}
		g, _ := tx.VulnGroup("PYSEC-2026-9")
		if g.Key != "PYSEC-2026-9" || len(g.Advisories) != 1 {
			t.Errorf("standalone advisory: %+v", g)
		}
		if g, _ := tx.VulnGroup("GO-2025-4010"); g.Key != "CVE-2025-47912" {
			t.Errorf("key = %q, want the CVE over the BIT- alias", g.Key)
		}
		if g, _ := tx.VulnGroup("GO-2025-4011"); g.Key != "GO-2025-4011" {
			t.Errorf("key = %q, want the advisory id when there is no CVE", g.Key)
		}
		if _, err := tx.VulnGroup("CVE-0000-0"); !errors.Is(err, ErrNotFound) {
			t.Errorf("unknown id: %v", err)
		}
		if m, _ := tx.VulnModified([]string{"EEF-CVE-2026-1", "GHSA-aaaa"}); m != "2026-01-03T00:00:00Z" {
			t.Errorf("VulnModified = %q, want the newest", m)
		}

		// An advisory that drops an alias leaves the group.
		upsert(t, tx, "GHSA-aaaa", "2026-02-01T00:00:00Z")
		if g, _ := tx.VulnGroup("EEF-CVE-2026-1"); !slices.Equal(g.Advisories, []string{"EEF-CVE-2026-1", "GHSA-aaaa"}) {
			t.Errorf("EEF still names GHSA, so they stay grouped: %+v", g)
		}
		if g, _ := tx.VulnGroup("CVE-2026-1"); len(g.Advisories) != 0 {
			t.Errorf("nothing answers to the CVE any more: %+v", g)
		}
		return nil
	})
}

func TestMigrationV2BackfillsAliasesAndKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "skope.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		schemaV1,
		`PRAGMA user_version = 1`,
		`INSERT INTO projects (id, name, created_at) VALUES (1, 'cure', '2026-01-01')`,
		`INSERT INTO advisories (id, modified, severity, raw) VALUES ('GHSA-aaaa', 'm', 'high', CAST('{"id":"GHSA-aaaa","aliases":["CVE-2026-1"]}' AS BLOB))`,
		`INSERT INTO findings (project_id, advisory_id, ecosystem, name_key, name, versions, severity, opened_at)
		   VALUES (1, 'GHSA-aaaa', 'Hex', 'plug', 'plug', '1.0.0', 'high', '2026-01-01')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	db.Close()

	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.Tx(context.Background(), func(tx *Tx) error {
		if g, err := tx.VulnGroup("CVE-2026-1"); err != nil || g.Advisories[0] != "GHSA-aaaa" {
			t.Errorf("aliases not backfilled: %+v %v", g, err)
		}
		fs, _ := tx.OpenFindingsForProject(1)
		if len(fs) != 1 || fs[0].VulnID != "GHSA-aaaa" || fs[0].AdvisoryIDs != "GHSA-aaaa" {
			t.Errorf("finding after migration: %+v", fs)
		}
		return nil
	})
}
