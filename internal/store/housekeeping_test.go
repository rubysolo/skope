package store

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/rubysolo/skope/internal/pkgid"
)

func TestStaleProjects(t *testing.T) {
	st := open(t)
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	st.Now = func() time.Time { return clock }
	ctx := context.Background()
	tx := func(fn func(*Tx) error) {
		t.Helper()
		if err := st.Tx(ctx, fn); err != nil {
			t.Fatal(err)
		}
	}
	stale := func() (names []string) {
		tx(func(tx *Tx) error {
			ps, err := tx.StaleProjects()
			for _, p := range ps {
				names = append(names, p.Name)
			}
			return err
		})
		return names
	}

	var reporter, retired Project
	tx(func(tx *Tx) (err error) {
		reporter, _, _ = tx.CreateProject("reporter")
		tx.CreateProject("silent")
		retired, _, _ = tx.CreateProject("retired")
		return tx.ArchiveProject(retired.ID)
	})

	clock = clock.Add(20 * 24 * time.Hour)
	tx(func(tx *Tx) error {
		_, err := tx.RecordReport(reporter.ID, ReportMeta{}, []pkgid.Package{{Ecosystem: "Hex", Name: "plug", Version: "1.0.0"}})
		return err
	})
	if got := stale(); len(got) != 0 {
		t.Errorf("day 20: %v", got)
	}

	clock = clock.Add(11 * 24 * time.Hour) // day 31
	if got := stale(); len(got) != 1 || got[0] != "silent" {
		t.Errorf("day 31: %v, want [silent] (never reported; archived projects never count)", got)
	}
	if got := stale(); len(got) != 0 {
		t.Errorf("same day again: %v, want no repeat", got)
	}

	clock = clock.Add(8 * 24 * time.Hour) // day 39
	if got := stale(); len(got) != 1 || got[0] != "silent" {
		t.Errorf("a week later: %v, want a reminder", got)
	}

	clock = clock.Add(13 * 24 * time.Hour) // day 52: reporter's last report was day 20
	got := stale()
	slices.Sort(got)
	if !slices.Equal(got, []string{"reporter", "silent"}) {
		t.Errorf("day 52: %v, want reporter (32 days since its report) and silent (reminded 13 days ago)", got)
	}
}

func TestExpiredIgnores(t *testing.T) {
	st := open(t)
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	st.Now = func() time.Time { return clock }
	st.Tx(context.Background(), func(tx *Tx) error {
		p, _, _ := tx.CreateProject("cure")
		a, _ := tx.InsertFinding(Finding{ProjectID: p.ID, VulnID: "A", AdvisoryIDs: "A", Ecosystem: "Hex", NameKey: "plug", Name: "plug", Versions: "1", Severity: "high"}, 0)
		b, _ := tx.InsertFinding(Finding{ProjectID: p.ID, VulnID: "B", AdvisoryIDs: "B", Ecosystem: "Hex", NameKey: "plug", Name: "plug", Versions: "1", Severity: "high"}, 0)
		c, _ := tx.InsertFinding(Finding{ProjectID: p.ID, VulnID: "C", AdvisoryIDs: "C", Ecosystem: "Hex", NameKey: "plug", Name: "plug", Versions: "1", Severity: "high"}, 0)
		tx.IgnoreFinding(a, "x", "2025-12-31T00:00:00Z", "m")
		tx.IgnoreFinding(b, "x", "2026-06-01T00:00:00Z", "m")
		tx.IgnoreFinding(c, "x", "", "m")
		fs, err := tx.ExpiredIgnores()
		if err != nil || len(fs) != 1 || fs[0].ID != a {
			t.Errorf("ExpiredIgnores = %+v, %v; want only the lapsed one", fs, err)
		}
		return nil
	})
}
