package store

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rubysolo/skope/internal/pkgid"
)

func TestRotateToken(t *testing.T) {
	st := open(t)
	st.Tx(context.Background(), func(tx *Tx) error {
		p, old, _ := tx.CreateProject("cure")
		fresh, err := tx.RotateToken(p.ID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ProjectByToken(old); !errors.Is(err, ErrNotFound) {
			t.Error("old token must stop working")
		}
		if got, err := tx.ProjectByToken(fresh); err != nil || got.ID != p.ID {
			t.Errorf("new token: %+v, %v", got, err)
		}
		return nil
	})
}

func TestArchiveProject(t *testing.T) {
	st := open(t)
	st.Tx(context.Background(), func(tx *Tx) error {
		p, token, _ := tx.CreateProject("cure")
		rid, _ := tx.RecordReport(p.ID, ReportMeta{}, []pkgid.Package{{Ecosystem: "Hex", Name: "plug", Version: "1.0.0"}})
		tx.InsertFinding(Finding{ProjectID: p.ID, AdvisoryID: "A", Ecosystem: "Hex", NameKey: "plug", Name: "plug", Versions: "1.0.0", Severity: "high"}, rid)

		if err := tx.ArchiveProject(p.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ProjectByToken(token); !errors.Is(err, ErrNotFound) {
			t.Error("archived project's token must stop working")
		}
		if open, _ := tx.OpenFindingsForProject(p.ID); len(open) != 0 {
			t.Errorf("archive should resolve open findings, %d left", len(open))
		}
		if _, err := tx.RotateToken(p.ID); !errors.Is(err, ErrNotFound) {
			t.Error("archived projects can't get a new token")
		}
		if err := tx.ArchiveProject(p.ID); !errors.Is(err, ErrNotFound) {
			t.Error("archiving twice should report not found")
		}
		return nil
	})
}

func TestDeleteProjectCascades(t *testing.T) {
	st := open(t)
	st.Tx(context.Background(), func(tx *Tx) error {
		p, _, _ := tx.CreateProject("cure")
		rid, _ := tx.RecordReport(p.ID, ReportMeta{}, []pkgid.Package{{Ecosystem: "Hex", Name: "plug", Version: "1.0.0"}})
		tx.InsertFinding(Finding{ProjectID: p.ID, AdvisoryID: "A", Ecosystem: "Hex", NameKey: "plug", Name: "plug", Versions: "1.0.0", Severity: "high"}, rid)
		if err := tx.DeleteProject(p.ID); err != nil {
			t.Fatal(err)
		}
		if views, _ := tx.FindingViews(FindingFilter{IncludeResolved: true}); len(views) != 0 {
			t.Errorf("findings survived delete: %+v", views)
		}
		if inv, _ := tx.Inventory(p.ID); len(inv) != 0 {
			t.Errorf("inventory survived delete: %+v", inv)
		}
		return nil
	})
}

func TestFindingViewsOrder(t *testing.T) {
	st := open(t)
	st.Tx(context.Background(), func(tx *Tx) error {
		p, _, _ := tx.CreateProject("cure")
		for _, f := range []struct{ adv, sev string }{{"LOW", "low"}, {"CRIT", "critical"}, {"UNK", "unknown"}, {"HIGH", "high"}} {
			tx.InsertFinding(Finding{ProjectID: p.ID, AdvisoryID: f.adv, Ecosystem: "Hex", NameKey: "plug", Name: "plug", Versions: "1", Severity: f.sev}, 0)
		}
		views, err := tx.FindingViews(FindingFilter{ProjectID: p.ID})
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, v := range views {
			got = append(got, v.AdvisoryID)
		}
		if want := "CRIT HIGH UNK LOW"; strings.Join(got, " ") != want {
			t.Errorf("order = %v, want %s", got, want)
		}
		return nil
	})
}
