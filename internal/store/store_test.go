package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rubysolo/skope/internal/pkgid"
)

func open(t *testing.T) *Store {
	st, err := Open(filepath.Join(t.TempDir(), "skope.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestProjectTokens(t *testing.T) {
	st := open(t)
	err := st.Tx(context.Background(), func(tx *Tx) error {
		p, token, err := tx.CreateProject("cure")
		if err != nil {
			return err
		}
		if !strings.HasPrefix(token, "skope_") || len(token) < 40 {
			t.Errorf("token %q: want a long skope_-prefixed secret", token)
		}
		got, err := tx.ProjectByToken(token)
		if err != nil || got.ID != p.ID {
			t.Errorf("ProjectByToken = %+v, %v", got, err)
		}
		for _, bad := range []string{"", "skope_nope", strings.TrimPrefix(token, "skope_")} {
			if _, err := tx.ProjectByToken(bad); !errors.Is(err, ErrNotFound) {
				t.Errorf("ProjectByToken(%q) = %v, want ErrNotFound", bad, err)
			}
		}
		if _, _, err := tx.CreateProject("cure"); err == nil || !strings.Contains(err.Error(), "already exists") {
			t.Errorf("duplicate name: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestReportReplacesInventory(t *testing.T) {
	st := open(t)
	ctx := context.Background()
	err := st.Tx(ctx, func(tx *Tx) error {
		p, _, _ := tx.CreateProject("cure")
		first := []pkgid.Package{{Ecosystem: "Hex", Name: "plug", Version: "1.0.0"}, {Ecosystem: "Hex", Name: "ecto", Version: "3.0.0"}}
		if _, err := tx.RecordReport(p.ID, ReportMeta{Commit: "a"}, first); err != nil {
			return err
		}
		second := []pkgid.Package{{Ecosystem: "Hex", Name: "plug", Version: "1.1.0"}}
		id, err := tx.RecordReport(p.ID, ReportMeta{Commit: "b"}, second)
		if err != nil {
			return err
		}
		inv, _ := tx.Inventory(p.ID)
		if len(inv) != 1 || inv[0].Package != second[0] || inv[0].Source != "repo" {
			t.Errorf("inventory = %+v, want only %+v", inv, second)
		}
		if latest, _ := tx.LatestReportID(p.ID); latest != id {
			t.Errorf("LatestReportID = %d, want %d", latest, id)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestReopenKeepsData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "skope.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	st.Tx(context.Background(), func(tx *Tx) error { _, _, err := tx.CreateProject("cure"); return err })
	st.Close()

	st, err = Open(path) // migrations must not re-run
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.Tx(context.Background(), func(tx *Tx) error {
		if _, err := tx.ProjectName(1); err != nil {
			t.Errorf("project lost on reopen: %v", err)
		}
		return nil
	})
}

func TestReportsReplaceOnlyTheirSource(t *testing.T) {
	st := open(t)
	st.Tx(context.Background(), func(tx *Tx) error {
		p, _, _ := tx.CreateProject("cure")
		plug := []pkgid.Package{{Ecosystem: "Hex", Name: "plug", Version: "1.0.0"}}
		ssl := []pkgid.Package{{Ecosystem: "Alpine:v3.24", Name: "openssl", Version: "3.5.0-r0"}}
		tx.RecordReport(p.ID, ReportMeta{}, plug)
		tx.RecordReport(p.ID, ReportMeta{Source: "image:ghcr.io/x/cure"}, ssl)
		tx.RecordReport(p.ID, ReportMeta{Source: "image:ghcr.io/x/cure"}, ssl) // again: replaces, no duplicates
		inv, err := tx.Inventory(p.ID)
		if err != nil || len(inv) != 2 || inv[0].Source != "image:ghcr.io/x/cure" || inv[1].Source != "repo" {
			t.Errorf("both sources kept: %+v %v", inv, err)
		}
		tx.RecordReport(p.ID, ReportMeta{}, nil) // the repo now has no packages
		if inv, _ := tx.Inventory(p.ID); len(inv) != 1 || inv[0].Package != ssl[0] {
			t.Errorf("a repo report must not touch the image's packages: %+v", inv)
		}
		return nil
	})
}
