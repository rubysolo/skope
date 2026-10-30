package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rubysolo/skope/internal/osvsync"
	"github.com/rubysolo/skope/internal/pkgid"
	"github.com/rubysolo/skope/internal/store"
)

// TestLiveOSV syncs real OSV data and matches known-vulnerable packages.
// Run with SKOPE_LIVE=Hex,crates.io (or "all"); SKOPE_LIVE_DB keeps the db.
func TestLiveOSV(t *testing.T) {
	live := os.Getenv("SKOPE_LIVE")
	if live == "" {
		t.Skip("set SKOPE_LIVE to run against osv.dev")
	}
	ecosystems := strings.Split(live, ",")
	if live == "all" {
		ecosystems = pkgid.Ecosystems()
	}
	path := os.Getenv("SKOPE_LIVE_DB")
	if path == "" {
		path = filepath.Join(t.TempDir(), "skope.db")
	}
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	sc := New(st)

	var p store.Project
	st.Tx(ctx, func(tx *store.Tx) (err error) { p, _, err = tx.CreateProject("live"); return })

	known := map[string]string{ // purl → an advisory that must match it
		"Hex":       "pkg:hex/hex_core@0.10.0",
		"crates.io": "pkg:cargo/time@0.1.43",
		"RubyGems":  "pkg:gem/rack@2.0.0",
		"npm":       "pkg:npm/lodash@4.17.15",
		"Go":        "pkg:golang/golang.org/x/net@v0.0.1",
		"PyPI":      "pkg:pypi/django@3.0.0",
	}
	var pkgs []pkgid.Package
	for _, eco := range ecosystems {
		p, _ := pkgid.Parse(known[eco])
		pkgs = append(pkgs, p)
	}
	if _, err := sc.Report(ctx, p.ID, store.ReportMeta{}, pkgs); err != nil {
		t.Fatal(err)
	}

	syncer := osvsync.New(st)
	for _, eco := range ecosystems {
		start := time.Now()
		ids, err := syncer.Sync(ctx, eco)
		if err != nil {
			t.Fatalf("%s: %v", eco, err)
		}
		synced := time.Since(start)
		changes, err := sc.Advisories(ctx, ids)
		if err != nil {
			t.Fatalf("%s: %v", eco, err)
		}
		t.Logf("%-9s %6d advisories  sync %v  match %v  %d findings opened",
			eco, len(ids), synced.Round(time.Second), (time.Since(start) - synced).Round(time.Second), len(changes))

		// Every advisory should be evaluable: a parse error means a version
		// scheme we mishandle.
		st.Tx(ctx, func(tx *store.Tx) error {
			bad := 0
			for _, id := range ids {
				a, err := tx.Advisory(id)
				if err != nil {
					return err
				}
				for _, ref := range a.Packages() {
					for _, af := range a.Affected {
						if pkgid.NameKey(eco, af.Package.Name) != ref.Key {
							continue
						}
						if _, err := a.Affects(pkgid.Package{Ecosystem: eco, Name: af.Package.Name, Version: "1.0.0"}); err != nil {
							if bad < 5 {
								t.Logf("  %v", err)
							}
							bad++
						}
					}
				}
			}
			if bad > 0 {
				t.Errorf("%s: %d unevaluable (advisory, package) pairs", eco, bad)
			}
			return nil
		})
	}

	st.Tx(ctx, func(tx *store.Tx) error {
		open, _ := tx.OpenFindingsForProject(p.ID)
		hit := map[string]bool{}
		for _, f := range open {
			hit[f.Ecosystem] = true
		}
		for _, eco := range ecosystems {
			if !hit[eco] {
				t.Errorf("%s: %s should have a finding", eco, known[eco])
			}
		}
		t.Logf("%d open findings", len(open))
		return nil
	})
	if fi, err := os.Stat(path); err == nil {
		t.Logf("db size %d MB", fi.Size()>>20)
	}
}
