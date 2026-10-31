package scan

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/rubysolo/skope/internal/osv"
	"github.com/rubysolo/skope/internal/pkgid"
	"github.com/rubysolo/skope/internal/store"
)

type env struct {
	t     *testing.T
	st    *store.Store
	sc    *Scanner
	clock time.Time
}

func newEnv(t *testing.T) *env {
	st, err := store.Open(filepath.Join(t.TempDir(), "skope.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := &env{t: t, st: st, sc: New(st), clock: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)}
	st.Now = func() time.Time { e.clock = e.clock.Add(time.Minute); return e.clock }
	return e
}

func (e *env) project(name string) int64 {
	e.t.Helper()
	var id int64
	e.tx(func(tx *store.Tx) error {
		p, _, err := tx.CreateProject(name)
		id = p.ID
		return err
	})
	return id
}

func (e *env) tx(fn func(*store.Tx) error) {
	e.t.Helper()
	if err := e.st.Tx(context.Background(), fn); err != nil {
		e.t.Fatal(err)
	}
}

// report records a report of hex packages ("name@version") and matches it.
func (e *env) report(projectID int64, pkgs ...string) []Change {
	e.t.Helper()
	var list []pkgid.Package
	for _, s := range pkgs {
		p, err := pkgid.Parse("pkg:hex/" + s)
		if err != nil {
			e.t.Fatal(err)
		}
		list = append(list, p)
	}
	changes, err := e.sc.Report(context.Background(), projectID, store.ReportMeta{Commit: "abc"}, list)
	if err != nil {
		e.t.Fatal(err)
	}
	return changes
}

// advisory stores a Hex advisory affecting [introduced, fixed) and matches it.
func (e *env) advisory(id, modified, pkg, introduced, fixed string, extra string) []Change {
	e.t.Helper()
	raw := fmt.Sprintf(`{"id": %q, "modified": %q, "summary": "bad", %s "affected": [{"package": {"ecosystem": "Hex", "name": %q},
	  "ranges": [{"type": "SEMVER", "events": [{"introduced": %q}, {"fixed": %q}]}]}]}`,
		id, modified, extra, pkg, introduced, fixed)
	a, err := osv.Parse([]byte(raw))
	if err != nil {
		e.t.Fatal(err)
	}
	var changed []string
	e.tx(func(tx *store.Tx) error {
		ok, err := tx.UpsertAdvisory(a)
		if ok {
			changed = append(changed, a.ID)
		}
		return err
	})
	changes, err := e.sc.Advisories(context.Background(), changed)
	if err != nil {
		e.t.Fatal(err)
	}
	return changes
}

func (e *env) open(projectID int64) []store.Finding {
	var fs []store.Finding
	e.tx(func(tx *store.Tx) (err error) { fs, err = tx.OpenFindingsForProject(projectID); return })
	return fs
}

func kinds(cs []Change) string {
	s := ""
	for _, c := range cs {
		s += fmt.Sprintf("%s %s %s@%s;", c.Kind, c.Project, c.Name, c.Versions)
	}
	return s
}

func expect(t *testing.T, what string, got []Change, want string) {
	t.Helper()
	if k := kinds(got); k != want {
		t.Errorf("%s:\n got  %q\n want %q", what, k, want)
	}
}

func TestReportLifecycle(t *testing.T) {
	e := newEnv(t)
	p := e.project("cure")
	e.advisory("GHSA-1", "2026-01-01T00:00:00Z", "plug", "1.0.0", "1.5.0", "")

	expect(t, "vulnerable dependency added", e.report(p, "plug@1.2.0", "phoenix@1.7.14"), "opened cure plug@1.2.0;")
	expect(t, "bump to another affected version", e.report(p, "plug@1.3.0"), "")
	if fs := e.open(p); len(fs) != 1 || fs[0].Versions != "1.3.0" {
		t.Errorf("finding should carry the new version: %+v", fs)
	}
	expect(t, "fixed", e.report(p, "plug@1.5.0"), "resolved cure plug@1.3.0;")
	expect(t, "regressed: a new finding", e.report(p, "plug@1.4.0"), "opened cure plug@1.4.0;")
}

func TestReportMultipleVersionsOneFinding(t *testing.T) {
	e := newEnv(t)
	p := e.project("cure")
	e.advisory("GHSA-1", "2026-01-01T00:00:00Z", "plug", "1.0.0", "1.5.0", "")
	expect(t, "two affected versions", e.report(p, "plug@1.2.0", "plug@1.3.0", "plug@2.0.0"), "opened cure plug@1.2.0, 1.3.0;")
}

func TestAdvisoryMatchesExistingInventories(t *testing.T) {
	e := newEnv(t)
	a, b, c := e.project("a"), e.project("b"), e.project("c")
	e.report(a, "plug@1.2.0")
	e.report(b, "plug@1.4.0")
	e.report(c, "plug@1.6.0")

	expect(t, "new advisory", e.advisory("GHSA-1", "2026-01-01T00:00:00Z", "plug", "1.0.0", "1.5.0", ""),
		"opened a plug@1.2.0;opened b plug@1.4.0;")
	expect(t, "unchanged advisory re-synced", e.advisory("GHSA-1", "2026-01-01T00:00:00Z", "plug", "1.0.0", "1.5.0", ""), "")
	expect(t, "range narrowed", e.advisory("GHSA-1", "2026-02-01T00:00:00Z", "plug", "1.0.0", "1.3.0", ""),
		"resolved b plug@1.4.0;")
	expect(t, "withdrawn", e.advisory("GHSA-1", "2026-03-01T00:00:00Z", "plug", "1.0.0", "1.3.0", `"withdrawn": "2026-03-01T00:00:00Z",`),
		"resolved a plug@1.2.0;")
}

func TestIgnoredFinding(t *testing.T) {
	e := newEnv(t)
	p := e.project("cure")
	e.advisory("GHSA-1", "2026-01-01T00:00:00Z", "plug", "1.0.0", "1.5.0", "")
	e.report(p, "plug@1.2.0")
	f := e.open(p)[0]
	e.tx(func(tx *store.Tx) error { return tx.IgnoreFinding(f.ID, "not reachable", "", "2026-01-01T00:00:00Z") })

	expect(t, "re-report while ignored", e.report(p, "plug@1.3.0"), "")
	changes := e.advisory("GHSA-1", "2026-02-01T00:00:00Z", "plug", "1.0.0", "1.6.0", "")
	expect(t, "advisory changed", changes, "reactivated cure plug@1.3.0;")
	if e.open(p)[0].IgnoredReason != "" {
		t.Error("reactivation must clear the ignore")
	}

	f = e.open(p)[0]
	e.tx(func(tx *store.Tx) error { return tx.IgnoreFinding(f.ID, "still fine", "", "2026-02-01T00:00:00Z") })
	changes = e.report(p, "plug@2.0.0")
	expect(t, "ignored finding resolves", changes, "resolved cure plug@1.3.0;")
	if !changes[0].Quiet {
		t.Error("resolution of an ignored finding should be quiet")
	}
}

func TestChangeCarriesAlertContext(t *testing.T) {
	e := newEnv(t)
	p := e.project("cure")
	e.advisory("MAL-2026-1", "2026-01-01T00:00:00Z", "plugg", "0", "9.9.9", "")
	c := e.report(p, "plugg@1.0.0")[0]
	if c.VulnID != "MAL-2026-1" || c.Severity != osv.Critical || !c.Malicious() || c.Ecosystem != "Hex" {
		t.Errorf("change = %+v", c)
	}
	if c.Quiet {
		t.Error("a new finding is never quiet")
	}
}

func TestAliasedAdvisoriesAreOneFinding(t *testing.T) {
	e := newEnv(t)
	p := e.project("cure")
	// The Hex shape: EEF lists the GHSA, the GHSA lists the CVE.
	e.advisory("EEF-CVE-2026-1", "2026-01-01T00:00:00Z", "plug", "1.0.0", "1.5.0",
		`"aliases": ["GHSA-aaaa"], "database_specific": {"severity": "MODERATE"},`)
	e.advisory("GHSA-aaaa", "2026-01-01T00:00:00Z", "plug", "1.0.0", "1.5.0",
		`"aliases": ["CVE-2026-1"], "database_specific": {"severity": "HIGH"},`)

	changes := e.report(p, "plug@1.2.0")
	expect(t, "two advisories, one vulnerability", changes, "opened cure plug@1.2.0;")
	c := changes[0]
	if c.VulnID != "CVE-2026-1" || c.Severity != osv.High || len(c.Advisories) != 2 {
		t.Errorf("change = %+v (want key CVE-2026-1, highest severity, both advisories)", c)
	}
	if ids := c.Identifiers(); !slices.Equal(ids, []string{"CVE-2026-1", "EEF-CVE-2026-1", "GHSA-aaaa"}) {
		t.Errorf("Identifiers() = %v", ids)
	}

	expect(t, "one advisory withdrawn, the other still applies",
		e.advisory("GHSA-aaaa", "2026-02-01T00:00:00Z", "plug", "1.0.0", "1.5.0", `"aliases": ["CVE-2026-1"], "withdrawn": "2026-02-01T00:00:00Z",`), "")
	if f := e.open(p)[0]; f.AdvisoryIDs != "EEF-CVE-2026-1" || f.Severity != "medium" {
		t.Errorf("finding should narrow to the remaining advisory: %+v", f)
	}
}

func TestIgnoringAVulnerabilityCoversItsAliases(t *testing.T) {
	e := newEnv(t)
	p := e.project("cure")
	e.advisory("EEF-CVE-2026-1", "2026-01-01T00:00:00Z", "plug", "1.0.0", "1.5.0", `"aliases": ["GHSA-aaaa"],`)
	e.advisory("GHSA-aaaa", "2026-01-02T00:00:00Z", "plug", "1.0.0", "1.5.0", "")
	e.report(p, "plug@1.2.0")
	f := e.open(p)[0]
	e.tx(func(tx *store.Tx) error { return tx.IgnoreFinding(f.ID, "unreachable", "", "2026-01-02T00:00:00Z") })

	expect(t, "re-report", e.report(p, "plug@1.3.0"), "")
	expect(t, "the other advisory changes", e.advisory("EEF-CVE-2026-1", "2026-03-01T00:00:00Z", "plug", "1.0.0", "1.6.0", `"aliases": ["GHSA-aaaa"],`),
		"reactivated cure plug@1.3.0;")
}

func TestMergingAliasGroupsDoesNotRealert(t *testing.T) {
	e := newEnv(t)
	p := e.project("cure")
	e.advisory("GHSA-aaaa", "2026-01-01T00:00:00Z", "plug", "1.0.0", "1.5.0", "")
	expect(t, "first advisory", e.report(p, "plug@1.2.0"), "opened cure plug@1.2.0;")

	// A second database publishes the same flaw, naming the GHSA and a CVE:
	// the vulnerability's key becomes the CVE.
	changes := e.advisory("EEF-CVE-2026-1", "2026-01-05T00:00:00Z", "plug", "1.0.0", "1.5.0", `"aliases": ["GHSA-aaaa", "CVE-2026-1"],`)
	expect(t, "group grows", changes, "")
	fs := e.open(p)
	if len(fs) != 1 || fs[0].VulnID != "CVE-2026-1" || fs[0].AdvisoryIDs != "EEF-CVE-2026-1,GHSA-aaaa" {
		t.Errorf("finding should be re-keyed in place: %+v", fs)
	}
	expect(t, "next report", e.report(p, "plug@1.2.0"), "")
}

func TestReportContextOnOpenedFindings(t *testing.T) {
	e := newEnv(t)
	p := e.project("cure")
	e.advisory("GHSA-1", "2026-01-01T00:00:00Z", "plug", "1.0.0", "1.5.0", "")
	c := e.report(p, "plug@1.2.0")[0]
	if c.Report.Commit != "abc" {
		t.Errorf("opened by a report should carry its commit: %+v", c.Report)
	}
	e.report(p)
	e.report(p, "plug@1.2.0")
	changes := e.advisory("GHSA-2", "2026-01-01T00:00:00Z", "plug", "1.0.0", "1.5.0", "")
	if changes[0].Report.Commit != "" {
		t.Errorf("opened by a sync: no report context, got %+v", changes[0].Report)
	}
}

func TestExpireIgnores(t *testing.T) {
	e := newEnv(t)
	p := e.project("cure")
	e.advisory("GHSA-1", "2026-01-01T00:00:00Z", "plug", "1.0.0", "1.5.0", "")
	e.report(p, "plug@1.2.0")
	f := e.open(p)[0]
	until := e.clock.Add(time.Hour).Format(time.RFC3339)
	e.tx(func(tx *store.Tx) error { return tx.IgnoreFinding(f.ID, "later", until, "2026-01-01T00:00:00Z") })

	if cs, _ := e.sc.ExpireIgnores(context.Background()); len(cs) != 0 {
		t.Errorf("not yet: %+v", cs)
	}
	e.clock = e.clock.Add(2 * time.Hour)
	cs, err := e.sc.ExpireIgnores(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	expect(t, "expired", cs, "ignore expired cure plug@1.2.0;")
	if cs[0].Summary() != "bad" || e.open(p)[0].IgnoredReason != "" {
		t.Errorf("change should carry the advisory and the finding be unmuted: %+v", cs[0])
	}
}

// reportFrom records a report of full purls from a source and matches it.
func (e *env) reportFrom(projectID int64, source string, purls ...string) []Change {
	e.t.Helper()
	var list []pkgid.Package
	for _, s := range purls {
		p, err := pkgid.Parse(s)
		if err != nil {
			e.t.Fatal(err)
		}
		list = append(list, p)
	}
	changes, err := e.sc.Report(context.Background(), projectID, store.ReportMeta{Source: source}, list)
	if err != nil {
		e.t.Fatal(err)
	}
	return changes
}

// raw stores an advisory document as-is and matches it.
func (e *env) raw(doc string) []Change {
	e.t.Helper()
	a, err := osv.Parse([]byte(doc))
	if err != nil {
		e.t.Fatal(err)
	}
	var changed []string
	e.tx(func(tx *store.Tx) error {
		ok, err := tx.UpsertAdvisory(a)
		if ok {
			changed = append(changed, a.ID)
		}
		return err
	})
	changes, err := e.sc.Advisories(context.Background(), changed)
	if err != nil {
		e.t.Fatal(err)
	}
	return changes
}

func loud(cs []Change) (out []Change) {
	for _, c := range cs {
		if !c.Quiet {
			out = append(out, c)
		}
	}
	return out
}

const opensslUnfixed = `{"id": "DEBIAN-CVE-2026-9", "modified": "2026-01-01T00:00:00Z", "aliases": ["CVE-2026-9"], "summary": "openssl bug",
  "affected": [{"package": {"name": "openssl", "ecosystem": "Debian:12"},
    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}], "ecosystem_specific": {"urgency": "high"}}]}`

const opensslFixed = `{"id": "DEBIAN-CVE-2026-9", "modified": "2026-02-01T00:00:00Z", "aliases": ["CVE-2026-9"], "summary": "openssl bug",
  "affected": [{"package": {"name": "openssl", "ecosystem": "Debian:12"},
    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.18-1~deb12u1"}]}], "ecosystem_specific": {"urgency": "high"}}]}`

const libssl = "pkg:deb/debian/libssl3@3.0.17-1~deb12u2?arch=arm64&distro=debian-12.12&upstream=openssl"

func TestUnfixedFindingWaitsForAFix(t *testing.T) {
	e := newEnv(t)
	p := e.project("cure")
	e.raw(opensslUnfixed)

	changes := e.reportFrom(p, "image:ghcr.io/x/cure", libssl)
	expect(t, "opened, but unfixed", changes, "opened cure openssl@3.0.17-1~deb12u2;")
	if !changes[0].Quiet || changes[0].Fixable || changes[0].Severity != osv.High {
		t.Errorf("an unfixed finding opens quietly: %+v", changes[0])
	}
	if f := e.open(p)[0]; f.Fixable || f.Sources != "image:ghcr.io/x/cure" || f.Ecosystem != "Debian:12" {
		t.Errorf("finding = %+v", f)
	}

	changes = e.raw(opensslFixed)
	expect(t, "the advisory gains a fix", changes, "fix available cure openssl@3.0.17-1~deb12u2;")
	if changes[0].Quiet || !changes[0].Fixable {
		t.Errorf("fix available is announced: %+v", changes[0])
	}
	expect(t, "the image is rebuilt with the fix",
		loud(e.reportFrom(p, "image:ghcr.io/x/cure", "pkg:deb/debian/libssl3@3.0.18-1~deb12u1?distro=debian-12.13&upstream=openssl")),
		"resolved cure openssl@3.0.17-1~deb12u2;")
}

func TestUnfixedFindingResolvesQuietly(t *testing.T) {
	e := newEnv(t)
	p := e.project("cure")
	e.raw(opensslUnfixed)
	e.reportFrom(p, "image:ghcr.io/x/cure", libssl)
	changes := e.reportFrom(p, "image:ghcr.io/x/cure") // openssl gone from the image
	if len(changes) != 1 || changes[0].Kind != Resolved || !changes[0].Quiet {
		t.Errorf("never announced, so its resolution isn't either: %+v", changes)
	}
}

func TestMaliciousAlertsWithoutAFix(t *testing.T) {
	e := newEnv(t)
	p := e.project("cure")
	e.raw(`{"id": "MAL-2026-7", "modified": "m", "affected": [{"package": {"name": "evil", "ecosystem": "npm"}, "versions": ["1.0.0"]}]}`)
	changes := e.reportFrom(p, "", "pkg:npm/evil@1.0.0")
	if len(changes) != 1 || changes[0].Quiet || changes[0].Fixable {
		t.Errorf("malicious packages are announced though nothing fixes them: %+v", changes)
	}
}

func TestSourcesDontReplaceEachOther(t *testing.T) {
	e := newEnv(t)
	p := e.project("cure")
	e.advisory("GHSA-1", "2026-01-01T00:00:00Z", "plug", "1.0.0", "1.5.0", "")
	e.raw(opensslFixed)

	expect(t, "repo report", e.reportFrom(p, "", "pkg:hex/plug@1.2.0"), "opened cure plug@1.2.0;")
	expect(t, "image report keeps the repo's finding", e.reportFrom(p, "image:ghcr.io/x/cure", libssl),
		"opened cure openssl@3.0.17-1~deb12u2;")
	expect(t, "repo report keeps the image's finding", e.reportFrom(p, "", "pkg:hex/plug@1.3.0"), "")

	// The same package in both sources is one finding naming both.
	e.reportFrom(p, "image:ghcr.io/x/cure", libssl, "pkg:hex/plug@1.2.0")
	for _, f := range e.open(p) {
		if f.Name == "plug" && (f.Sources != "image:ghcr.io/x/cure,repo" || f.Versions != "1.2.0, 1.3.0" && f.Versions != "1.3.0, 1.2.0") {
			t.Errorf("plug finding = %+v", f)
		}
	}
}
