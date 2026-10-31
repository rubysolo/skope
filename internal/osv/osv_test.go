package osv

import (
	"testing"

	"github.com/rubysolo/skope/internal/pkgid"
)

// hexCore is trimmed from the real EEF-CVE-2026-103502: a SEMVER range plus a
// GIT range that must be ignored.
const hexCore = `{
  "id": "EEF-CVE-2026-103502",
  "modified": "2026-10-12T13:41:07.038113018Z",
  "aliases": ["CVE-2026-103502", "GHSA-p26c-h8c2-rwqj"],
  "summary": "hex_core's default HTTP adapter doesn't verify TLS certificates",
  "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N"}],
  "affected": [
    {"package": {"name": "hex_core", "ecosystem": "Hex"},
     "ranges": [{"type": "SEMVER", "events": [{"introduced": "0.1.0"}, {"fixed": "0.20.0"}]}]},
    {"ranges": [{"type": "GIT", "repo": "https://github.com/hexpm/hex_core",
      "events": [{"introduced": "fbb6d9de"}, {"fixed": "b7b3a42d"}]}]}
  ]
}`

func mustParse(t *testing.T, s string) *Advisory {
	t.Helper()
	a, err := Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func pkg(eco, name, version string) pkgid.Package {
	return pkgid.Package{Ecosystem: eco, Name: name, Version: version}
}

func TestAffectsSemverRange(t *testing.T) {
	a := mustParse(t, hexCore)
	cases := map[string]bool{"0.0.9": false, "0.1.0": true, "0.19.0": true, "0.20.0": false, "1.0.0": false}
	for v, want := range cases {
		got, err := a.Affects(pkg("Hex", "hex_core", v))
		if err != nil {
			t.Fatal(err)
		}
		if got.Affected != want {
			t.Errorf("hex_core@%s: got %v, want %v", v, got, want)
		}
	}
	if got, _ := a.Affects(pkg("Hex", "phoenix", "0.5.0")); got.Affected {
		t.Error("a different package must not be affected")
	}
	if got, _ := a.Affects(pkg("npm", "hex_core", "0.5.0")); got.Affected {
		t.Error("the same name in another ecosystem must not be affected")
	}
}

func TestAffectsEcosystemRangesUnordered(t *testing.T) {
	// Two introduced/fixed windows, events deliberately out of order, with
	// last_affected closing the second window inclusively.
	a := mustParse(t, `{"id": "X", "affected": [{"package": {"name": "rack", "ecosystem": "RubyGems"},
	  "ranges": [{"type": "ECOSYSTEM", "events": [
	    {"introduced": "3.0.0"}, {"fixed": "2.2.8.1"}, {"introduced": "0"}, {"last_affected": "3.0.9"}]}]}]}`)
	cases := map[string]bool{
		"1.0.0": true, "2.2.8": true, "2.2.8.1": false, "2.9.0": false,
		"3.0.0": true, "3.0.9": true, "3.0.9.1": false, "3.1.0": false,
	}
	for v, want := range cases {
		if got, err := a.Affects(pkg("RubyGems", "rack", v)); err != nil || got.Affected != want {
			t.Errorf("rack@%s: got %v (%v), want %v", v, got, err, want)
		}
	}
}

func TestAffectsExplicitVersions(t *testing.T) {
	a := mustParse(t, `{"id": "MAL-2025-1", "affected": [{"package": {"name": "Evil_Pkg", "ecosystem": "PyPI"},
	  "versions": ["1.0.1"]}]}`)
	if got, _ := a.Affects(pkg("PyPI", "evil-pkg", "1.0.1")); !got.Affected {
		t.Error("listed version, normalised name: want affected")
	}
	if got, _ := a.Affects(pkg("PyPI", "evil-pkg", "1.0.2")); got.Affected {
		t.Error("unlisted version: want unaffected")
	}
}

func TestAffectsPEP440(t *testing.T) {
	a := mustParse(t, `{"id": "PYSEC-1", "affected": [{"package": {"name": "django", "ecosystem": "PyPI"},
	  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "4.2"}, {"fixed": "4.2.11"}]}]}]}`)
	cases := map[string]bool{"4.2rc1": false, "4.2.0": true, "4.2.10": true, "4.2.11": false}
	for v, want := range cases {
		if got, err := a.Affects(pkg("PyPI", "django", v)); err != nil || got.Affected != want {
			t.Errorf("django@%s: got %v (%v), want %v", v, got, err, want)
		}
	}
}

func TestAffectsWithdrawn(t *testing.T) {
	a := mustParse(t, `{"id": "X", "withdrawn": "2026-01-01T00:00:00Z", "affected": [{"package": {"name": "rack", "ecosystem": "RubyGems"}, "versions": ["1.0.0"]}]}`)
	if got, _ := a.Affects(pkg("RubyGems", "rack", "1.0.0")); got.Affected {
		t.Error("withdrawn advisories affect nothing")
	}
}

func TestPackages(t *testing.T) {
	a := mustParse(t, hexCore)
	got := a.Packages()
	if len(got) != 1 || got[0] != (PackageRef{Ecosystem: "Hex", Key: "hex_core"}) {
		t.Errorf("Packages() = %+v", got)
	}
}

func TestSeverity(t *testing.T) {
	cases := []struct {
		name, json string
		want       Severity
	}{
		{"cvss v4", hexCore, Medium}, // 5.9: attack requirements and user interaction
		{"cvss v4 reference", `{"id": "X", "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}]}`, Critical},
		{"cvss v3", `{"id": "X", "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}`, Critical},
		{"ghsa label", `{"id": "GHSA-x", "database_specific": {"severity": "MODERATE"}}`, Medium},
		{"malicious", `{"id": "MAL-2025-1"}`, Critical},
		{"nothing", `{"id": "RUSTSEC-2025-1"}`, Unknown},
		{"per-package vector", `{"id": "X", "affected": [{"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"}]}]}`, Low},
	}
	for _, c := range cases {
		if got := mustParse(t, c.json).Severity(); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestMalicious(t *testing.T) {
	if !mustParse(t, `{"id": "MAL-2025-1"}`).Malicious() {
		t.Error("MAL- prefix is malicious")
	}
	if mustParse(t, hexCore).Malicious() {
		t.Error("EEF advisory is not malicious")
	}
}

// curlAlpine is shaped like the real ALPINE-CVE-2026-86411: one entry per release.
const curlAlpine = `{"id": "ALPINE-CVE-2026-1", "modified": "m", "aliases": ["CVE-2026-1"],
  "affected": [
    {"package": {"name": "curl", "ecosystem": "Alpine:v3.23"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "8.23.0-r0"}]}]},
    {"package": {"name": "curl", "ecosystem": "Alpine:v3.24"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "8.23.0-r1"}]}]}
  ]}`

func TestAffectsIsPerDistroRelease(t *testing.T) {
	a := mustParse(t, curlAlpine)
	cases := []struct {
		eco, version string
		want         bool
	}{
		{"Alpine:v3.24", "8.22.1-r0", true},
		{"Alpine:v3.24", "8.23.0-r0", true}, // v3.24's fix is r1
		{"Alpine:v3.24", "8.23.0-r1", false},
		{"Alpine:v3.23", "8.23.0-r0", false},
		{"Alpine:v3.20", "8.0.0-r0", false}, // release not listed: not affected
	}
	for _, c := range cases {
		got, err := a.Affects(pkg(c.eco, "curl", c.version))
		if err != nil || got.Affected != c.want {
			t.Errorf("curl@%s on %s: got %+v (%v), want affected=%v", c.version, c.eco, got, err, c.want)
		}
	}
	refs := a.Packages()
	if len(refs) != 2 || refs[0] != (PackageRef{Ecosystem: "Alpine:v3.23", Key: "curl"}) {
		t.Errorf("Packages() should index each release: %+v", refs)
	}
}

func TestAffectsDebianUnfixedAndEpochs(t *testing.T) {
	a := mustParse(t, `{"id": "DEBIAN-CVE-2026-2", "modified": "m", "affected": [
	  {"package": {"name": "util-linux", "ecosystem": "Debian:12"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
	   "ecosystem_specific": {"urgency": "unimportant"}},
	  {"package": {"name": "util-linux", "ecosystem": "Debian:13"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1:2.41-5"}]}],
	   "ecosystem_specific": {"urgency": "high"}}]}`)

	m, err := a.Affects(pkg("Debian:12", "util-linux", "2.38.1-5+deb12u3"))
	if err != nil || !m.Affected || m.Fixable {
		t.Errorf("Debian 12, no fix published: %+v %v", m, err)
	}
	m, _ = a.Affects(pkg("Debian:13", "util-linux", "2.41-4"))
	if !m.Affected || !m.Fixable {
		t.Errorf("Debian 13 below the epoch-1 fix: %+v", m)
	}
	m, _ = a.Affects(pkg("Debian:13", "util-linux", "1:2.41-5"))
	if m.Affected {
		t.Errorf("Debian 13 at the fix: %+v", m)
	}
	if got := a.Severity(); got != High {
		t.Errorf("severity falls back to the highest urgency: got %v", got)
	}
}

func TestFixable(t *testing.T) {
	fixed := mustParse(t, hexCore)
	if m, _ := fixed.Affects(pkg("Hex", "hex_core", "0.10.0")); !m.Fixable {
		t.Errorf("a fixed event above the version: %+v", m)
	}
	open := mustParse(t, `{"id": "GHSA-x", "affected": [{"package": {"name": "left-pad", "ecosystem": "npm"},
	  "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"last_affected": "1.3.0"}]}]}]}`)
	if m, _ := open.Affects(pkg("npm", "left-pad", "1.2.0")); !m.Affected || m.Fixable {
		t.Errorf("last_affected names no fix: %+v", m)
	}
	listed := mustParse(t, `{"id": "MAL-2026-1", "affected": [{"package": {"name": "evil", "ecosystem": "npm"}, "versions": ["1.0.0"]}]}`)
	if m, _ := listed.Affects(pkg("npm", "evil", "1.0.0")); !m.Affected || m.Fixable {
		t.Errorf("a versions list names no fix: %+v", m)
	}
}

func TestCompactDropsDistroVersionLists(t *testing.T) {
	a := mustParse(t, `{"id": "DEBIAN-CVE-1", "affected": [
	  {"package": {"name": "openssl", "ecosystem": "Debian:12"}, "versions": ["3.0.1-1", "3.0.2-1"],
	   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.3-1"}]}]},
	  {"package": {"name": "plug", "ecosystem": "Hex"}, "versions": ["1.0.0"],
	   "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.0.1"}]}]}]}`)
	c := a.Compact()
	if c.Affected[0].Versions != nil || len(c.Affected[1].Versions) != 1 || len(a.Affected[0].Versions) != 2 {
		t.Errorf("drop only the distro list, without touching the original: %+v / %+v", c.Affected, a.Affected)
	}
	if m, _ := c.Affects(pkg("Debian:12", "openssl", "3.0.2-1")); !m.Affected {
		t.Error("the range still decides")
	}
}
