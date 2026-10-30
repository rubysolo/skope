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
		if got != want {
			t.Errorf("hex_core@%s: got %v, want %v", v, got, want)
		}
	}
	if got, _ := a.Affects(pkg("Hex", "phoenix", "0.5.0")); got {
		t.Error("a different package must not be affected")
	}
	if got, _ := a.Affects(pkg("npm", "hex_core", "0.5.0")); got {
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
		if got, err := a.Affects(pkg("RubyGems", "rack", v)); err != nil || got != want {
			t.Errorf("rack@%s: got %v (%v), want %v", v, got, err, want)
		}
	}
}

func TestAffectsExplicitVersions(t *testing.T) {
	a := mustParse(t, `{"id": "MAL-2025-1", "affected": [{"package": {"name": "Evil_Pkg", "ecosystem": "PyPI"},
	  "versions": ["1.0.1"]}]}`)
	if got, _ := a.Affects(pkg("PyPI", "evil-pkg", "1.0.1")); !got {
		t.Error("listed version, normalised name: want affected")
	}
	if got, _ := a.Affects(pkg("PyPI", "evil-pkg", "1.0.2")); got {
		t.Error("unlisted version: want unaffected")
	}
}

func TestAffectsPEP440(t *testing.T) {
	a := mustParse(t, `{"id": "PYSEC-1", "affected": [{"package": {"name": "django", "ecosystem": "PyPI"},
	  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "4.2"}, {"fixed": "4.2.11"}]}]}]}`)
	cases := map[string]bool{"4.2rc1": false, "4.2.0": true, "4.2.10": true, "4.2.11": false}
	for v, want := range cases {
		if got, err := a.Affects(pkg("PyPI", "django", v)); err != nil || got != want {
			t.Errorf("django@%s: got %v (%v), want %v", v, got, err, want)
		}
	}
}

func TestAffectsWithdrawn(t *testing.T) {
	a := mustParse(t, `{"id": "X", "withdrawn": "2026-01-01T00:00:00Z", "affected": [{"package": {"name": "rack", "ecosystem": "RubyGems"}, "versions": ["1.0.0"]}]}`)
	if got, _ := a.Affects(pkg("RubyGems", "rack", "1.0.0")); got {
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
