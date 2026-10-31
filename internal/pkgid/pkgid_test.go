package pkgid

import (
	"errors"
	"slices"
	"testing"
)

func TestParse(t *testing.T) {
	cases := []struct {
		purl string
		want Package
	}{
		{"pkg:hex/phoenix@1.7.14", Package{"Hex", "phoenix", "1.7.14"}},
		{"pkg:cargo/serde@1.0.200", Package{"crates.io", "serde", "1.0.200"}},
		{"pkg:gem/rack@3.0.8", Package{"RubyGems", "rack", "3.0.8"}},
		{"pkg:npm/left-pad@1.3.0", Package{"npm", "left-pad", "1.3.0"}},
		{"pkg:npm/%40babel/core@7.24.0", Package{"npm", "@babel/core", "7.24.0"}},
		{"pkg:golang/golang.org/x/net@v0.23.0", Package{"Go", "golang.org/x/net", "0.23.0"}},
		{"pkg:golang/stdlib@go1.22.1", Package{"Go", "stdlib", "1.22.1"}},
		{"pkg:pypi/Django@4.2.0", Package{"PyPI", "django", "4.2.0"}},
	}
	for _, c := range cases {
		got, err := Parse(c.purl)
		if err != nil {
			t.Errorf("Parse(%q): %v", c.purl, err)
			continue
		}
		if got != c.want {
			t.Errorf("Parse(%q) = %+v, want %+v", c.purl, got, c.want)
		}
	}
}

func TestParseRejects(t *testing.T) {
	var unsupported ErrUnsupported
	if _, err := Parse("pkg:deb/debian/curl@7.88.1"); !errors.As(err, &unsupported) {
		t.Errorf("deb purl: got %v, want ErrUnsupported", err)
	}
	if _, err := Parse("pkg:hex/phoenix"); err == nil {
		t.Error("versionless purl: want error")
	}
	if _, err := Parse("not a purl"); err == nil {
		t.Error("garbage: want error")
	}
}

func TestNameKey(t *testing.T) {
	cases := []struct{ eco, a, b string }{
		{"PyPI", "Django_REST.framework", "django-rest-framework"},
		{"Hex", "Phoenix", "phoenix"},
		{"npm", "@Babel/Core", "@babel/core"},
	}
	for _, c := range cases {
		if NameKey(c.eco, c.a) != NameKey(c.eco, c.b) {
			t.Errorf("%s: %q and %q should share a key", c.eco, c.a, c.b)
		}
	}
	if NameKey("RubyGems", "Rack") == NameKey("RubyGems", "rack") {
		t.Error("RubyGems names are case-sensitive")
	}
}

func TestParseOSPackages(t *testing.T) {
	cases := []struct {
		purl string
		want Package
	}{
		// Real syft output. Alpine subpackages name their origin in upstream=.
		{"pkg:apk/alpine/libssl3@3.3.7-r0?arch=aarch64&distro=alpine-3.20.10&upstream=openssl", Package{"Alpine:v3.20", "openssl", "3.3.7-r0"}},
		{"pkg:apk/alpine/busybox@1.36.1-r31?arch=aarch64&distro=alpine-3.20.10", Package{"Alpine:v3.20", "busybox", "1.36.1-r31"}},
		// Debian: binNMU binaries (+b13) are matched by their source version.
		{"pkg:deb/debian/bash@5.2.15-2%2Bb13?arch=arm64&distro=debian-12.15&upstream=bash%405.2.15-2", Package{"Debian:12", "bash", "5.2.15-2"}},
		{"pkg:deb/debian/bsdutils@1%3A2.38.1-5%2Bdeb12u3?arch=arm64&distro=debian-12.15&upstream=util-linux%402.38.1-5%2Bdeb12u3", Package{"Debian:12", "util-linux", "2.38.1-5+deb12u3"}},
		{"pkg:deb/debian/libc6@2.36-9%2Bdeb12u14?arch=arm64&distro=debian-12.15&upstream=glibc", Package{"Debian:12", "glibc", "2.36-9+deb12u14"}},
		{"pkg:deb/debian/tzdata@2025b-0%2Bdeb12u2?distro=debian-12", Package{"Debian:12", "tzdata", "2025b-0+deb12u2"}},
	}
	for _, c := range cases {
		got, err := Parse(c.purl)
		if err != nil {
			t.Errorf("Parse(%q): %v", c.purl, err)
			continue
		}
		if got != c.want {
			t.Errorf("Parse(%q) = %+v, want %+v", c.purl, got, c.want)
		}
		if !IsOS(got.Ecosystem) {
			t.Errorf("%s should be an OS ecosystem", got.Ecosystem)
		}
	}
	if IsOS("npm") || IsOS("crates.io") {
		t.Error("language ecosystems are not OS ecosystems")
	}

	var unsupported ErrUnsupported
	for _, purl := range []string{
		"pkg:deb/ubuntu/bash@5.1-6ubuntu1?distro=ubuntu-22.04", // Ubuntu isn't synced
		"pkg:apk/alpine/busybox@1.36.1-r31",                    // no release: can't pick advisories
	} {
		if _, err := Parse(purl); !errors.As(err, &unsupported) {
			t.Errorf("Parse(%q) = %v, want ErrUnsupported", purl, err)
		}
	}
}

func TestSyncEcosystems(t *testing.T) {
	got := SyncEcosystems()
	for _, want := range []string{"Hex", "npm", "Alpine", "Debian"} {
		if !slices.Contains(got, want) {
			t.Errorf("SyncEcosystems() = %v, missing %s", got, want)
		}
	}
	if SyncBase("Alpine:v3.20") != "Alpine" || SyncBase("Debian:12") != "Debian" || SyncBase("Hex") != "Hex" {
		t.Error("SyncBase should drop the release")
	}
}
