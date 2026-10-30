package pkgid

import (
	"errors"
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
