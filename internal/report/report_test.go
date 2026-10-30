package report

import (
	"testing"

	"github.com/rubysolo/skope/internal/pkgid"
)

func TestParsePurlList(t *testing.T) {
	r, err := Parse([]byte(`{"packages": ["pkg:hex/phoenix@1.7.14", "pkg:hex/phoenix@1.7.14", "pkg:cargo/serde@1.0.200"]}`))
	if err != nil {
		t.Fatal(err)
	}
	want := []pkgid.Package{{Ecosystem: "Hex", Name: "phoenix", Version: "1.7.14"}, {Ecosystem: "crates.io", Name: "serde", Version: "1.0.200"}}
	if len(r.Packages) != len(want) {
		t.Fatalf("got %+v, want %+v (duplicates collapse)", r.Packages, want)
	}
	for i := range want {
		if r.Packages[i] != want[i] {
			t.Errorf("package %d = %+v, want %+v", i, r.Packages[i], want[i])
		}
	}
}

func TestParseCycloneDX(t *testing.T) {
	// Shaped like syft output: nested components, an unsupported purl type, a
	// component without a purl.
	r, err := Parse([]byte(`{
	  "bomFormat": "CycloneDX", "specVersion": "1.6",
	  "components": [
	    {"type": "library", "name": "phoenix", "purl": "pkg:hex/phoenix@1.7.14"},
	    {"type": "library", "name": "checkout", "purl": "pkg:github/actions/checkout@v4"},
	    {"type": "file", "name": "/app/bin/thing"},
	    {"type": "library", "name": "outer", "purl": "pkg:npm/outer@1.0.0",
	     "components": [{"type": "library", "name": "inner", "purl": "pkg:npm/%40scope/inner@2.0.0"}]}
	  ]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Packages) != 3 {
		t.Fatalf("got %d packages %+v, want 3", len(r.Packages), r.Packages)
	}
	if r.Packages[2] != (pkgid.Package{Ecosystem: "npm", Name: "@scope/inner", Version: "2.0.0"}) {
		t.Errorf("nested component: got %+v", r.Packages[2])
	}
	if r.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1 (the github purl)", r.Skipped)
	}
}

func TestParseRejects(t *testing.T) {
	for _, body := range []string{``, `nope`, `{}`, `{"packages": []}`, `{"packages": ["pkg:hex/phoenix"]}`} {
		if _, err := Parse([]byte(body)); err == nil {
			t.Errorf("Parse(%q): want error", body)
		}
	}
}
