// Package pkgid maps package URLs (purls) onto OSV's package identity: an
// ecosystem name, a package name, and a version in the form OSV records it.
package pkgid

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/package-url/packageurl-go"
)

// Package is one package version in an inventory.
type Package struct {
	Ecosystem string // OSV ecosystem name, e.g. "Hex", "crates.io"
	Name      string // name as OSV spells it
	Version   string
}

// Key is the case- and spelling-normalised name used to match an inventory
// package against advisories. Two spellings of the same package share a key.
func (p Package) Key() string { return NameKey(p.Ecosystem, p.Name) }

func (p Package) String() string { return fmt.Sprintf("%s:%s@%s", p.Ecosystem, p.Name, p.Version) }

// ecosystems maps purl types to OSV ecosystem names. Only these are supported.
var ecosystems = map[string]string{
	"hex":    "Hex",
	"cargo":  "crates.io",
	"gem":    "RubyGems",
	"npm":    "npm",
	"golang": "Go",
	"pypi":   "PyPI",
}

// Ecosystems lists the supported OSV ecosystem names.
func Ecosystems() []string {
	return []string{"Hex", "crates.io", "RubyGems", "npm", "Go", "PyPI"}
}

// ErrUnsupported reports a purl whose type Skope does not watch.
type ErrUnsupported struct{ Type string }

func (e ErrUnsupported) Error() string { return "unsupported purl type " + e.Type }

// Parse converts a purl into a Package. Purls without a version are rejected:
// an inventory entry with no version can't be matched against ranges.
func Parse(s string) (Package, error) {
	u, err := packageurl.FromString(s)
	if err != nil {
		return Package{}, fmt.Errorf("parse purl %q: %w", s, err)
	}
	eco, ok := ecosystems[u.Type]
	if !ok {
		return Package{}, ErrUnsupported{Type: u.Type}
	}
	if u.Version == "" {
		return Package{}, fmt.Errorf("purl %q has no version", s)
	}
	p := Package{Ecosystem: eco, Name: u.Name, Version: u.Version}
	switch eco {
	case "npm":
		if u.Namespace != "" {
			p.Name = u.Namespace + "/" + u.Name // namespace is "@scope"
		}
	case "Go":
		if u.Namespace != "" {
			p.Name = u.Namespace + "/" + u.Name
		}
		p.Version = goVersion(p.Name, p.Version)
	}
	return p, nil
}

// goVersion strips the prefixes Go tooling puts on versions ("v1.2.3",
// "go1.22.0" for the standard library); OSV records Go versions bare.
func goVersion(name, v string) string {
	if name == "stdlib" {
		return strings.TrimPrefix(v, "go")
	}
	return strings.TrimPrefix(v, "v")
}

var pypiSeparators = regexp.MustCompile(`[-_.]+`)

// NameKey normalises a package name per ecosystem so that matching ignores
// spellings the registry itself treats as equal.
func NameKey(ecosystem, name string) string {
	switch ecosystem {
	case "PyPI": // PEP 503
		return pypiSeparators.ReplaceAllString(strings.ToLower(name), "-")
	case "Hex", "npm", "crates.io":
		return strings.ToLower(name)
	default: // RubyGems and Go module paths are case-sensitive
		return name
	}
}
