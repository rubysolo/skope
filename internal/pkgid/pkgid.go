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
	"apk":    "Alpine",
	"deb":    "Debian",
}

// SyncEcosystems lists the ecosystems whose advisories Skope syncs, as OSV
// names its exports. A distribution's export covers all its releases.
func SyncEcosystems() []string {
	return []string{"Hex", "crates.io", "RubyGems", "npm", "Go", "PyPI", "Alpine", "Debian"}
}

// IsOS reports whether an ecosystem is an operating system release
// ("Alpine:v3.24", "Debian:12") rather than a language registry.
func IsOS(ecosystem string) bool {
	return strings.HasPrefix(ecosystem, "Alpine:") || strings.HasPrefix(ecosystem, "Debian:")
}

// SyncBase is the export an ecosystem's advisories come from: the
// distribution for an OS release, the ecosystem itself otherwise.
func SyncBase(ecosystem string) string {
	base, _, _ := strings.Cut(ecosystem, ":")
	return base
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
	if eco == "Alpine" || eco == "Debian" {
		return osPackage(u, eco)
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

// osPackage identifies a distribution package the way its advisories do: by
// release (from the distro qualifier) and by source package, whose name and
// version syft records in the upstream qualifier when they differ from the
// binary package's.
func osPackage(u packageurl.PackageURL, eco string) (Package, error) {
	q := u.Qualifiers.Map()
	release, ok := osRelease(eco, u.Namespace, q["distro"])
	if !ok {
		return Package{}, ErrUnsupported{Type: u.Type + "/" + u.Namespace}
	}
	p := Package{Ecosystem: release, Name: u.Name, Version: u.Version}
	if up := q["upstream"]; up != "" {
		name, version, hasVersion := strings.Cut(up, "@")
		p.Name = name
		if hasVersion {
			p.Version = version
		}
	}
	return p, nil
}

// osRelease maps syft's distro qualifier ("alpine-3.20.10", "debian-12.15")
// to OSV's ecosystem ("Alpine:v3.20", "Debian:12").
func osRelease(eco, namespace, distro string) (string, bool) {
	switch {
	case eco == "Alpine" && namespace == "alpine":
		v, ok := strings.CutPrefix(distro, "alpine-")
		parts := strings.Split(v, ".")
		if !ok || len(parts) < 2 {
			return "", false
		}
		return "Alpine:v" + parts[0] + "." + parts[1], true
	case eco == "Debian" && namespace == "debian":
		v, ok := strings.CutPrefix(distro, "debian-")
		major, _, _ := strings.Cut(v, ".")
		if !ok || major == "" {
			return "", false
		}
		return "Debian:" + major, true
	}
	return "", false
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
