// Package osv models OSV advisories and decides whether one affects a package.
package osv

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/semantic"

	"github.com/rubysolo/skope/internal/pkgid"
)

// Advisory is the subset of the OSV schema Skope uses.
type Advisory struct {
	ID               string           `json:"id"`
	Modified         string           `json:"modified"`
	Withdrawn        string           `json:"withdrawn,omitempty"`
	Aliases          []string         `json:"aliases,omitempty"`
	Summary          string           `json:"summary,omitempty"`
	Scores           []SeverityScore  `json:"severity,omitempty"`
	Affected         []Affected       `json:"affected,omitempty"`
	DatabaseSpecific DatabaseSpecific `json:"database_specific,omitempty"`
}

type Affected struct {
	Package  Package         `json:"package"`
	Ranges   []Range         `json:"ranges,omitempty"`
	Versions []string        `json:"versions,omitempty"`
	Severity []SeverityScore `json:"severity,omitempty"`
}

type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

type SeverityScore struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type DatabaseSpecific struct {
	Severity string `json:"severity,omitempty"` // GHSA's LOW/MODERATE/HIGH/CRITICAL label
}

// Parse decodes one OSV JSON document.
func Parse(data []byte) (*Advisory, error) {
	var a Advisory
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, fmt.Errorf("decode advisory: %w", err)
	}
	if a.ID == "" {
		return nil, fmt.Errorf("advisory has no id")
	}
	return &a, nil
}

// Malicious reports whether the advisory is a Malicious Package Advisory.
func (a *Advisory) Malicious() bool { return strings.HasPrefix(a.ID, "MAL-") }

// PackageRef identifies a package across all its versions, for indexing.
type PackageRef struct {
	Ecosystem string
	Key       string // pkgid.NameKey
}

// Packages lists the distinct packages the advisory names in a supported
// ecosystem.
func (a *Advisory) Packages() []PackageRef {
	var refs []PackageRef
	for _, af := range a.Affected {
		eco := baseEcosystem(af.Package.Ecosystem)
		if af.Package.Name == "" || !slices.Contains(pkgid.Ecosystems(), eco) {
			continue
		}
		ref := PackageRef{Ecosystem: eco, Key: pkgid.NameKey(eco, af.Package.Name)}
		if !slices.Contains(refs, ref) {
			refs = append(refs, ref)
		}
	}
	return refs
}

// Affects reports whether p's version falls in any of the advisory's affected
// versions or SEMVER/ECOSYSTEM ranges. GIT ranges can't be evaluated against a
// registry version and are ignored.
func (a *Advisory) Affects(p pkgid.Package) (bool, error) {
	if a.Withdrawn != "" {
		return false, nil
	}
	for _, af := range a.Affected {
		eco := baseEcosystem(af.Package.Ecosystem)
		if eco != p.Ecosystem || pkgid.NameKey(eco, af.Package.Name) != p.Key() {
			continue
		}
		if slices.Contains(af.Versions, p.Version) {
			return true, nil
		}
		for _, r := range af.Ranges {
			if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
				continue
			}
			hit, err := inRange(r, eco, p.Version)
			if err != nil {
				return false, fmt.Errorf("%s: %s: %w", a.ID, p, err)
			}
			if hit {
				return true, nil
			}
		}
	}
	return false, nil
}

// baseEcosystem drops OSV's ":suffix" qualifiers (e.g. "Debian:11").
func baseEcosystem(e string) string {
	base, _, _ := strings.Cut(e, ":")
	return base
}

type parsedEvent struct {
	v    semantic.Version // nil for introduced "0", which sorts first
	kind string
}

// inRange evaluates one range: events are sorted by version and the last one
// at or below v decides whether v is inside an affected window.
func inRange(r Range, ecosystem, version string) (bool, error) {
	parse := func(s string) (semantic.Version, error) {
		if r.Type == "SEMVER" {
			return semantic.ParseSemverVersion(s), nil
		}
		return semantic.Parse(s, ecosystem)
	}
	v, err := parse(version)
	if err != nil {
		return false, fmt.Errorf("parse version %q: %w", version, err)
	}

	events := make([]parsedEvent, 0, len(r.Events))
	for _, e := range r.Events {
		kind, raw := "introduced", e.Introduced
		switch {
		case e.Fixed != "":
			kind, raw = "fixed", e.Fixed
		case e.LastAffected != "":
			kind, raw = "last_affected", e.LastAffected
		case e.Introduced == "":
			continue // limit, or an empty event
		}
		if kind == "introduced" && raw == "0" {
			events = append(events, parsedEvent{kind: kind})
			continue
		}
		ev, err := parse(raw)
		if err != nil {
			return false, fmt.Errorf("parse event %q: %w", raw, err)
		}
		events = append(events, parsedEvent{v: ev, kind: kind})
	}
	var sortErr error
	slices.SortStableFunc(events, func(x, y parsedEvent) int {
		switch {
		case x.v == nil && y.v == nil:
			return 0
		case x.v == nil:
			return -1
		case y.v == nil:
			return 1
		}
		c, err := x.v.Compare(y.v)
		if err != nil {
			sortErr = err
		}
		return c
	})
	if sortErr != nil {
		return false, sortErr
	}

	affected := false
	for _, e := range events {
		c := 1 // version vs. event; "0" is below everything
		if e.v != nil {
			if c, err = v.Compare(e.v); err != nil {
				return false, err
			}
		}
		switch e.kind {
		case "introduced":
			if c >= 0 {
				affected = true
			}
		case "fixed":
			if c >= 0 {
				affected = false
			}
		case "last_affected":
			if c > 0 {
				affected = false
			}
		}
	}
	return affected, nil
}
