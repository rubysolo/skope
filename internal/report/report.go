// Package report decodes a project's report body into an inventory.
package report

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/rubysolo/skope/internal/pkgid"
)

// Report is a decoded report body.
type Report struct {
	Packages []pkgid.Package // de-duplicated, in first-seen order
	Skipped  int             // purls of unsupported types (GitHub Actions, OS packages, …)
}

type body struct {
	BOMFormat  string      `json:"bomFormat"`
	Components []component `json:"components"`
	Purls      []string    `json:"packages"`
}

type component struct {
	Purl       string      `json:"purl"`
	Components []component `json:"components"`
}

// Parse accepts a CycloneDX JSON SBOM or {"packages": [purl, …]}. In a purl
// list every entry must be valid; an SBOM is generated, so entries Skope can't
// use are skipped rather than failing the report.
func Parse(data []byte) (*Report, error) {
	var b body
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("decode report: %w", err)
	}
	r := &Report{}
	seen := map[pkgid.Package]bool{}
	add := func(p pkgid.Package) {
		if !seen[p] {
			seen[p] = true
			r.Packages = append(r.Packages, p)
		}
	}

	switch {
	case b.BOMFormat == "CycloneDX":
		var walk func([]component)
		walk = func(cs []component) {
			for _, c := range cs {
				if c.Purl != "" {
					if p, err := pkgid.Parse(c.Purl); err == nil {
						add(p)
					} else {
						r.Skipped++
					}
				}
				walk(c.Components)
			}
		}
		walk(b.Components)
	case len(b.Purls) > 0:
		for _, s := range b.Purls {
			p, err := pkgid.Parse(s)
			var unsupported pkgid.ErrUnsupported
			switch {
			case errors.As(err, &unsupported):
				r.Skipped++
			case err != nil:
				return nil, err
			default:
				add(p)
			}
		}
	default:
		return nil, errors.New("report is neither a CycloneDX SBOM nor a purl list")
	}

	if len(r.Packages) == 0 {
		return nil, errors.New("report contains no packages in a supported ecosystem")
	}
	return r, nil
}
