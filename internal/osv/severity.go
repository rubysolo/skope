package osv

import (
	"strings"

	cvss30 "github.com/pandatix/go-cvss/30"
	cvss31 "github.com/pandatix/go-cvss/31"
	cvss40 "github.com/pandatix/go-cvss/40"
)

// Severity is Skope's coarse rating of an advisory.
type Severity int

const (
	Unknown Severity = iota
	Low
	Medium
	High
	Critical
)

func (s Severity) String() string {
	return [...]string{"unknown", "low", "medium", "high", "critical"}[s]
}

// ParseSeverity is the inverse of String; unrecognised input is Unknown.
func ParseSeverity(s string) Severity {
	switch strings.ToLower(s) {
	case "low":
		return Low
	case "medium", "moderate":
		return Medium
	case "high":
		return High
	case "critical":
		return Critical
	}
	return Unknown
}

// Urgent reports whether a finding at this severity warrants a phone push.
// Unknown counts: staying quiet about an unrated advisory is the worse failure.
func (s Severity) Urgent() bool { return s == Unknown || s >= High }

// Severity rates the advisory: Malicious Package Advisories are always
// critical; otherwise the highest CVSS score among its vectors, falling back
// to GHSA's label.
func (a *Advisory) Severity() Severity {
	if a.Malicious() {
		return Critical
	}
	scores := append([]SeverityScore{}, a.Scores...)
	for _, af := range a.Affected {
		scores = append(scores, af.Severity...)
	}
	best := -1.0
	for _, s := range scores {
		if score, ok := cvssScore(s); ok && score > best {
			best = score
		}
	}
	if best >= 0 {
		return fromScore(best)
	}
	return ParseSeverity(a.DatabaseSpecific.Severity)
}

func cvssScore(s SeverityScore) (float64, bool) {
	switch {
	case s.Type == "CVSS_V4":
		if c, err := cvss40.ParseVector(s.Score); err == nil {
			return c.Score(), true
		}
	case s.Type == "CVSS_V3" && strings.HasPrefix(s.Score, "CVSS:3.1/"):
		if c, err := cvss31.ParseVector(s.Score); err == nil {
			return c.BaseScore(), true
		}
	case s.Type == "CVSS_V3":
		if c, err := cvss30.ParseVector(s.Score); err == nil {
			return c.BaseScore(), true
		}
	}
	return 0, false
}

// fromScore applies the CVSS qualitative rating scale.
func fromScore(score float64) Severity {
	switch {
	case score >= 9.0:
		return Critical
	case score >= 7.0:
		return High
	case score >= 4.0:
		return Medium
	case score > 0:
		return Low
	}
	return Unknown
}
