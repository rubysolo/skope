// Package api holds the JSON shapes exchanged between the skope server, its
// CLI client and CI.
package api

// Report headers carry CI metadata alongside the report body, which is an
// SBOM or purl list and has no place for it.
const (
	HeaderCommit = "Skope-Commit"
	HeaderRef    = "Skope-Ref"
	HeaderRunURL = "Skope-Run-Url"
)

type Error struct {
	Error string `json:"error"`
}

type Project struct {
	Name           string `json:"name"`
	StaleAfterDays int    `json:"stale_after_days"`
	CreatedAt      string `json:"created_at"`
	ArchivedAt     string `json:"archived_at,omitempty"`
	LastReportAt   string `json:"last_report_at,omitempty"`
}

type CreateProject struct {
	Name string `json:"name"`
}

// ProjectToken is returned once, on creation or rotation.
type ProjectToken struct {
	Project Project `json:"project"`
	Token   string  `json:"token"`
}

type Finding struct {
	ID      int64  `json:"id"`
	Project string `json:"project"`
	// Vulnerability is the key of the vulnerability (its smallest identifier,
	// a CVE id when there is one); Advisories are the advisories that matched.
	Vulnerability string   `json:"vulnerability"`
	Advisories    []string `json:"advisories"`
	Summary       string   `json:"summary,omitempty"`
	URL           string   `json:"url"`
	Ecosystem     string   `json:"ecosystem"`
	Package       string   `json:"package"`
	Versions      string   `json:"versions"`
	Severity      string   `json:"severity"`
	OpenedAt      string   `json:"opened_at"`
	ResolvedAt    string   `json:"resolved_at,omitempty"`
	Ignored       *Ignored `json:"ignored,omitempty"`
}

type Ignored struct {
	Reason string `json:"reason"`
	Until  string `json:"until,omitempty"`
}

// Ignore is the request body for muting a finding. Until is a date
// (2027-01-01) or RFC 3339 time; empty means indefinitely.
type Ignore struct {
	Reason string `json:"reason"`
	Until  string `json:"until,omitempty"`
}

type ReportResult struct {
	Project  string    `json:"project"`
	Packages int       `json:"packages"`
	Skipped  int       `json:"skipped"`
	Findings []Finding `json:"findings"`
}

func AdvisoryURL(id string) string { return "https://osv.dev/vulnerability/" + id }
