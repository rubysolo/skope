// Package alert turns finding changes into the operator's email and phone
// notifications.
package alert

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rubysolo/skope/internal/api"
	"github.com/rubysolo/skope/internal/osv"
	"github.com/rubysolo/skope/internal/scan"
	"github.com/rubysolo/skope/internal/store"
)

// Email is a composed plain-text email.
type Email struct {
	Subject string
	Body    string
}

// Push is a composed phone notification.
type Push struct {
	Title    string
	Message  string
	Priority int // ntfy: 3 default, 4 high, 5 max
	Tags     []string
	Click    string
}

// vuln is the changes of one kind for one vulnerability, across projects.
type vuln struct {
	id        string
	kind      scan.Kind
	severity  osv.Severity
	malicious bool
	summary   string
	aliases   []string
	url       string
	changes   []scan.Change
}

// group collects changes by (kind, vulnerability), most urgent first.
func group(changes []scan.Change) []*vuln {
	byKey := map[string]*vuln{}
	var out []*vuln
	for _, c := range changes {
		k := c.Kind.String() + "|" + c.VulnID
		v := byKey[k]
		if v == nil {
			v = &vuln{id: c.VulnID, kind: c.Kind}
			for _, id := range c.Identifiers() {
				if id != c.VulnID {
					v.aliases = append(v.aliases, id)
				}
			}
			if len(c.Advisories) > 0 {
				v.url = api.AdvisoryURL(c.Advisories[0].ID)
			} else {
				v.url = api.AdvisoryURL(c.VulnID)
			}
			byKey[k] = v
			out = append(out, v)
		}
		v.severity = max(v.severity, c.Severity)
		v.malicious = v.malicious || c.Malicious()
		if v.summary == "" {
			v.summary = c.Summary()
		}
		v.changes = append(v.changes, c)
	}
	slices.SortStableFunc(out, func(a, b *vuln) int {
		return cmp.Or(compareBool(b.malicious, a.malicious), cmp.Compare(rank(a.severity), rank(b.severity)), cmp.Compare(a.id, b.id))
	})
	return out
}

func compareBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return 1
	}
	return -1
}

// rank orders severities for attention: unknown sits with high, since it may
// be anything.
func rank(s osv.Severity) int {
	switch s {
	case osv.Critical:
		return 0
	case osv.High, osv.Unknown:
		return 1
	case osv.Medium:
		return 2
	}
	return 3
}

func (v *vuln) label() string {
	if v.malicious {
		return "MALICIOUS"
	}
	return strings.ToUpper(v.severity.String())
}

func (v *vuln) projects() []string {
	var ps []string
	for _, c := range v.changes {
		if !slices.Contains(ps, c.Project) {
			ps = append(ps, c.Project)
		}
	}
	return ps
}

// urgent reports whether a change deserves a phone push: a finding coming
// into view that is malicious, high/critical, or unrated.
func urgent(c scan.Change) bool {
	return c.Kind.Active() && (c.Malicious() || c.Severity.Urgent())
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func short(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

// ComposeEmail describes every announced change. ok is false when there is
// nothing to send (every change was quiet).
func ComposeEmail(changes []scan.Change) (e Email, ok bool) {
	var loud []scan.Change
	for _, c := range changes {
		if !c.Quiet {
			loud = append(loud, c)
		}
	}
	if len(loud) == 0 {
		return Email{}, false
	}
	vulns := group(loud)

	sections := []struct {
		title string
		kinds []scan.Kind
	}{
		{"NEW", []scan.Kind{scan.Opened}},
		{"BACK ON YOUR LIST", []scan.Kind{scan.Reactivated, scan.IgnoreExpired}},
		{"RESOLVED", []scan.Kind{scan.Resolved}},
	}
	var b strings.Builder
	// One report opens all its findings at one commit: say so once.
	shared := sharedReport(loud)
	if shared.Commit != "" {
		fmt.Fprintf(&b, "Reported from commit %s", short(shared.Commit))
		if shared.RunURL != "" {
			fmt.Fprintf(&b, " - %s", shared.RunURL)
		}
		b.WriteString("\n\n")
	}
	counts := map[string]int{}
	var projects []string
	malicious := false
	for _, sec := range sections {
		var in []*vuln
		for _, v := range vulns {
			if slices.Contains(sec.kinds, v.kind) {
				in = append(in, v)
			}
		}
		if len(in) == 0 {
			continue
		}
		counts[sec.title] = len(in)
		fmt.Fprintf(&b, "%s\n\n", sec.title)
		for _, v := range in {
			if v.kind.Active() {
				malicious = malicious || v.malicious
				for _, p := range v.projects() {
					if !slices.Contains(projects, p) {
						projects = append(projects, p)
					}
				}
			}
			writeVuln(&b, v, shared.Commit == "")
		}
	}
	b.WriteString("-- \nMute a finding:   skope finding ignore <id> --reason \"...\" [--until 2027-01-01]\nSee all findings: skope finding list\n")

	var subject string
	switch {
	case malicious:
		subject = "MALICIOUS package in " + strings.Join(projects, ", ")
	case counts["NEW"] > 0:
		subject = plural(counts["NEW"], "new vulnerability", "new vulnerabilities") + " in " + strings.Join(projects, ", ")
	case counts["BACK ON YOUR LIST"] > 0:
		subject = plural(counts["BACK ON YOUR LIST"], "vulnerability needs", "vulnerabilities need") + " another look in " + strings.Join(projects, ", ")
	default:
		subject = plural(counts["RESOLVED"], "vulnerability", "vulnerabilities") + " resolved"
	}
	return Email{Subject: "[skope] " + subject, Body: b.String()}, true
}

// sharedReport returns the report context when every change that has one
// shares it, or the zero value.
func sharedReport(changes []scan.Change) store.ReportMeta {
	var shared store.ReportMeta
	for _, c := range changes {
		if c.Report.Commit == "" {
			continue
		}
		if shared.Commit != "" && c.Report != shared {
			return store.ReportMeta{}
		}
		shared = c.Report
	}
	return shared
}

func writeVuln(b *strings.Builder, v *vuln, perLineReport bool) {
	title := v.id
	if v.summary != "" {
		title += ": " + v.summary
	}
	if v.kind == scan.Resolved {
		fmt.Fprintf(b, "%s\n", title)
	} else {
		fmt.Fprintf(b, "[%s] %s\n", v.label(), title)
	}
	for _, c := range v.changes {
		line := fmt.Sprintf("  #%d  %s  %s %s %s", c.FindingID, c.Project, c.Ecosystem, c.Name, c.Versions)
		switch c.Kind {
		case scan.Resolved:
			line = fmt.Sprintf("  #%d  %s  %s %s (was %s)", c.FindingID, c.Project, c.Ecosystem, c.Name, c.Versions)
		case scan.Reactivated:
			line += "  (advisory changed since you ignored it)"
		case scan.IgnoreExpired:
			line += "  (ignore expired)"
		}
		if perLineReport && c.Report.Commit != "" {
			line += "\n      introduced by commit " + short(c.Report.Commit)
			if c.Report.RunURL != "" {
				line += " - " + c.Report.RunURL
			}
		}
		b.WriteString(line + "\n")
	}
	if len(v.aliases) > 0 {
		fmt.Fprintf(b, "  Also known as: %s\n", strings.Join(v.aliases, ", "))
	}
	fmt.Fprintf(b, "  %s\n\n", v.url)
}

// ComposePush describes the urgent changes for a phone. ok is false when none
// are urgent.
func ComposePush(changes []scan.Change) (p Push, ok bool) {
	var hot []scan.Change
	for _, c := range changes {
		if !c.Quiet && urgent(c) {
			hot = append(hot, c)
		}
	}
	if len(hot) == 0 {
		return Push{}, false
	}
	vulns := group(hot)
	p.Priority = 4
	p.Tags = []string{"warning"}
	var lines, projects []string
	for _, v := range vulns {
		if v.malicious {
			p.Priority = 5
			p.Tags = []string{"skull"}
		}
		for _, c := range v.changes {
			lines = append(lines, fmt.Sprintf("%s %s %s (%s) %s", v.label(), c.Name, c.Versions, c.Project, v.id))
			if !slices.Contains(projects, c.Project) {
				projects = append(projects, c.Project)
			}
		}
	}
	if len(vulns) == 1 {
		v := vulns[0]
		p.Title = fmt.Sprintf("%s: %s in %s", v.label(), v.id, strings.Join(projects, ", "))
		if v.malicious {
			p.Title = "MALICIOUS package in " + strings.Join(projects, ", ")
		}
		p.Click = v.url
		if v.summary != "" {
			lines = append(lines, v.summary)
		}
	} else {
		p.Title = fmt.Sprintf("%d urgent vulnerabilities in %s", len(vulns), strings.Join(projects, ", "))
		if p.Priority == 5 {
			p.Title = "MALICIOUS package and more in " + strings.Join(projects, ", ")
		}
	}
	p.Message = strings.Join(lines, "\n")
	return p, true
}

// ComposeStale describes projects that have stopped reporting.
func ComposeStale(projects []store.StaleProject, now time.Time) (Email, Push) {
	var names []string
	var b strings.Builder
	b.WriteString("These projects haven't reported their dependencies recently, so Skope is matching new advisories against stale inventories:\n\n")
	for _, p := range projects {
		names = append(names, p.Name)
		days := int(now.Sub(p.Since).Hours() / 24)
		if p.LastReportAt == "" {
			fmt.Fprintf(&b, "  %s  never reported (registered %d days ago)\n", p.Name, days)
		} else {
			fmt.Fprintf(&b, "  %s  last report %d days ago\n", p.Name, days)
		}
	}
	b.WriteString("\nCheck the project's skope CI workflow, or if it's retired:\n  skope project archive <name>\n\nYou'll be reminded weekly until it reports again.\n")
	list := strings.Join(names, ", ")
	subject := plural(len(projects), "project has", "projects have") + " stopped reporting: " + list
	return Email{Subject: "[skope] " + subject, Body: b.String()},
		Push{Title: "skope: " + subject, Message: "Check CI, or `skope project archive` retired projects.", Priority: 3, Tags: []string{"hourglass"}}
}
