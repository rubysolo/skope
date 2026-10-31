package alert

import (
	"strings"
	"testing"
	"time"

	"github.com/rubysolo/skope/internal/osv"
	"github.com/rubysolo/skope/internal/scan"
	"github.com/rubysolo/skope/internal/store"
)

func adv(id, summary string, aliases ...string) *osv.Advisory {
	return &osv.Advisory{ID: id, Summary: summary, Aliases: aliases}
}

func change(kind scan.Kind, id int64, project, vulnID string, sev osv.Severity, advs ...*osv.Advisory) scan.Change {
	return scan.Change{Kind: kind, FindingID: id, Project: project, VulnID: vulnID, Advisories: advs,
		Ecosystem: "Hex", Name: "plug", Versions: "1.2.0", Severity: sev}
}

func TestEmailGroupsByVulnerability(t *testing.T) {
	plugVuln := []*osv.Advisory{adv("EEF-CVE-2026-1", "plug mishandles headers", "GHSA-aaaa"), adv("GHSA-aaaa", "", "CVE-2026-1")}
	opened := change(scan.Opened, 7, "cure", "CVE-2026-1", osv.High, plugVuln...)
	opened.Report = store.ReportMeta{Commit: "abcdef1234567", RunURL: "https://github.com/x/cure/actions/runs/1"}
	e, ok := ComposeEmail([]scan.Change{
		opened,
		change(scan.Opened, 8, "ordered_path", "CVE-2026-1", osv.High, plugVuln...),
		change(scan.Resolved, 3, "cure", "GHSA-old", osv.Low, adv("GHSA-old", "old thing")),
	})
	if !ok {
		t.Fatal("want an email")
	}
	if e.Subject != "[skope] 1 new vulnerability in cure, ordered_path" {
		t.Errorf("subject = %q", e.Subject)
	}
	for _, want := range []string{
		"NEW\n\n[HIGH] CVE-2026-1: plug mishandles headers\n",
		"Reported from commit abcdef1 - https://github.com/x/cure/actions/runs/1\n\nNEW",
		"  #7  cure  Hex plug 1.2.0\n",
		"  #8  ordered_path  Hex plug 1.2.0\n",
		"  Also known as: EEF-CVE-2026-1, GHSA-aaaa\n",
		"  https://osv.dev/vulnerability/EEF-CVE-2026-1\n",
		"RESOLVED\n\nGHSA-old: old thing\n  #3  cure  Hex plug (was 1.2.0)\n",
		"skope finding ignore <id>",
	} {
		if !strings.Contains(e.Body, want) {
			t.Errorf("body missing %q:\n%s", want, e.Body)
		}
	}
	if strings.Index(e.Body, "NEW") > strings.Index(e.Body, "RESOLVED") {
		t.Error("new findings come before resolutions")
	}
}

func TestEmailSkipsQuietChanges(t *testing.T) {
	quiet := change(scan.Resolved, 1, "cure", "GHSA-x", osv.High, adv("GHSA-x", ""))
	quiet.Quiet = true
	if _, ok := ComposeEmail([]scan.Change{quiet}); ok {
		t.Error("only quiet changes: no email")
	}
}

func TestEmailSubjects(t *testing.T) {
	mal := change(scan.Opened, 1, "cure", "MAL-2026-1", osv.Critical, adv("MAL-2026-1", "malicious code in plugg"))
	if e, _ := ComposeEmail([]scan.Change{mal}); e.Subject != "[skope] MALICIOUS package in cure" || !strings.Contains(e.Body, "[MALICIOUS] MAL-2026-1") {
		t.Errorf("malicious: %q\n%s", e.Subject, e.Body)
	}
	exp := change(scan.IgnoreExpired, 2, "cure", "CVE-1", osv.Medium, adv("GHSA-1", ""))
	if e, _ := ComposeEmail([]scan.Change{exp}); e.Subject != "[skope] 1 vulnerability needs another look in cure" || !strings.Contains(e.Body, "(ignore expired)") {
		t.Errorf("expired: %q\n%s", e.Subject, e.Body)
	}
	res := []scan.Change{change(scan.Resolved, 3, "cure", "CVE-1", osv.Low), change(scan.Resolved, 4, "cure", "CVE-2", osv.Low)}
	if e, _ := ComposeEmail(res); e.Subject != "[skope] 2 vulnerabilities resolved" {
		t.Errorf("resolved: %q", e.Subject)
	}
}

func TestPushOnlyForUrgent(t *testing.T) {
	medium := change(scan.Opened, 1, "cure", "CVE-1", osv.Medium, adv("GHSA-1", ""))
	highResolved := change(scan.Resolved, 2, "cure", "CVE-2", osv.High, adv("GHSA-2", ""))
	if p, ok := ComposePush([]scan.Change{medium, highResolved}); ok {
		t.Errorf("medium and resolutions don't push: %+v", p)
	}

	high := change(scan.Opened, 3, "cure", "CVE-3", osv.High, adv("GHSA-3", "bad plug"))
	p, ok := ComposePush([]scan.Change{medium, high})
	if !ok || p.Priority != 4 || p.Title != "HIGH: CVE-3 in cure" || p.Click != "https://osv.dev/vulnerability/GHSA-3" ||
		!strings.Contains(p.Message, "bad plug") || strings.Contains(p.Message, "CVE-1") {
		t.Errorf("high: %+v", p)
	}

	unknown := change(scan.Opened, 4, "ordered_path", "RUSTSEC-1", osv.Unknown, adv("RUSTSEC-1", ""))
	if p, ok := ComposePush([]scan.Change{unknown}); !ok || p.Priority != 4 {
		t.Errorf("unknown severity should push: %+v", p)
	}

	mal := change(scan.Opened, 5, "cure", "MAL-1", osv.Critical, adv("MAL-1", ""))
	p, ok = ComposePush([]scan.Change{high, mal})
	if !ok || p.Priority != 5 || p.Tags[0] != "skull" || !strings.HasPrefix(p.Title, "MALICIOUS") {
		t.Errorf("malicious: %+v", p)
	}
	if strings.Index(p.Message, "MAL-1") > strings.Index(p.Message, "CVE-3") {
		t.Errorf("malicious first:\n%s", p.Message)
	}
}

func TestComposeStale(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	e, p := ComposeStale([]store.StaleProject{
		{Project: store.Project{Name: "cure", LastReportAt: "x"}, Since: now.Add(-31 * 24 * time.Hour)},
		{Project: store.Project{Name: "skope-k8s"}, Since: now.Add(-40 * 24 * time.Hour)},
	}, now)
	if e.Subject != "[skope] 2 projects have stopped reporting: cure, skope-k8s" || p.Priority != 3 {
		t.Errorf("subject %q priority %d", e.Subject, p.Priority)
	}
	for _, want := range []string{"cure  last report 31 days ago", "skope-k8s  never reported (registered 40 days ago)", "skope project archive"} {
		if !strings.Contains(e.Body, want) {
			t.Errorf("body missing %q:\n%s", want, e.Body)
		}
	}
}

func TestEmailReportContextPerLineWhenMixed(t *testing.T) {
	a := change(scan.Opened, 1, "cure", "CVE-1", osv.High, adv("GHSA-1", ""))
	a.Report.Commit = "aaaaaaa111"
	b := change(scan.Opened, 2, "ordered_path", "CVE-2", osv.High, adv("GHSA-2", ""))
	b.Report.Commit = "bbbbbbb222"
	e, _ := ComposeEmail([]scan.Change{a, b})
	if strings.Contains(e.Body, "Reported from") || !strings.Contains(e.Body, "introduced by commit aaaaaaa") ||
		!strings.Contains(e.Body, "introduced by commit bbbbbbb") {
		t.Errorf("mixed commits go per line:\n%s", e.Body)
	}
}
