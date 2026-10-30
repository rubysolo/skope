// Package scan matches inventories against advisories and keeps findings in
// step: opening, updating, resolving and reactivating them. Findings are per
// vulnerability, so advisories that alias each other produce one finding.
package scan

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"

	"github.com/rubysolo/skope/internal/osv"
	"github.com/rubysolo/skope/internal/pkgid"
	"github.com/rubysolo/skope/internal/store"
)

type Kind int

const (
	Opened Kind = iota
	Resolved
	// Reactivated is an ignored finding whose vulnerability has since changed.
	Reactivated
)

func (k Kind) String() string { return [...]string{"opened", "resolved", "reactivated"}[k] }

// Change is one finding transition, carrying what an alert needs to describe it.
type Change struct {
	Kind      Kind
	FindingID int64
	ProjectID int64
	Project   string
	VulnID    string
	// Advisories are the vulnerability's advisories that matched (for a
	// resolution, the ones that last matched), sorted by id.
	Advisories []*osv.Advisory
	Ecosystem  string
	Name       string
	Versions   string
	Severity   osv.Severity
	// Quiet marks the resolution of an ignored finding: recorded, not announced.
	Quiet bool
}

// Summary is the first summary any of the advisories gives.
func (c Change) Summary() string {
	for _, a := range c.Advisories {
		if a.Summary != "" {
			return a.Summary
		}
	}
	return ""
}

// Malicious reports whether any advisory calls the package malicious.
func (c Change) Malicious() bool {
	return slices.ContainsFunc(c.Advisories, (*osv.Advisory).Malicious)
}

// Identifiers lists every id the vulnerability is known by: its advisories
// and their aliases (CVE ids included), sorted.
func (c Change) Identifiers() []string {
	ids := []string{c.VulnID}
	for _, a := range c.Advisories {
		ids = append(ids, a.ID)
		ids = append(ids, a.Aliases...)
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}

type Scanner struct {
	st *store.Store
}

func New(st *store.Store) *Scanner { return &Scanner{st: st} }

type key struct {
	projectID int64
	vulnID    string
	ecosystem string
	nameKey   string
}

type match struct {
	group    store.VulnGroup
	name     string
	versions []string
	advs     []*osv.Advisory
}

type matches map[key]*match

func (m matches) add(projectID int64, g store.VulnGroup, adv *osv.Advisory, p pkgid.Package) {
	k := key{projectID, g.Key, p.Ecosystem, p.Key()}
	if m[k] == nil {
		m[k] = &match{group: g, name: p.Name}
	}
	if !slices.Contains(m[k].versions, p.Version) {
		m[k].versions = append(m[k].versions, p.Version)
	}
	if !slices.Contains(m[k].advs, adv) {
		m[k].advs = append(m[k].advs, adv)
	}
}

// finding describes the match as the finding it should be.
func (m *match) finding(k key) store.Finding {
	slices.SortFunc(m.advs, func(a, b *osv.Advisory) int { return strings.Compare(a.ID, b.ID) })
	var ids []string
	severity := osv.Unknown
	for _, a := range m.advs {
		ids = append(ids, a.ID)
		severity = max(severity, a.Severity())
	}
	c := Change{Advisories: m.advs}
	return store.Finding{ProjectID: k.projectID, VulnID: k.vulnID, AdvisoryIDs: strings.Join(ids, ","), Summary: c.Summary(),
		Ecosystem: k.ecosystem, NameKey: k.nameKey, Name: m.name, Versions: strings.Join(m.versions, ", "), Severity: severity.String()}
}

// affects wraps Advisory.Affects; an advisory Skope can't evaluate is logged
// and treated as not matching rather than failing the whole scan.
func affects(adv *osv.Advisory, p pkgid.Package) bool {
	hit, err := adv.Affects(p)
	if err != nil {
		slog.Warn("cannot evaluate advisory", "err", err)
	}
	return hit
}

// Report replaces a project's inventory and matches it against every known
// advisory.
func (s *Scanner) Report(ctx context.Context, projectID int64, meta store.ReportMeta, pkgs []pkgid.Package) ([]Change, error) {
	var changes []Change
	err := s.st.Tx(ctx, func(tx *store.Tx) error {
		reportID, err := tx.RecordReport(projectID, meta, pkgs)
		if err != nil {
			return err
		}
		advs := advisoryCache{tx: tx}
		groups := map[string]store.VulnGroup{}
		found := matches{}
		for _, p := range pkgs {
			ids, err := tx.AdvisoryIDsFor(p.Ecosystem, p.Key())
			if err != nil {
				return err
			}
			for _, id := range ids {
				adv, err := advs.get(id)
				if err != nil {
					return err
				}
				if !affects(adv, p) {
					continue
				}
				g, ok := groups[id]
				if !ok {
					if g, err = tx.VulnGroup(id); err != nil {
						return err
					}
					groups[id] = g
				}
				found.add(projectID, g, adv, p)
			}
		}
		open, err := tx.OpenFindingsForProject(projectID)
		if err != nil {
			return err
		}
		changes, err = reconcile(tx, &advs, open, found, func(int64) (int64, error) { return reportID, nil })
		return err
	})
	return changes, err
}

// Advisories matches new or modified advisories — and the rest of each one's
// vulnerability — against every active project's inventory.
func (s *Scanner) Advisories(ctx context.Context, ids []string) ([]Change, error) {
	var all []Change
	// A first sync hands over every advisory in an ecosystem (npm has ~230k),
	// so work in batches rather than one transaction per advisory.
	for batch := range slices.Chunk(ids, 500) {
		err := s.st.Tx(ctx, func(tx *store.Tx) error {
			done := map[string]bool{}
			for _, id := range batch {
				if done[id] {
					continue
				}
				g, err := tx.VulnGroup(id)
				if err != nil {
					return err
				}
				for _, a := range g.Advisories {
					done[a] = true
				}
				changes, err := matchVuln(tx, g)
				if err != nil {
					return err
				}
				all = append(all, changes...)
			}
			return nil
		})
		if err != nil {
			return all, err
		}
	}
	return all, nil
}

func matchVuln(tx *store.Tx, g store.VulnGroup) ([]Change, error) {
	advs := advisoryCache{tx: tx}
	found := matches{}
	for _, id := range g.Advisories {
		adv, err := advs.get(id)
		if err != nil {
			return nil, err
		}
		for _, ref := range adv.Packages() {
			entries, err := tx.InventoryUsing(ref)
			if err != nil {
				return nil, err
			}
			for _, e := range entries {
				if affects(adv, e.Package) {
					found.add(e.ProjectID, g, adv, e.Package)
				}
			}
		}
	}
	// Every identifier, not just the key: a finding opened before two groups
	// merged is keyed by the old, larger id, and must be reconciled here too.
	open, err := tx.OpenFindingsForVulns(g.Identifiers)
	if err != nil {
		return nil, err
	}
	return reconcile(tx, &advs, open, found, tx.LatestReportID)
}

// reconcile brings the open findings in scope in line with the matches
// computed for that same scope.
func reconcile(tx *store.Tx, advs *advisoryCache, open []store.Finding, found matches,
	reportID func(projectID int64) (int64, error)) ([]Change, error) {

	names := map[int64]string{}
	change := func(kind Kind, f store.Finding, matched []*osv.Advisory) (Change, error) {
		name, ok := names[f.ProjectID]
		if !ok {
			var err error
			if name, err = tx.ProjectName(f.ProjectID); err != nil {
				return Change{}, err
			}
			names[f.ProjectID] = name
		}
		return Change{Kind: kind, FindingID: f.ID, ProjectID: f.ProjectID, Project: name, VulnID: f.VulnID, Advisories: matched,
			Ecosystem: f.Ecosystem, Name: f.Name, Versions: f.Versions, Severity: osv.ParseSeverity(f.Severity)}, nil
	}

	open, err := rekey(tx, open)
	if err != nil {
		return nil, err
	}

	var changes []Change
	for _, f := range open {
		k := key{f.ProjectID, f.VulnID, f.Ecosystem, f.NameKey}
		m, still := found[k]
		if !still {
			if err := tx.ResolveFinding(f.ID); err != nil {
				return nil, err
			}
			var last []*osv.Advisory
			for _, id := range strings.Split(f.AdvisoryIDs, ",") {
				if a, err := advs.get(id); err == nil {
					last = append(last, a)
				}
			}
			c, err := change(Resolved, f, last)
			if err != nil {
				return nil, err
			}
			c.Quiet = f.Ignored(tx.Now())
			changes = append(changes, c)
			continue
		}
		delete(found, k)

		want := m.finding(k)
		want.ID = f.ID
		if want.AdvisoryIDs != f.AdvisoryIDs || want.Summary != f.Summary || want.Versions != f.Versions || want.Severity != f.Severity {
			if err := tx.UpdateFinding(want); err != nil {
				return nil, err
			}
		}
		if f.IgnoredReason == "" {
			continue
		}
		modified, err := tx.VulnModified(m.group.Advisories)
		if err != nil {
			return nil, err
		}
		if f.IgnoredModified != modified {
			if err := tx.Unignore(f.ID); err != nil {
				return nil, err
			}
			want.ProjectID = f.ProjectID
			c, err := change(Reactivated, want, m.advs)
			if err != nil {
				return nil, err
			}
			changes = append(changes, c)
		}
	}

	for k, m := range found {
		f := m.finding(k)
		rid, err := reportID(k.projectID)
		if err != nil {
			return nil, err
		}
		if f.ID, err = tx.InsertFinding(f, rid); err != nil {
			return nil, err
		}
		c, err := change(Opened, f, m.advs)
		if err != nil {
			return nil, err
		}
		changes = append(changes, c)
	}

	slices.SortFunc(changes, func(a, b Change) int {
		return cmp.Or(cmp.Compare(a.ProjectID, b.ProjectID), cmp.Compare(a.VulnID, b.VulnID),
			cmp.Compare(a.Name, b.Name), cmp.Compare(a.Kind, b.Kind))
	})
	return changes, nil
}

// rekey moves open findings to their vulnerability's current key. A key
// changes when a new advisory joins two alias groups; without this the
// finding would resolve under the old key and reopen under the new one,
// alerting twice about one vulnerability.
func rekey(tx *store.Tx, open []store.Finding) ([]store.Finding, error) {
	groups := map[string]string{}
	held := map[key]bool{}
	for _, f := range open {
		held[key{f.ProjectID, f.VulnID, f.Ecosystem, f.NameKey}] = true
	}
	out := open[:0:0]
	for _, f := range open {
		current, ok := groups[f.VulnID]
		if !ok {
			g, err := tx.VulnGroup(f.VulnID)
			switch {
			case errors.Is(err, store.ErrNotFound):
				current = f.VulnID // no advisory answers to it any more; it will resolve
			case err != nil:
				return nil, err
			default:
				current = g.Key
			}
			groups[f.VulnID] = current
		}
		if current != f.VulnID {
			to := key{f.ProjectID, current, f.Ecosystem, f.NameKey}
			if held[to] {
				// Already tracked under the new key: this one is a leftover.
				if err := tx.ResolveFinding(f.ID); err != nil {
					return nil, err
				}
				continue
			}
			if err := tx.RekeyFinding(f.ID, current); err != nil {
				return nil, err
			}
			held[to] = true
			f.VulnID = current
		}
		out = append(out, f)
	}
	return out, nil
}

type advisoryCache struct {
	tx   *store.Tx
	byID map[string]*osv.Advisory
}

func (c *advisoryCache) get(id string) (*osv.Advisory, error) {
	if a, ok := c.byID[id]; ok {
		return a, nil
	}
	a, err := c.tx.Advisory(id)
	if err != nil {
		return nil, err
	}
	if c.byID == nil {
		c.byID = map[string]*osv.Advisory{}
	}
	c.byID[id] = a
	return a, nil
}
