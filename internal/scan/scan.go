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
	// IgnoreExpired is an ignored finding whose --until date has passed.
	IgnoreExpired
	// FixAvailable is an unfixed finding whose advisories now name a fix.
	FixAvailable
)

func (k Kind) String() string {
	return [...]string{"opened", "resolved", "reactivated", "ignore expired", "fix available"}[k]
}

// Active reports whether the change puts a finding in front of the operator
// (as opposed to taking one away).
func (k Kind) Active() bool { return k != Resolved }

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
	// Sources are where the affected versions were found ("repo", "image:…").
	Sources  []string
	Severity osv.Severity
	// Fixable is false for an unfixed finding: no advisory names a fix.
	Fixable bool
	// Quiet marks a change that is recorded but not announced: the resolution
	// of an ignored finding, or anything about an unfixed one, which the
	// operator hears about once a fix exists.
	Quiet bool
	// Report is the CI context of the report that opened the finding, when a
	// report (rather than a sync) did.
	Report store.ReportMeta
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
		ids = append(ids, a.OtherIDs()...)
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
	sources  []string
	advs     []*osv.Advisory
	fixable  bool
}

type matches map[key]*match

func (m matches) add(e store.InventoryEntry, g store.VulnGroup, adv *osv.Advisory, how osv.Match) {
	p := e.Package
	k := key{e.ProjectID, g.Key, p.Ecosystem, p.Key()}
	if m[k] == nil {
		m[k] = &match{group: g, name: p.Name}
	}
	mm := m[k]
	if !slices.Contains(mm.versions, p.Version) {
		mm.versions = append(mm.versions, p.Version)
	}
	if !slices.Contains(mm.sources, e.Source) {
		mm.sources = append(mm.sources, e.Source)
	}
	if !slices.Contains(mm.advs, adv) {
		mm.advs = append(mm.advs, adv)
	}
	mm.fixable = mm.fixable || how.Fixable
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
	slices.Sort(m.sources)
	c := Change{Advisories: m.advs}
	return store.Finding{ProjectID: k.projectID, VulnID: k.vulnID, AdvisoryIDs: strings.Join(ids, ","), Summary: c.Summary(),
		Ecosystem: k.ecosystem, NameKey: k.nameKey, Name: m.name, Versions: strings.Join(m.versions, ", "),
		Sources: strings.Join(m.sources, ","), Severity: severity.String(), Fixable: m.fixable}
}

// affects wraps Advisory.Affects; an advisory Skope can't evaluate is logged
// and treated as not matching rather than failing the whole scan.
func affects(adv *osv.Advisory, p pkgid.Package) osv.Match {
	m, err := adv.Affects(p)
	if err != nil {
		slog.Warn("cannot evaluate advisory", "err", err)
	}
	return m
}

// announced reports whether the operator hears about a finding: once it can
// be fixed, or straight away for a malicious package, which has no fix but
// removing it.
func announced(fixable bool, advs []*osv.Advisory) bool {
	return fixable || slices.ContainsFunc(advs, (*osv.Advisory).Malicious)
}

// Report replaces the report's source's part of a project's inventory, then
// matches the project's whole inventory, every source, against every known
// advisory.
func (s *Scanner) Report(ctx context.Context, projectID int64, meta store.ReportMeta, pkgs []pkgid.Package) ([]Change, error) {
	var changes []Change
	err := s.st.Tx(ctx, func(tx *store.Tx) error {
		reportID, err := tx.RecordReport(projectID, meta, pkgs)
		if err != nil {
			return err
		}
		inventory, err := tx.Inventory(projectID)
		if err != nil {
			return err
		}
		advs := advisoryCache{tx: tx}
		groups := map[string]store.VulnGroup{}
		found := matches{}
		for _, e := range inventory {
			ids, err := tx.AdvisoryIDsFor(e.Package.Ecosystem, e.Package.Key())
			if err != nil {
				return err
			}
			for _, id := range ids {
				adv, err := advs.get(id)
				if err != nil {
					return err
				}
				how := affects(adv, e.Package)
				if !how.Affected {
					continue
				}
				g, ok := groups[id]
				if !ok {
					if g, err = tx.VulnGroup(id); err != nil {
						return err
					}
					groups[id] = g
				}
				found.add(e, g, adv, how)
			}
		}
		open, err := tx.OpenFindingsForProject(projectID)
		if err != nil {
			return err
		}
		changes, err = reconcile(tx, &advs, open, found, func(int64) (int64, error) { return reportID, nil })
		for i := range changes {
			if changes[i].Kind == Opened {
				changes[i].Report = meta
			}
		}
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
				if how := affects(adv, e.Package); how.Affected {
					found.add(e, g, adv, how)
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
			Ecosystem: f.Ecosystem, Name: f.Name, Versions: f.Versions, Sources: strings.Split(f.Sources, ","),
			Severity: osv.ParseSeverity(f.Severity), Fixable: f.Fixable, Quiet: !announced(f.Fixable, matched)}, nil
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
			c, err := change(Resolved, f, advs.load(f.AdvisoryIDs))
			if err != nil {
				return nil, err
			}
			c.Quiet = c.Quiet || f.Ignored(tx.Now())
			changes = append(changes, c)
			continue
		}
		delete(found, k)

		want := m.finding(k)
		want.ID = f.ID
		if want.AdvisoryIDs != f.AdvisoryIDs || want.Summary != f.Summary || want.Versions != f.Versions ||
			want.Sources != f.Sources || want.Severity != f.Severity || want.Fixable != f.Fixable {
			if err := tx.UpdateFinding(want); err != nil {
				return nil, err
			}
		}
		if !announced(f.Fixable, m.advs) && announced(want.Fixable, m.advs) && !f.Ignored(tx.Now()) {
			c, err := change(FixAvailable, want, m.advs)
			if err != nil {
				return nil, err
			}
			changes = append(changes, c)
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

// ExpireIgnores unmutes findings whose ignore has run out.
func (s *Scanner) ExpireIgnores(ctx context.Context) ([]Change, error) {
	var changes []Change
	err := s.st.Tx(ctx, func(tx *store.Tx) error {
		expired, err := tx.ExpiredIgnores()
		if err != nil {
			return err
		}
		advs := advisoryCache{tx: tx}
		for _, f := range expired {
			if err := tx.Unignore(f.ID); err != nil {
				return err
			}
			name, err := tx.ProjectName(f.ProjectID)
			if err != nil {
				return err
			}
			matched := advs.load(f.AdvisoryIDs)
			changes = append(changes, Change{Kind: IgnoreExpired, FindingID: f.ID, ProjectID: f.ProjectID, Project: name,
				VulnID: f.VulnID, Advisories: matched, Ecosystem: f.Ecosystem, Name: f.Name, Versions: f.Versions,
				Sources: strings.Split(f.Sources, ","), Severity: osv.ParseSeverity(f.Severity), Fixable: f.Fixable,
				Quiet: !announced(f.Fixable, matched)})
		}
		return nil
	})
	return changes, err
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

// load fetches a finding's comma-separated advisories, skipping any that are
// no longer stored.
func (c *advisoryCache) load(ids string) []*osv.Advisory {
	var out []*osv.Advisory
	for _, id := range strings.Split(ids, ",") {
		if a, err := c.get(id); err == nil {
			out = append(out, a)
		}
	}
	return out
}
