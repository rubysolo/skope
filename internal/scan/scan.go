// Package scan matches inventories against advisories and keeps findings in
// step: opening, updating, resolving and reactivating them.
package scan

import (
	"cmp"
	"context"
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
	// Reactivated is an ignored finding whose advisory has since changed.
	Reactivated
)

func (k Kind) String() string { return [...]string{"opened", "resolved", "reactivated"}[k] }

// Change is one finding transition, carrying what an alert needs to describe it.
type Change struct {
	Kind      Kind
	FindingID int64
	ProjectID int64
	Project   string
	Advisory  *osv.Advisory
	Ecosystem string
	Name      string
	Versions  string
	Severity  osv.Severity
	// Quiet marks the resolution of an ignored finding: recorded, not announced.
	Quiet bool
}

type Scanner struct {
	st *store.Store
}

func New(st *store.Store) *Scanner { return &Scanner{st: st} }

type key struct {
	projectID  int64
	advisoryID string
	ecosystem  string
	nameKey    string
}

type match struct {
	name     string
	versions []string
	adv      *osv.Advisory
}

type matches map[key]*match

func (m matches) add(projectID int64, adv *osv.Advisory, p pkgid.Package) {
	k := key{projectID, adv.ID, p.Ecosystem, p.Key()}
	if m[k] == nil {
		m[k] = &match{name: p.Name, adv: adv}
	}
	if !slices.Contains(m[k].versions, p.Version) {
		m[k].versions = append(m[k].versions, p.Version)
	}
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
				if affects(adv, p) {
					found.add(projectID, adv, p)
				}
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

// Advisories matches new or modified advisories against every active
// project's inventory.
func (s *Scanner) Advisories(ctx context.Context, ids []string) ([]Change, error) {
	var all []Change
	// A first sync hands over every advisory in an ecosystem (npm has ~230k),
	// so work in batches rather than one transaction per advisory.
	for batch := range slices.Chunk(ids, 500) {
		err := s.st.Tx(ctx, func(tx *store.Tx) error {
			for _, id := range batch {
				changes, err := matchAdvisory(tx, id)
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

func matchAdvisory(tx *store.Tx, id string) ([]Change, error) {
	advs := advisoryCache{tx: tx}
	adv, err := advs.get(id)
	if err != nil {
		return nil, err
	}
	found := matches{}
	for _, ref := range adv.Packages() {
		entries, err := tx.InventoryUsing(ref)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if affects(adv, e.Package) {
				found.add(e.ProjectID, adv, e.Package)
			}
		}
	}
	open, err := tx.OpenFindingsForAdvisory(id)
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
	change := func(kind Kind, f store.Finding, adv *osv.Advisory) (Change, error) {
		name, ok := names[f.ProjectID]
		if !ok {
			var err error
			if name, err = tx.ProjectName(f.ProjectID); err != nil {
				return Change{}, err
			}
			names[f.ProjectID] = name
		}
		return Change{Kind: kind, FindingID: f.ID, ProjectID: f.ProjectID, Project: name, Advisory: adv,
			Ecosystem: f.Ecosystem, Name: f.Name, Versions: f.Versions, Severity: osv.ParseSeverity(f.Severity)}, nil
	}

	var changes []Change
	for _, f := range open {
		k := key{f.ProjectID, f.AdvisoryID, f.Ecosystem, f.NameKey}
		m, still := found[k]
		if !still {
			if err := tx.ResolveFinding(f.ID); err != nil {
				return nil, err
			}
			adv, err := advs.get(f.AdvisoryID)
			if err != nil {
				return nil, err
			}
			c, err := change(Resolved, f, adv)
			if err != nil {
				return nil, err
			}
			c.Quiet = f.Ignored(tx.Now())
			changes = append(changes, c)
			continue
		}
		delete(found, k)

		versions, severity := strings.Join(m.versions, ", "), m.adv.Severity().String()
		if versions != f.Versions || severity != f.Severity {
			if err := tx.UpdateFinding(f.ID, versions, severity); err != nil {
				return nil, err
			}
			f.Versions, f.Severity = versions, severity
		}
		if f.IgnoredReason != "" && f.IgnoredModified != m.adv.Modified {
			if err := tx.Unignore(f.ID); err != nil {
				return nil, err
			}
			c, err := change(Reactivated, f, m.adv)
			if err != nil {
				return nil, err
			}
			changes = append(changes, c)
		}
	}

	for k, m := range found {
		f := store.Finding{ProjectID: k.projectID, AdvisoryID: k.advisoryID, Ecosystem: k.ecosystem, NameKey: k.nameKey,
			Name: m.name, Versions: strings.Join(m.versions, ", "), Severity: m.adv.Severity().String()}
		rid, err := reportID(k.projectID)
		if err != nil {
			return nil, err
		}
		if f.ID, err = tx.InsertFinding(f, rid); err != nil {
			return nil, err
		}
		c, err := change(Opened, f, m.adv)
		if err != nil {
			return nil, err
		}
		changes = append(changes, c)
	}

	slices.SortFunc(changes, func(a, b Change) int {
		return cmp.Or(cmp.Compare(a.ProjectID, b.ProjectID), cmp.Compare(a.Advisory.ID, b.Advisory.ID),
			cmp.Compare(a.Name, b.Name), cmp.Compare(a.Kind, b.Kind))
	})
	return changes, nil
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
