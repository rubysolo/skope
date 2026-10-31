package store

import (
	"slices"
	"strings"
)

// VulnGroup is a vulnerability: the advisories connected by aliases.
type VulnGroup struct {
	// Key is what findings are keyed by: the group's smallest CVE ID, or its
	// smallest advisory ID when it has no CVE. Other aliases (Bitnami's BIT-…,
	// for one) never become the key.
	Key string
	// Advisories are the stored advisories in the group, sorted.
	Advisories []string
	// Identifiers are every id and alias in the group, sorted.
	Identifiers []string
}

// VulnGroup finds the vulnerability that identifier id (an advisory id or an
// alias such as a CVE) belongs to, following aliases transitively: EEF-CVE-x
// lists GHSA-y, GHSA-y lists CVE-z, and all three are one vulnerability.
func (t *Tx) VulnGroup(id string) (VulnGroup, error) {
	idents := map[string]bool{id: true}
	advs := map[string]bool{}
	queue := []string{id}
	for len(queue) > 0 {
		alias := queue[0]
		queue = queue[1:]
		owners, err := t.strings(`SELECT advisory_id FROM advisory_aliases WHERE alias = ?`, alias)
		if err != nil {
			return VulnGroup{}, err
		}
		for _, a := range owners {
			if advs[a] {
				continue
			}
			advs[a] = true
			aliases, err := t.strings(`SELECT alias FROM advisory_aliases WHERE advisory_id = ?`, a)
			if err != nil {
				return VulnGroup{}, err
			}
			for _, x := range aliases {
				if !idents[x] {
					idents[x] = true
					queue = append(queue, x)
				}
			}
		}
	}
	if len(advs) == 0 {
		return VulnGroup{}, ErrNotFound
	}
	g := VulnGroup{}
	for a := range advs {
		g.Advisories = append(g.Advisories, a)
	}
	for x := range idents {
		g.Identifiers = append(g.Identifiers, x)
	}
	slices.Sort(g.Advisories)
	slices.Sort(g.Identifiers)
	g.Key = g.Advisories[0]
	for _, x := range g.Identifiers {
		if strings.HasPrefix(x, "CVE-") {
			g.Key = x
			break
		}
	}
	return g, nil
}

// VulnModified is the newest modified time among the given advisories: the
// vulnerability's version, against which an ignore is judged.
func (t *Tx) VulnModified(advisoryIDs []string) (string, error) {
	if len(advisoryIDs) == 0 {
		return "", ErrNotFound
	}
	args := make([]any, len(advisoryIDs))
	for i, id := range advisoryIDs {
		args[i] = id
	}
	var m string
	err := t.tx.QueryRow(`SELECT COALESCE(MAX(modified), '') FROM advisories WHERE id IN (?`+
		strings.Repeat(", ?", len(advisoryIDs)-1)+`)`, args...).Scan(&m)
	return m, err
}
