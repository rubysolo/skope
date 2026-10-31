package store

import (
	"cmp"
	"slices"
)

// ProjectByName looks up a project, archived or not.
func (t *Tx) ProjectByName(name string) (Project, error) {
	return scanProject(t.tx.QueryRow(`SELECT `+projectCols+` FROM projects WHERE name = ?`, name))
}

// Projects lists every project, archived ones last.
func (t *Tx) Projects() ([]Project, error) {
	rows, err := t.tx.Query(`SELECT ` + projectCols + ` FROM projects ORDER BY archived_at IS NOT NULL, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Project
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// RotateToken replaces an active project's token; the old one stops working.
func (t *Tx) RotateToken(projectID int64) (string, error) {
	token, err := newToken()
	if err != nil {
		return "", err
	}
	res, err := t.tx.Exec(`UPDATE projects SET token_hash = ? WHERE id = ? AND archived_at IS NULL`, hashToken(token), projectID)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", ErrNotFound
	}
	return token, nil
}

// ArchiveProject revokes the project's token, takes it out of matching and
// staleness checks, and resolves its open findings without announcing them.
func (t *Tx) ArchiveProject(projectID int64) error {
	res, err := t.tx.Exec(`UPDATE projects SET token_hash = NULL, archived_at = ? WHERE id = ? AND archived_at IS NULL`, t.now, projectID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	_, err = t.tx.Exec(`UPDATE findings SET resolved_at = ? WHERE project_id = ? AND resolved_at IS NULL`, t.now, projectID)
	return err
}

// DeleteProject erases a project and everything recorded about it.
func (t *Tx) DeleteProject(projectID int64) error {
	res, err := t.tx.Exec(`DELETE FROM projects WHERE id = ?`, projectID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (t *Tx) FindingByID(id int64) (Finding, error) {
	fs, err := t.findings(`id = ?`, id)
	if err != nil {
		return Finding{}, err
	}
	if len(fs) == 0 {
		return Finding{}, ErrNotFound
	}
	return fs[0], nil
}

// FindingView is a finding with the project name an operator reads it by.
type FindingView struct {
	Finding
	Project string
}

// FindingFilter narrows FindingViews. Zero values mean "any".
type FindingFilter struct {
	ProjectID       int64
	IncludeResolved bool
}

// FindingViews lists findings, most severe first.
func (t *Tx) FindingViews(f FindingFilter) ([]FindingView, error) {
	fs, err := t.findings(`(? = 0 OR project_id = ?) AND (? OR resolved_at IS NULL)`, f.ProjectID, f.ProjectID, f.IncludeResolved)
	if err != nil {
		return nil, err
	}
	names := map[int64]string{}
	out := make([]FindingView, 0, len(fs))
	for _, fd := range fs {
		name, ok := names[fd.ProjectID]
		if !ok {
			if name, err = t.ProjectName(fd.ProjectID); err != nil {
				return nil, err
			}
			names[fd.ProjectID] = name
		}
		out = append(out, FindingView{Finding: fd, Project: name})
	}
	slices.SortStableFunc(out, func(a, b FindingView) int {
		return cmp.Or(compareBool(a.ResolvedAt != "", b.ResolvedAt != ""), cmp.Compare(severityRank(a.Severity), severityRank(b.Severity)),
			cmp.Compare(a.Project, b.Project), cmp.Compare(a.VulnID, b.VulnID))
	})
	return out, nil
}

// severityRank orders severities for review: unknown sits between high and
// medium because it may be either.
func severityRank(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "unknown":
		return 2
	case "medium":
		return 3
	}
	return 4
}

// PruneReports deletes report log entries received before cutoff (RFC 3339).
// Findings keep their row but lose the link to the pruned report.
func (t *Tx) PruneReports(cutoff string) (int64, error) {
	res, err := t.tx.Exec(`DELETE FROM reports WHERE received_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
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
