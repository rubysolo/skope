package store

import (
	"database/sql"
	"errors"
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

// FindingView is a finding with the names an operator reads it by.
type FindingView struct {
	Finding
	Project string
	Summary string
}

// FindingFilter narrows FindingViews. Zero values mean "any".
type FindingFilter struct {
	ProjectID       int64
	IncludeResolved bool
}

// FindingViews lists findings, most severe first.
func (t *Tx) FindingViews(f FindingFilter) ([]FindingView, error) {
	q := `SELECT f.id, p.name, COALESCE(a.summary, '') FROM findings f
		JOIN projects p ON p.id = f.project_id
		LEFT JOIN advisories a ON a.id = f.advisory_id
		WHERE (? = 0 OR f.project_id = ?) AND (? OR f.resolved_at IS NULL)
		ORDER BY f.resolved_at IS NOT NULL,
		  CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'unknown' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
		  p.name, f.advisory_id`
	rows, err := t.tx.Query(q, f.ProjectID, f.ProjectID, f.IncludeResolved)
	if err != nil {
		return nil, err
	}
	type head struct {
		id               int64
		project, summary string
	}
	var heads []head
	for rows.Next() {
		var h head
		if err := rows.Scan(&h.id, &h.project, &h.summary); err != nil {
			rows.Close()
			return nil, err
		}
		heads = append(heads, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]FindingView, 0, len(heads))
	for _, h := range heads {
		fd, err := t.FindingByID(h.id)
		if err != nil {
			return nil, err
		}
		out = append(out, FindingView{Finding: fd, Project: h.project, Summary: h.summary})
	}
	return out, nil
}

// AdvisoryModified returns an advisory's modified time.
func (t *Tx) AdvisoryModified(id string) (string, error) {
	var m string
	err := t.tx.QueryRow(`SELECT modified FROM advisories WHERE id = ?`, id).Scan(&m)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return m, err
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
