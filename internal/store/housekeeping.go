package store

import (
	"database/sql"
	"errors"
	"time"
)

// ReportMeta returns the CI metadata recorded with a report.
func (t *Tx) ReportMeta(reportID int64) (ReportMeta, error) {
	var m ReportMeta
	err := t.tx.QueryRow(`SELECT commit_sha, ref, run_url FROM reports WHERE id = ?`, reportID).Scan(&m.Commit, &m.Ref, &m.RunURL)
	if errors.Is(err, sql.ErrNoRows) {
		return m, ErrNotFound
	}
	return m, err
}

// ExpiredIgnores returns open findings whose ignore has run out.
func (t *Tx) ExpiredIgnores() ([]Finding, error) {
	return t.findings(`resolved_at IS NULL AND ignored_until IS NOT NULL AND ignored_until <= ?`, t.now)
}

// StaleProject is an active project overdue for a report.
type StaleProject struct {
	Project
	// Since is the last report, or creation for a project that never reported.
	Since time.Time
}

// staleReminder is how often a stale project is alerted about again.
const staleReminder = 7 * 24 * time.Hour

// StaleProjects returns active projects that have gone longer than their
// staleness threshold without a report and haven't been alerted about in
// the last week, and marks them alerted.
func (t *Tx) StaleProjects() ([]StaleProject, error) {
	now, err := time.Parse(time.RFC3339Nano, t.now)
	if err != nil {
		return nil, err
	}
	rows, err := t.tx.Query(`SELECT ` + projectCols + `, COALESCE(stale_alerted_at, '') FROM projects WHERE archived_at IS NULL`)
	if err != nil {
		return nil, err
	}
	var due []StaleProject
	for rows.Next() {
		var p Project
		var alerted string
		if err := rows.Scan(&p.ID, &p.Name, &p.StaleAfterDays, &p.CreatedAt, &p.ArchivedAt, &p.LastReportAt, &alerted); err != nil {
			rows.Close()
			return nil, err
		}
		since := p.LastReportAt
		if since == "" {
			since = p.CreatedAt
		}
		sinceT, err := time.Parse(time.RFC3339Nano, since)
		if err != nil {
			rows.Close()
			return nil, err
		}
		if now.Sub(sinceT) < time.Duration(p.StaleAfterDays)*24*time.Hour {
			continue
		}
		if alerted != "" {
			if a, err := time.Parse(time.RFC3339Nano, alerted); err == nil && now.Sub(a) < staleReminder {
				continue
			}
		}
		due = append(due, StaleProject{Project: p, Since: sinceT})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, p := range due {
		if _, err := t.tx.Exec(`UPDATE projects SET stale_alerted_at = ? WHERE id = ?`, t.now, p.ID); err != nil {
			return nil, err
		}
	}
	return due, nil
}
