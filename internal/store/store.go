// Package store persists projects, inventories, advisories and findings in
// SQLite.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/rubysolo/skope/internal/osv"
	"github.com/rubysolo/skope/internal/pkgid"
)

//go:embed schema.sql
var schemaV1 string

//go:embed schema_v2.sql
var schemaV2 string

//go:embed schema_v3.sql
var schemaV3 string

// migrations[i] takes the database from user_version i to i+1.
var migrations = []string{schemaV1, schemaV2, schemaV3}

var (
	ErrNotFound = errors.New("not found")
	ErrExists   = errors.New("already exists")
)

type Store struct {
	db  *sql.DB
	Now func() time.Time
}

// Open opens (creating if needed) and migrates the database at path.
func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection serialises writers; Skope's write volume is tiny.
	db.SetMaxOpenConns(1)
	s := &Store{db: db, Now: func() time.Time { return time.Now().UTC() }}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	var version int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	for i := version; i < len(migrations); i++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) now() string { return s.Now().UTC().Format(time.RFC3339Nano) }

// Tx runs fn in a transaction, committing if it returns nil.
func (s *Store) Tx(ctx context.Context, fn func(*Tx) error) error {
	sqlTx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(&Tx{tx: sqlTx, now: s.now()}); err != nil {
		sqlTx.Rollback()
		return err
	}
	return sqlTx.Commit()
}

// Tx is a unit of work; every write happens through one.
type Tx struct {
	tx  *sql.Tx
	now string
}

// --- projects -------------------------------------------------------------

type Project struct {
	ID             int64
	Name           string
	StaleAfterDays int
	CreatedAt      string
	ArchivedAt     string
	LastReportAt   string
}

const tokenPrefix = "skope_"

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func newToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return tokenPrefix + hex.EncodeToString(b), nil
}

// CreateProject registers a project and returns its first project token. The
// token is only ever available here and from RotateToken.
func (t *Tx) CreateProject(name string) (Project, string, error) {
	token, err := newToken()
	if err != nil {
		return Project{}, "", err
	}
	res, err := t.tx.Exec(`INSERT INTO projects (name, token_hash, created_at) VALUES (?, ?, ?)`,
		name, hashToken(token), t.now)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return Project{}, "", fmt.Errorf("project %q %w", name, ErrExists)
		}
		return Project{}, "", err
	}
	id, _ := res.LastInsertId()
	return Project{ID: id, Name: name, StaleAfterDays: 30, CreatedAt: t.now}, token, nil
}

const projectCols = `id, name, stale_after_days, created_at, COALESCE(archived_at, ''), COALESCE(last_report_at, '')`

func scanProject(row interface{ Scan(...any) error }) (Project, error) {
	var p Project
	err := row.Scan(&p.ID, &p.Name, &p.StaleAfterDays, &p.CreatedAt, &p.ArchivedAt, &p.LastReportAt)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

// ProjectByToken authenticates a project token. Archived projects have no
// token, so they never authenticate.
func (t *Tx) ProjectByToken(token string) (Project, error) {
	if !strings.HasPrefix(token, tokenPrefix) {
		return Project{}, ErrNotFound
	}
	return scanProject(t.tx.QueryRow(`SELECT `+projectCols+` FROM projects WHERE token_hash = ?`, hashToken(token)))
}

// --- reports and inventory --------------------------------------------------

// SourceRepo is the source a report comes from unless it names another: the
// project repository's lockfiles. Container images are "image:<name>".
const SourceRepo = "repo"

type ReportMeta struct {
	// Source is where the packages were read from; "" means SourceRepo.
	Source              string
	Commit, Ref, RunURL string
}

func (m ReportMeta) source() string {
	if m.Source == "" {
		return SourceRepo
	}
	return m.Source
}

// RecordReport replaces the report's source's part of the project's inventory
// and logs the report.
func (t *Tx) RecordReport(projectID int64, meta ReportMeta, pkgs []pkgid.Package) (int64, error) {
	source := meta.source()
	res, err := t.tx.Exec(`INSERT INTO reports (project_id, source, received_at, commit_sha, ref, run_url, package_count)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, projectID, source, t.now, meta.Commit, meta.Ref, meta.RunURL, len(pkgs))
	if err != nil {
		return 0, err
	}
	reportID, _ := res.LastInsertId()
	if _, err := t.tx.Exec(`DELETE FROM inventory WHERE project_id = ? AND source = ?`, projectID, source); err != nil {
		return 0, err
	}
	stmt, err := t.tx.Prepare(`INSERT OR IGNORE INTO inventory (project_id, source, ecosystem, name_key, name, version) VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	for _, p := range pkgs {
		if _, err := stmt.Exec(projectID, source, p.Ecosystem, p.Key(), p.Name, p.Version); err != nil {
			return 0, err
		}
	}
	_, err = t.tx.Exec(`UPDATE projects SET last_report_at = ?, stale_alerted_at = NULL WHERE id = ?`, t.now, projectID)
	return reportID, err
}

// InventoryEntry is an inventory package together with its project and source.
type InventoryEntry struct {
	ProjectID int64
	Source    string
	Package   pkgid.Package
}

func (t *Tx) inventory(where string, args ...any) ([]InventoryEntry, error) {
	rows, err := t.tx.Query(`SELECT i.project_id, i.source, i.ecosystem, i.name, i.version
		FROM inventory i JOIN projects p ON p.id = i.project_id
		WHERE `+where+` ORDER BY i.project_id, i.source, i.ecosystem, i.name_key, i.version`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []InventoryEntry
	for rows.Next() {
		var e InventoryEntry
		if err := rows.Scan(&e.ProjectID, &e.Source, &e.Package.Ecosystem, &e.Package.Name, &e.Package.Version); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Inventory returns a project's current packages from every source.
func (t *Tx) Inventory(projectID int64) ([]InventoryEntry, error) {
	return t.inventory(`i.project_id = ?`, projectID)
}

// InventoryUsing returns every package version, across active projects, that
// is the given package.
func (t *Tx) InventoryUsing(ref osv.PackageRef) ([]InventoryEntry, error) {
	return t.inventory(`i.ecosystem = ? AND i.name_key = ? AND p.archived_at IS NULL`, ref.Ecosystem, ref.Key)
}

// LatestReportID returns the project's most recent report, or 0.
func (t *Tx) LatestReportID(projectID int64) (int64, error) {
	var id sql.NullInt64
	err := t.tx.QueryRow(`SELECT MAX(id) FROM reports WHERE project_id = ?`, projectID).Scan(&id)
	return id.Int64, err
}

// --- advisories -------------------------------------------------------------

// UpsertAdvisory stores an advisory and indexes the packages it names.
// It reports whether anything changed (a new id, or a new modified time).
// Only the fields osv.Advisory models are kept, which is about a third of the
// size of OSV's full documents.
func (t *Tx) UpsertAdvisory(a *osv.Advisory) (bool, error) {
	var modified string
	err := t.tx.QueryRow(`SELECT modified FROM advisories WHERE id = ?`, a.ID).Scan(&modified)
	switch {
	case err == nil && modified == a.Modified:
		return false, nil
	case err != nil && !errors.Is(err, sql.ErrNoRows):
		return false, err
	}
	raw, err := json.Marshal(a.Compact())
	if err != nil {
		return false, err
	}
	withdrawn := 0
	if a.Withdrawn != "" {
		withdrawn = 1
	}
	if _, err := t.tx.Exec(`INSERT INTO advisories (id, modified, severity, withdrawn, summary, raw) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET modified = excluded.modified, severity = excluded.severity,
		  withdrawn = excluded.withdrawn, summary = excluded.summary, raw = excluded.raw`,
		a.ID, a.Modified, a.Severity().String(), withdrawn, a.Summary, raw); err != nil {
		return false, err
	}
	if _, err := t.tx.Exec(`DELETE FROM advisory_packages WHERE advisory_id = ?`, a.ID); err != nil {
		return false, err
	}
	if _, err := t.tx.Exec(`DELETE FROM advisory_aliases WHERE advisory_id = ?`, a.ID); err != nil {
		return false, err
	}
	for _, alias := range append([]string{a.ID}, a.OtherIDs()...) {
		if _, err := t.tx.Exec(`INSERT OR IGNORE INTO advisory_aliases (alias, advisory_id) VALUES (?, ?)`, alias, a.ID); err != nil {
			return false, err
		}
	}
	for _, ref := range a.Packages() {
		if _, err := t.tx.Exec(`INSERT INTO advisory_packages (advisory_id, ecosystem, name_key) VALUES (?, ?, ?)`,
			a.ID, ref.Ecosystem, ref.Key); err != nil {
			return false, err
		}
	}
	return true, nil
}

// Advisory loads a stored advisory.
func (t *Tx) Advisory(id string) (*osv.Advisory, error) {
	var raw []byte
	err := t.tx.QueryRow(`SELECT raw FROM advisories WHERE id = ?`, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return osv.Parse(raw)
}

// AdvisoryIDsFor lists the advisories that name a package.
func (t *Tx) AdvisoryIDsFor(ecosystem, nameKey string) ([]string, error) {
	return t.strings(`SELECT advisory_id FROM advisory_packages WHERE ecosystem = ? AND name_key = ?`, ecosystem, nameKey)
}

func (t *Tx) strings(query string, args ...any) ([]string, error) {
	rows, err := t.tx.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// --- sync state -------------------------------------------------------------

// SyncCursor returns the newest advisory modified time applied for an
// ecosystem, or "" before the first sync.
func (t *Tx) SyncCursor(ecosystem string) (string, error) {
	var c string
	err := t.tx.QueryRow(`SELECT last_modified FROM sync_state WHERE ecosystem = ?`, ecosystem).Scan(&c)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return c, err
}

func (t *Tx) SetSyncCursor(ecosystem, cursor string) error {
	_, err := t.tx.Exec(`INSERT INTO sync_state (ecosystem, last_modified) VALUES (?, ?)
		ON CONFLICT (ecosystem) DO UPDATE SET last_modified = excluded.last_modified`, ecosystem, cursor)
	return err
}

// --- findings ---------------------------------------------------------------

type Finding struct {
	ID        int64
	ProjectID int64
	// VulnID keys the vulnerability: the smallest identifier in its alias group.
	VulnID string
	// AdvisoryIDs lists the group's advisories that matched, comma-separated.
	AdvisoryIDs string
	Summary     string
	Ecosystem   string
	NameKey     string
	Name        string
	Versions    string
	// Sources lists the sources containing an affected version, comma-separated.
	Sources  string
	Severity string
	// Fixable is false while no advisory names a fixed version (unfixed).
	Fixable       bool
	OpenedAt      string
	ResolvedAt    string
	IgnoredReason string
	IgnoredUntil  string
	// IgnoredModified is the vulnerability's modified time when it was ignored.
	IgnoredModified string
}

// Ignored reports whether the finding is muted at time now (RFC 3339).
func (f Finding) Ignored(now string) bool {
	return f.IgnoredReason != "" && (f.IgnoredUntil == "" || f.IgnoredUntil > now)
}

const findingCols = `id, project_id, vuln_id, advisory_ids, summary, ecosystem, name_key, name, versions, sources, severity, fixable, opened_at,
	COALESCE(resolved_at, ''), COALESCE(ignored_reason, ''), COALESCE(ignored_until, ''), COALESCE(ignored_modified, '')`

func (t *Tx) findings(where string, args ...any) ([]Finding, error) {
	rows, err := t.tx.Query(`SELECT `+findingCols+` FROM findings WHERE `+where+` ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.ID, &f.ProjectID, &f.VulnID, &f.AdvisoryIDs, &f.Summary, &f.Ecosystem, &f.NameKey, &f.Name, &f.Versions,
			&f.Sources, &f.Severity, &f.Fixable, &f.OpenedAt, &f.ResolvedAt, &f.IgnoredReason, &f.IgnoredUntil, &f.IgnoredModified); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (t *Tx) OpenFindingsForProject(projectID int64) ([]Finding, error) {
	return t.findings(`project_id = ? AND resolved_at IS NULL`, projectID)
}

// OpenFindingsForVulns returns open findings keyed by any of ids. A
// vulnerability's key can change when alias groups merge, so callers pass
// every identifier in the group to catch findings under a former key.
func (t *Tx) OpenFindingsForVulns(ids []string) ([]Finding, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	return t.findings(`vuln_id IN (?`+strings.Repeat(", ?", len(ids)-1)+`) AND resolved_at IS NULL`, args...)
}

// InsertFinding opens a finding; reportID 0 means none is known.
func (t *Tx) InsertFinding(f Finding, reportID int64) (int64, error) {
	var rid any
	if reportID != 0 {
		rid = reportID
	}
	res, err := t.tx.Exec(`INSERT INTO findings (project_id, vuln_id, advisory_ids, summary, ecosystem, name_key, name, versions, sources, severity, fixable, opened_at, introduced_report_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ProjectID, f.VulnID, f.AdvisoryIDs, f.Summary, f.Ecosystem, f.NameKey, f.Name, f.Versions, f.Sources, f.Severity, f.Fixable, t.now, rid)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateFinding refreshes an open finding's descriptive fields.
func (t *Tx) UpdateFinding(f Finding) error {
	_, err := t.tx.Exec(`UPDATE findings SET advisory_ids = ?, summary = ?, versions = ?, sources = ?, severity = ?, fixable = ? WHERE id = ?`,
		f.AdvisoryIDs, f.Summary, f.Versions, f.Sources, f.Severity, f.Fixable, f.ID)
	return err
}

// RekeyFinding moves an open finding to its vulnerability's new key.
func (t *Tx) RekeyFinding(id int64, vulnID string) error {
	_, err := t.tx.Exec(`UPDATE findings SET vuln_id = ? WHERE id = ?`, vulnID, id)
	return err
}

func (t *Tx) ResolveFinding(id int64) error {
	_, err := t.tx.Exec(`UPDATE findings SET resolved_at = ? WHERE id = ?`, t.now, id)
	return err
}

// IgnoreFinding mutes an open finding until `until` ("" for indefinitely),
// remembering the vulnerability's state (VulnGroup.Modified) it was judged
// against.
func (t *Tx) IgnoreFinding(id int64, reason, until, vulnModified string) error {
	res, err := t.tx.Exec(`UPDATE findings SET ignored_reason = ?, ignored_until = NULLIF(?, ''), ignored_modified = ?
		WHERE id = ? AND resolved_at IS NULL`, reason, until, vulnModified, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (t *Tx) Unignore(id int64) error {
	_, err := t.tx.Exec(`UPDATE findings SET ignored_reason = NULL, ignored_until = NULL, ignored_modified = NULL WHERE id = ?`, id)
	return err
}

// Now is the transaction's timestamp (RFC 3339, UTC).
func (t *Tx) Now() string { return t.now }

// ProjectName looks up a project's name by id.
func (t *Tx) ProjectName(id int64) (string, error) {
	var name string
	err := t.tx.QueryRow(`SELECT name FROM projects WHERE id = ?`, id).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return name, err
}
