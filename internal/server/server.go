// Package server is skope's HTTP API and background sync loop.
package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rubysolo/skope/internal/api"
	"github.com/rubysolo/skope/internal/osvsync"
	"github.com/rubysolo/skope/internal/pkgid"
	"github.com/rubysolo/skope/internal/report"
	"github.com/rubysolo/skope/internal/scan"
	"github.com/rubysolo/skope/internal/store"
)

// maxReportBytes bounds a report body. A large npm SBOM is ~10MB.
const maxReportBytes = 64 << 20

// reportRetention is how long the report log is kept.
const reportRetention = 90 * 24 * time.Hour

// Notifier receives the finding changes from one sync run or one report.
type Notifier interface {
	Notify(ctx context.Context, changes []scan.Change)
}

// LogNotifier logs changes; it stands in until alert channels are configured.
type LogNotifier struct{}

func (LogNotifier) Notify(_ context.Context, changes []scan.Change) {
	for _, c := range changes {
		slog.Info("finding "+c.Kind.String(), "project", c.Project, "vulnerability", c.VulnID,
			"package", c.Name, "versions", c.Versions, "severity", c.Severity, "quiet", c.Quiet)
	}
}

type Server struct {
	st         *store.Store
	scanner    *scan.Scanner
	syncer     *osvsync.Syncer
	adminToken string
	notifier   Notifier
	ecosystems []string
	syncMu     sync.Mutex
}

func New(st *store.Store, syncer *osvsync.Syncer, adminToken string, notifier Notifier) *Server {
	return &Server{st: st, scanner: scan.New(st), syncer: syncer, adminToken: adminToken,
		notifier: notifier, ecosystems: pkgid.Ecosystems()}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok\n") })
	mux.HandleFunc("POST /v1/reports", s.postReport)

	admin := func(h http.HandlerFunc) http.HandlerFunc { return s.requireAdmin(h) }
	mux.HandleFunc("GET /v1/projects", admin(s.listProjects))
	mux.HandleFunc("POST /v1/projects", admin(s.createProject))
	mux.HandleFunc("POST /v1/projects/{name}/token", admin(s.rotateToken))
	mux.HandleFunc("POST /v1/projects/{name}/archive", admin(s.archiveProject))
	mux.HandleFunc("DELETE /v1/projects/{name}", admin(s.deleteProject))
	mux.HandleFunc("GET /v1/findings", admin(s.listFindings))
	mux.HandleFunc("PUT /v1/findings/{id}/ignore", admin(s.ignoreFinding))
	mux.HandleFunc("DELETE /v1/findings/{id}/ignore", admin(s.unignoreFinding))
	mux.HandleFunc("POST /v1/sync", admin(s.triggerSync))
	return mux
}

// --- background work --------------------------------------------------------

// Run syncs immediately and then every interval until ctx is done.
func (s *Server) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		s.SyncAll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// SyncAll syncs every ecosystem, matches what changed, and notifies once for
// the whole run. Overlapping calls wait rather than run twice.
func (s *Server) SyncAll(ctx context.Context) {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	var all []scan.Change
	for _, eco := range s.ecosystems {
		start := time.Now()
		ids, err := s.syncer.Sync(ctx, eco)
		if err != nil {
			slog.Error("sync failed", "ecosystem", eco, "err", err)
		}
		if len(ids) == 0 {
			continue
		}
		changes, err := s.scanner.Advisories(ctx, ids)
		if err != nil {
			slog.Error("matching failed", "ecosystem", eco, "err", err)
		}
		all = append(all, changes...)
		slog.Info("synced", "ecosystem", eco, "advisories", len(ids), "changes", len(changes), "took", time.Since(start).Round(time.Millisecond))
	}
	if err := s.st.Tx(ctx, func(tx *store.Tx) error {
		_, err := tx.PruneReports(time.Now().Add(-reportRetention).UTC().Format(time.RFC3339Nano))
		return err
	}); err != nil {
		slog.Error("pruning report log failed", "err", err)
	}
	if len(all) > 0 {
		s.notifier.Notify(ctx, all)
	}
}

// --- helpers ----------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, api.Error{Error: msg})
}

// storeError maps store errors to responses; anything unexpected is logged
// and reported as a 500 without detail.
func storeError(w http.ResponseWriter, err error, what string) {
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, what+" not found")
		return
	}
	slog.Error("request failed", "err", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

func bearer(r *http.Request) string {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return ""
	}
	return strings.TrimSpace(token)
}

func (s *Server) requireAdmin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.adminToken == "" || subtle.ConstantTimeCompare([]byte(bearer(r)), []byte(s.adminToken)) != 1 {
			writeError(w, http.StatusUnauthorized, "admin token required")
			return
		}
		h(w, r)
	}
}

func toAPIProject(p store.Project) api.Project {
	return api.Project{Name: p.Name, StaleAfterDays: p.StaleAfterDays, CreatedAt: p.CreatedAt,
		ArchivedAt: p.ArchivedAt, LastReportAt: p.LastReportAt}
}

func toAPIFinding(v store.FindingView) api.Finding {
	advisories := strings.Split(v.AdvisoryIDs, ",")
	f := api.Finding{ID: v.ID, Project: v.Project, Vulnerability: v.VulnID, Advisories: advisories, Summary: v.Summary,
		URL:       api.AdvisoryURL(advisories[0]),
		Ecosystem: v.Ecosystem, Package: v.Name, Versions: v.Versions, Severity: v.Severity,
		OpenedAt: v.OpenedAt, ResolvedAt: v.ResolvedAt}
	if v.IgnoredReason != "" {
		f.Ignored = &api.Ignored{Reason: v.IgnoredReason, Until: v.IgnoredUntil}
	}
	return f
}

// --- reports ----------------------------------------------------------------

func (s *Server) postReport(w http.ResponseWriter, r *http.Request) {
	var project store.Project
	err := s.st.Tx(r.Context(), func(tx *store.Tx) (err error) { project, err = tx.ProjectByToken(bearer(r)); return })
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusUnauthorized, "invalid project token")
			return
		}
		storeError(w, err, "project")
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxReportBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "report too large")
		return
	}
	rep, err := report.Parse(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	meta := store.ReportMeta{Commit: r.Header.Get(api.HeaderCommit), Ref: r.Header.Get(api.HeaderRef), RunURL: r.Header.Get(api.HeaderRunURL)}
	changes, err := s.scanner.Report(r.Context(), project.ID, meta, rep.Packages)
	if err != nil {
		storeError(w, err, "project")
		return
	}
	if len(changes) > 0 {
		s.notifier.Notify(context.WithoutCancel(r.Context()), changes)
	}

	res := api.ReportResult{Project: project.Name, Packages: len(rep.Packages), Skipped: rep.Skipped, Findings: []api.Finding{}}
	err = s.st.Tx(r.Context(), func(tx *store.Tx) error {
		views, err := tx.FindingViews(store.FindingFilter{ProjectID: project.ID})
		for _, v := range views {
			res.Findings = append(res.Findings, toAPIFinding(v))
		}
		return err
	})
	if err != nil {
		storeError(w, err, "project")
		return
	}
	slog.Info("report", "project", project.Name, "packages", len(rep.Packages), "skipped", rep.Skipped,
		"commit", meta.Commit, "changes", len(changes))
	writeJSON(w, http.StatusOK, res)
}

// --- projects ---------------------------------------------------------------

func (s *Server) listProjects(w http.ResponseWriter, r *http.Request) {
	out := []api.Project{}
	err := s.st.Tx(r.Context(), func(tx *store.Tx) error {
		ps, err := tx.Projects()
		for _, p := range ps {
			out = append(out, toAPIProject(p))
		}
		return err
	})
	if err != nil {
		storeError(w, err, "project")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func validName(name string) bool {
	if name == "" || len(name) > 100 {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-_.", c)) {
			return false
		}
	}
	return true
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	var req api.CreateProject
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if !validName(req.Name) {
		writeError(w, http.StatusBadRequest, "project names use letters, digits, '-', '_' and '.'")
		return
	}
	var res api.ProjectToken
	err := s.st.Tx(r.Context(), func(tx *store.Tx) error {
		p, token, err := tx.CreateProject(req.Name)
		res = api.ProjectToken{Project: toAPIProject(p), Token: token}
		return err
	})
	if err != nil {
		if errors.Is(err, store.ErrExists) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		storeError(w, err, "project")
		return
	}
	writeJSON(w, http.StatusCreated, res)
}

// withProject runs fn on the named project inside a transaction.
func (s *Server) withProject(w http.ResponseWriter, r *http.Request, fn func(*store.Tx, store.Project) error) bool {
	err := s.st.Tx(r.Context(), func(tx *store.Tx) error {
		p, err := tx.ProjectByName(r.PathValue("name"))
		if err != nil {
			return err
		}
		return fn(tx, p)
	})
	if err != nil {
		storeError(w, err, "project")
		return false
	}
	return true
}

func (s *Server) rotateToken(w http.ResponseWriter, r *http.Request) {
	var res api.ProjectToken
	if s.withProject(w, r, func(tx *store.Tx, p store.Project) error {
		token, err := tx.RotateToken(p.ID)
		res = api.ProjectToken{Project: toAPIProject(p), Token: token}
		return err
	}) {
		writeJSON(w, http.StatusOK, res)
	}
}

func (s *Server) archiveProject(w http.ResponseWriter, r *http.Request) {
	if s.withProject(w, r, func(tx *store.Tx, p store.Project) error { return tx.ArchiveProject(p.ID) }) {
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) deleteProject(w http.ResponseWriter, r *http.Request) {
	if s.withProject(w, r, func(tx *store.Tx, p store.Project) error { return tx.DeleteProject(p.ID) }) {
		w.WriteHeader(http.StatusNoContent)
	}
}

// --- findings ---------------------------------------------------------------

func (s *Server) listFindings(w http.ResponseWriter, r *http.Request) {
	out := []api.Finding{}
	err := s.st.Tx(r.Context(), func(tx *store.Tx) error {
		filter := store.FindingFilter{IncludeResolved: r.URL.Query().Get("all") == "1"}
		if name := r.URL.Query().Get("project"); name != "" {
			p, err := tx.ProjectByName(name)
			if err != nil {
				return err
			}
			filter.ProjectID = p.ID
		}
		views, err := tx.FindingViews(filter)
		for _, v := range views {
			out = append(out, toAPIFinding(v))
		}
		return err
	})
	if err != nil {
		storeError(w, err, "project")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// parseUntil accepts a date or an RFC 3339 time and returns RFC 3339 UTC.
func parseUntil(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	if t, err := time.Parse(time.DateOnly, s); err == nil {
		return t.UTC().Format(time.RFC3339), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return "", errors.New("until must be a date (2027-01-01) or an RFC 3339 time")
	}
	return t.UTC().Format(time.RFC3339), nil
}

func (s *Server) ignoreFinding(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid finding id")
		return
	}
	var req api.Ignore
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if strings.TrimSpace(req.Reason) == "" {
		writeError(w, http.StatusBadRequest, "a reason is required")
		return
	}
	until, err := parseUntil(req.Until)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	err = s.st.Tx(r.Context(), func(tx *store.Tx) error {
		f, err := tx.FindingByID(id)
		if err != nil {
			return err
		}
		g, err := tx.VulnGroup(f.VulnID)
		if err != nil {
			return err
		}
		modified, err := tx.VulnModified(g.Advisories)
		if err != nil {
			return err
		}
		return tx.IgnoreFinding(id, req.Reason, until, modified)
	})
	if err != nil {
		storeError(w, err, "open finding")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) unignoreFinding(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid finding id")
		return
	}
	err = s.st.Tx(r.Context(), func(tx *store.Tx) error {
		if _, err := tx.FindingByID(id); err != nil {
			return err
		}
		return tx.Unignore(id)
	})
	if err != nil {
		storeError(w, err, "finding")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) triggerSync(w http.ResponseWriter, r *http.Request) {
	go s.SyncAll(context.WithoutCancel(r.Context()))
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "sync started"})
}
