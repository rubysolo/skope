package server

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/rubysolo/skope/internal/api"
	"github.com/rubysolo/skope/internal/osvsync"
	"github.com/rubysolo/skope/internal/scan"
	"github.com/rubysolo/skope/internal/store"
)

const adminToken = "test-admin-token"

// plugAdvisory affects plug versions [1.0.0, 1.5.0).
const plugAdvisory = `{"id": "GHSA-plug", "modified": "2026-01-01T00:00:00Z", "summary": "plug is bad",
  "database_specific": {"severity": "HIGH"},
  "affected": [{"package": {"ecosystem": "Hex", "name": "plug"},
    "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.5.0"}]}]}]}`

type recorder struct {
	mu      sync.Mutex
	batches [][]scan.Change
}

func (r *recorder) Notify(_ context.Context, cs []scan.Change) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.batches = append(r.batches, cs)
}

type harness struct {
	t      *testing.T
	srv    *Server
	http   *httptest.Server
	notify *recorder
}

// newHarness serves a fake OSV with one Hex advisory and syncs it.
func newHarness(t *testing.T) *harness {
	osvSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Hex/modified_id.csv":
			io.WriteString(w, "2026-01-01T00:00:00Z,GHSA-plug\n")
		case "/Hex/all.zip":
			var buf bytes.Buffer
			zw := zip.NewWriter(&buf)
			f, _ := zw.Create("GHSA-plug.json")
			io.WriteString(f, plugAdvisory)
			zw.Close()
			w.Write(buf.Bytes())
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(osvSrv.Close)

	st, err := store.Open(filepath.Join(t.TempDir(), "skope.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	syncer := osvsync.New(st)
	syncer.BaseURL = osvSrv.URL
	syncer.TempDir = t.TempDir()

	h := &harness{t: t, notify: &recorder{}}
	h.srv = New(st, syncer, adminToken, h.notify)
	h.srv.ecosystems = []string{"Hex"}
	h.srv.SyncAll(context.Background())
	h.http = httptest.NewServer(h.srv.Handler())
	t.Cleanup(h.http.Close)
	return h
}

func (h *harness) do(method, path, token string, body string, headers ...string) (*http.Response, []byte) {
	h.t.Helper()
	req, _ := http.NewRequest(method, h.http.URL+path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, data
}

func (h *harness) createProject(name string) string {
	h.t.Helper()
	resp, body := h.do("POST", "/v1/projects", adminToken, fmt.Sprintf(`{"name": %q}`, name))
	if resp.StatusCode != http.StatusCreated {
		h.t.Fatalf("create project: %d %s", resp.StatusCode, body)
	}
	var pt api.ProjectToken
	json.Unmarshal(body, &pt)
	return pt.Token
}

func (h *harness) report(token, purls string) (int, api.ReportResult) {
	h.t.Helper()
	resp, body := h.do("POST", "/v1/reports", token, `{"packages": [`+purls+`]}`, api.HeaderCommit, "abc123")
	var res api.ReportResult
	json.Unmarshal(body, &res)
	return resp.StatusCode, res
}

func TestReportFlow(t *testing.T) {
	h := newHarness(t)
	token := h.createProject("cure")

	status, res := h.report(token, `"pkg:hex/plug@1.2.0", "pkg:hex/phoenix@1.7.14", "pkg:github/actions/checkout@v4"`)
	if status != http.StatusOK {
		t.Fatalf("report status %d", status)
	}
	if res.Project != "cure" || res.Packages != 2 || res.Skipped != 1 {
		t.Errorf("result = %+v", res)
	}
	if len(res.Findings) != 1 || res.Findings[0].Vulnerability != "GHSA-plug" || res.Findings[0].Severity != "high" ||
		res.Findings[0].URL != "https://osv.dev/vulnerability/GHSA-plug" {
		t.Fatalf("findings = %+v", res.Findings)
	}
	if len(h.notify.batches) != 1 || h.notify.batches[0][0].Kind != scan.Opened {
		t.Errorf("notifications = %+v", h.notify.batches)
	}

	_, res = h.report(token, `"pkg:hex/plug@1.5.0"`)
	if len(res.Findings) != 0 {
		t.Errorf("fixed version: findings = %+v", res.Findings)
	}
	if len(h.notify.batches) != 2 || h.notify.batches[1][0].Kind != scan.Resolved {
		t.Errorf("want a resolved notification, got %+v", h.notify.batches)
	}
}

func TestReportRejects(t *testing.T) {
	h := newHarness(t)
	token := h.createProject("cure")
	if status, _ := h.report("skope_wrong", `"pkg:hex/plug@1.2.0"`); status != http.StatusUnauthorized {
		t.Errorf("bad token: %d", status)
	}
	if status, _ := h.report(adminToken, `"pkg:hex/plug@1.2.0"`); status != http.StatusUnauthorized {
		t.Errorf("admin token is not a project token: %d", status)
	}
	if resp, _ := h.do("POST", "/v1/reports", token, `{"nope": 1}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad body: %d", resp.StatusCode)
	}
}

func TestAdminRequiresToken(t *testing.T) {
	h := newHarness(t)
	token := h.createProject("cure")
	for _, tok := range []string{"", "wrong", token} {
		if resp, _ := h.do("GET", "/v1/projects", tok, ""); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("token %q: status %d, want 401", tok, resp.StatusCode)
		}
	}
}

func TestProjectAdmin(t *testing.T) {
	h := newHarness(t)
	old := h.createProject("cure")

	if resp, _ := h.do("POST", "/v1/projects", adminToken, `{"name": "cure"}`); resp.StatusCode != http.StatusConflict {
		t.Errorf("duplicate: %d", resp.StatusCode)
	}
	if resp, _ := h.do("POST", "/v1/projects", adminToken, `{"name": "no spaces"}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad name: %d", resp.StatusCode)
	}

	resp, body := h.do("POST", "/v1/projects/cure/token", adminToken, "")
	var pt api.ProjectToken
	json.Unmarshal(body, &pt)
	if resp.StatusCode != http.StatusOK || pt.Token == "" || pt.Token == old {
		t.Fatalf("rotate: %d %s", resp.StatusCode, body)
	}
	if status, _ := h.report(old, `"pkg:hex/plug@1.2.0"`); status != http.StatusUnauthorized {
		t.Errorf("rotated-out token still works: %d", status)
	}
	h.report(pt.Token, `"pkg:hex/plug@1.2.0"`)

	if resp, _ := h.do("POST", "/v1/projects/cure/archive", adminToken, ""); resp.StatusCode != http.StatusNoContent {
		t.Errorf("archive: %d", resp.StatusCode)
	}
	if status, _ := h.report(pt.Token, `"pkg:hex/plug@1.2.0"`); status != http.StatusUnauthorized {
		t.Errorf("archived project can still report: %d", status)
	}
	_, body = h.do("GET", "/v1/findings", adminToken, "")
	if strings.TrimSpace(string(body)) != "[]" {
		t.Errorf("archive should resolve findings: %s", body)
	}

	if resp, _ := h.do("DELETE", "/v1/projects/cure", adminToken, ""); resp.StatusCode != http.StatusNoContent {
		t.Errorf("delete: %d", resp.StatusCode)
	}
	if resp, _ := h.do("DELETE", "/v1/projects/cure", adminToken, ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("delete again: %d", resp.StatusCode)
	}
}

func TestIgnoreFinding(t *testing.T) {
	h := newHarness(t)
	token := h.createProject("cure")
	_, res := h.report(token, `"pkg:hex/plug@1.2.0"`)
	id := res.Findings[0].ID
	path := fmt.Sprintf("/v1/findings/%d/ignore", id)

	if resp, _ := h.do("PUT", path, adminToken, `{"reason": ""}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("empty reason: %d", resp.StatusCode)
	}
	if resp, _ := h.do("PUT", path, adminToken, `{"reason": "x", "until": "soon"}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad until: %d", resp.StatusCode)
	}
	if resp, body := h.do("PUT", path, adminToken, `{"reason": "not reachable", "until": "2099-01-01"}`); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("ignore: %d %s", resp.StatusCode, body)
	}
	_, body := h.do("GET", "/v1/findings?project=cure", adminToken, "")
	var fs []api.Finding
	json.Unmarshal(body, &fs)
	if len(fs) != 1 || fs[0].Ignored == nil || fs[0].Ignored.Until != "2099-01-01T00:00:00Z" {
		t.Errorf("findings = %s", body)
	}

	if resp, _ := h.do("DELETE", path, adminToken, ""); resp.StatusCode != http.StatusNoContent {
		t.Errorf("unignore: %d", resp.StatusCode)
	}
	if resp, _ := h.do("PUT", "/v1/findings/9999/ignore", adminToken, `{"reason": "x"}`); resp.StatusCode != http.StatusNotFound {
		t.Errorf("missing finding: %d", resp.StatusCode)
	}
}

func TestHealthz(t *testing.T) {
	h := newHarness(t)
	if resp, _ := h.do("GET", "/healthz", "", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("healthz: %d", resp.StatusCode)
	}
}
