package osvsync

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rubysolo/skope/internal/store"
)

// fakeOSV serves one ecosystem's all.zip, modified_id.csv and per-id JSON.
type fakeOSV struct {
	docs     map[string]string // id → JSON
	modified map[string]string // id → modified
	hits     []string
}

func (f *fakeOSV) put(id, modified, pkg string) {
	f.docs[id] = fmt.Sprintf(`{"id": %q, "modified": %q, "affected": [{"package": {"ecosystem": "Hex", "name": %q}, "versions": ["1.0.0"]}]}`, id, modified, pkg)
	f.modified[id] = modified
}

func (f *fakeOSV) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.hits = append(f.hits, r.URL.Path)
	switch {
	case r.URL.Path == "/Hex/all.zip":
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		for id, doc := range f.docs {
			fw, _ := zw.Create(id + ".json")
			fw.Write([]byte(doc))
		}
		zw.Close()
		w.Write(buf.Bytes())
	case r.URL.Path == "/Hex/modified_id.csv":
		ids := make([]string, 0, len(f.modified))
		for id := range f.modified {
			ids = append(ids, id)
		}
		slices.SortFunc(ids, func(a, b string) int { return strings.Compare(f.modified[b], f.modified[a]) }) // newest first
		for _, id := range ids {
			fmt.Fprintf(w, "%s,%s\n", f.modified[id], id)
		}
	case strings.HasPrefix(r.URL.Path, "/Hex/") && strings.HasSuffix(r.URL.Path, ".json"):
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/Hex/"), ".json")
		if doc, ok := f.docs[id]; ok {
			w.Write([]byte(doc))
			return
		}
		http.NotFound(w, r)
	default:
		http.NotFound(w, r)
	}
}

func setup(t *testing.T) (*fakeOSV, *Syncer, *store.Store) {
	f := &fakeOSV{docs: map[string]string{}, modified: map[string]string{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	st, err := store.Open(filepath.Join(t.TempDir(), "skope.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(st)
	s.BaseURL = srv.URL
	s.TempDir = t.TempDir()
	return f, s, st
}

func TestFirstSyncDownloadsArchive(t *testing.T) {
	f, s, st := setup(t)
	f.put("A", "2026-01-01T00:00:00Z", "plug")
	f.put("B", "2026-01-02T00:00:00Z", "phoenix")

	ids, err := s.Sync(context.Background(), "Hex")
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(ids)
	if !slices.Equal(ids, []string{"A", "B"}) {
		t.Errorf("changed = %v", ids)
	}
	if !slices.Contains(f.hits, "/Hex/all.zip") {
		t.Errorf("first sync should fetch all.zip; hits %v", f.hits)
	}
	st.Tx(context.Background(), func(tx *store.Tx) error {
		if c, _ := tx.SyncCursor("Hex"); c != "2026-01-02T00:00:00Z" {
			t.Errorf("cursor = %q", c)
		}
		if ids, _ := tx.AdvisoryIDsFor("Hex", "plug"); !slices.Equal(ids, []string{"A"}) {
			t.Errorf("index for plug = %v", ids)
		}
		return nil
	})
}

func TestLaterSyncsAreIncremental(t *testing.T) {
	f, s, _ := setup(t)
	f.put("A", "2026-01-01T00:00:00Z", "plug")
	f.put("B", "2026-01-02T00:00:00Z", "phoenix")
	if _, err := s.Sync(context.Background(), "Hex"); err != nil {
		t.Fatal(err)
	}

	f.hits = nil
	f.put("A", "2026-01-05T00:00:00Z", "plug") // modified
	f.put("C", "2026-01-06T00:00:00Z", "ecto") // new
	ids, err := s.Sync(context.Background(), "Hex")
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(ids)
	if !slices.Equal(ids, []string{"A", "C"}) {
		t.Errorf("changed = %v", ids)
	}
	if slices.Contains(f.hits, "/Hex/all.zip") || !slices.Contains(f.hits, "/Hex/C.json") || slices.Contains(f.hits, "/Hex/B.json") {
		t.Errorf("incremental sync should fetch only changed ids; hits %v", f.hits)
	}

	f.hits = nil
	if ids, _ := s.Sync(context.Background(), "Hex"); len(ids) != 0 {
		t.Errorf("nothing new: changed = %v", ids)
	}
}

func TestIncrementalSkipsVanishedAdvisory(t *testing.T) {
	f, s, _ := setup(t)
	f.put("A", "2026-01-01T00:00:00Z", "plug")
	s.Sync(context.Background(), "Hex")
	f.modified["GONE"] = "2026-02-01T00:00:00Z" // listed but 404s
	f.put("B", "2026-02-02T00:00:00Z", "ecto")
	ids, err := s.Sync(context.Background(), "Hex")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ids, []string{"B"}) {
		t.Errorf("changed = %v", ids)
	}
}
