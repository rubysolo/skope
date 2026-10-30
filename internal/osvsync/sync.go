// Package osvsync refreshes the stored advisories from OSV's bulk exports.
package osvsync

import (
	"archive/zip"
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/rubysolo/skope/internal/osv"
	"github.com/rubysolo/skope/internal/store"
)

const DefaultBaseURL = "https://osv-vulnerabilities.storage.googleapis.com"

// maxIncremental is how many changed advisories are fetched one by one before
// it's cheaper to download the ecosystem's whole archive again.
const maxIncremental = 2000

type Syncer struct {
	st      *store.Store
	BaseURL string
	HTTP    *http.Client
	TempDir string // where all.zip is downloaded; "" for the OS default
}

func New(st *store.Store) *Syncer {
	return &Syncer{st: st, BaseURL: DefaultBaseURL, HTTP: &http.Client{Timeout: 10 * time.Minute}}
}

type modifiedRow struct{ modified, id string }

// Sync brings one ecosystem up to date and returns the ids of advisories that
// are new or modified.
//
// modified_id.csv lists every advisory with its modified time, newest first.
// The cursor is the newest time applied. On the first sync (or after a large
// gap) the whole archive is loaded; otherwise only the rows past the cursor.
// The cursor is taken from the CSV before the archive is downloaded, so an
// advisory modified in between is fetched again next time rather than missed.
func (s *Syncer) Sync(ctx context.Context, ecosystem string) ([]string, error) {
	var cursor string
	if err := s.st.Tx(ctx, func(tx *store.Tx) (err error) { cursor, err = tx.SyncCursor(ecosystem); return }); err != nil {
		return nil, err
	}
	rows, err := s.modifiedSince(ctx, ecosystem, cursor)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	newest := rows[0].modified

	var changed []string
	if cursor == "" || len(rows) > maxIncremental {
		changed, err = s.loadArchive(ctx, ecosystem)
	} else {
		changed, err = s.loadEach(ctx, ecosystem, rows)
	}
	if err != nil {
		return changed, err
	}
	err = s.st.Tx(ctx, func(tx *store.Tx) error { return tx.SetSyncCursor(ecosystem, newest) })
	return changed, err
}

func (s *Syncer) get(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(s.BaseURL, "/")+"/"+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return resp, fmt.Errorf("GET %s: %s", path, resp.Status)
	}
	return resp, nil
}

func (s *Syncer) modifiedSince(ctx context.Context, ecosystem, cursor string) ([]modifiedRow, error) {
	resp, err := s.get(ctx, ecosystem+"/modified_id.csv")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var rows []modifiedRow
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		modified, id, ok := strings.Cut(sc.Text(), ",")
		if !ok {
			continue
		}
		if modified <= cursor {
			break // newest first: everything after this is older
		}
		rows = append(rows, modifiedRow{modified, id})
	}
	return rows, sc.Err()
}

// upsert stores a batch of advisories in one transaction.
func (s *Syncer) upsert(ctx context.Context, advs []*osv.Advisory) ([]string, error) {
	var changed []string
	err := s.st.Tx(ctx, func(tx *store.Tx) error {
		for _, a := range advs {
			ok, err := tx.UpsertAdvisory(a)
			if err != nil {
				return fmt.Errorf("store %s: %w", a.ID, err)
			}
			if ok {
				changed = append(changed, a.ID)
			}
		}
		return nil
	})
	return changed, err
}

func (s *Syncer) loadEach(ctx context.Context, ecosystem string, rows []modifiedRow) ([]string, error) {
	var advs []*osv.Advisory
	for _, r := range rows {
		resp, err := s.get(ctx, ecosystem+"/"+r.id+".json")
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			slog.Warn("advisory listed but not served", "ecosystem", ecosystem, "id", r.id)
			continue
		}
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		a, err := osv.Parse(data)
		if err != nil {
			slog.Warn("skipping malformed advisory", "id", r.id, "err", err)
			continue
		}
		advs = append(advs, a)
	}
	return s.upsert(ctx, advs)
}

func (s *Syncer) loadArchive(ctx context.Context, ecosystem string) ([]string, error) {
	resp, err := s.get(ctx, ecosystem+"/all.zip")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// npm's archive is ~200MB: spool it to disk rather than memory.
	f, err := os.CreateTemp(s.TempDir, "osv-*.zip")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	size, err := io.Copy(f, resp.Body)
	if err != nil {
		return nil, fmt.Errorf("download %s archive: %w", ecosystem, err)
	}
	zr, err := zip.NewReader(f, size)
	if err != nil {
		return nil, fmt.Errorf("open %s archive: %w", ecosystem, err)
	}

	var batch []*osv.Advisory
	var ids []string
	flush := func() error {
		c, err := s.upsert(ctx, batch)
		ids = append(ids, c...)
		batch = batch[:0]
		return err
	}
	for _, zf := range zr.File {
		if !strings.HasSuffix(zf.Name, ".json") {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return ids, err
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return ids, err
		}
		a, err := osv.Parse(data)
		if err != nil {
			slog.Warn("skipping malformed advisory", "file", zf.Name, "err", err)
			continue
		}
		batch = append(batch, a)
		if len(batch) == 1000 {
			if err := flush(); err != nil {
				return ids, err
			}
		}
	}
	if err := flush(); err != nil {
		return ids, err
	}
	return slices.Clip(ids), nil
}
