package alert

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rubysolo/skope/internal/osv"
	"github.com/rubysolo/skope/internal/scan"
)

// fakeSMTP accepts one plain (no TLS, no auth) SMTP session per connection
// and records each message's DATA.
type fakeSMTP struct {
	addr string
	mu   sync.Mutex
	msgs []string
	rcpt [][]string
}

func newFakeSMTP(t *testing.T) *fakeSMTP {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f := &fakeSMTP{addr: ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.session(conn)
		}
	}()
	return f
}

func (f *fakeSMTP) sent() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.msgs...)
}

func (f *fakeSMTP) session(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	say := func(s string) { io.WriteString(conn, s+"\r\n") }
	say("220 fake")
	var rcpt []string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			say("250 fake")
		case strings.HasPrefix(cmd, "MAIL"):
			say("250 ok")
		case strings.HasPrefix(cmd, "RCPT"):
			rcpt = append(rcpt, strings.Trim(strings.TrimSpace(line)[len("RCPT TO:"):], "<>"))
			say("250 ok")
		case cmd == "DATA":
			say("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil || l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.mu.Lock()
			f.msgs = append(f.msgs, b.String())
			f.rcpt = append(f.rcpt, rcpt)
			f.mu.Unlock()
			say("250 queued")
		case cmd == "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

func TestSMTPSend(t *testing.T) {
	f := newFakeSMTP(t)
	s := &SMTP{Addr: f.addr, From: "skope@example.com", To: []string{"me@example.com", "you@example.com"}}
	if err := s.Send(context.Background(), Email{Subject: "[skope] 1 new vulnerability in cure", Body: "NEW\n\nline two"}); err != nil {
		t.Fatal(err)
	}
	msgs := f.sent()
	if len(msgs) != 1 {
		t.Fatalf("messages = %d", len(msgs))
	}
	m := msgs[0]
	for _, want := range []string{"From: skope@example.com\r\n", "To: me@example.com, you@example.com\r\n",
		"Subject: [skope] 1 new vulnerability in cure\r\n", "Content-Type: text/plain; charset=utf-8\r\n", "\r\n\r\nNEW\r\n\r\nline two"} {
		if !strings.Contains(m, want) {
			t.Errorf("message missing %q:\n%s", want, m)
		}
	}
	if strings.Join(f.rcpt[0], ",") != "me@example.com,you@example.com" {
		t.Errorf("recipients = %v", f.rcpt[0])
	}
}

type fakeNtfy struct {
	mu       sync.Mutex
	failures int // respond 500 this many times first
	got      []map[string]any
	auth     []string
}

func (f *fakeNtfy) pushes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.got)
}

func (f *fakeNtfy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failures > 0 {
		f.failures--
		http.Error(w, "nope", http.StatusInternalServerError)
		return
	}
	var m map[string]any
	json.NewDecoder(r.Body).Decode(&m)
	f.got = append(f.got, m)
	f.auth = append(f.auth, r.Header.Get("Authorization"))
}

func TestNtfySend(t *testing.T) {
	f := &fakeNtfy{}
	srv := httptest.NewServer(f)
	defer srv.Close()
	n := &Ntfy{URL: srv.URL + "/", Topic: "skope-alerts", Token: "tk_secret", HTTP: srv.Client()}
	err := n.Send(context.Background(), Push{Title: "HIGH: CVE-1 in cure", Message: "m", Priority: 4, Tags: []string{"warning"}, Click: "https://osv.dev/vulnerability/GHSA-1"})
	if err != nil {
		t.Fatal(err)
	}
	m := f.got[0]
	if m["topic"] != "skope-alerts" || m["title"] != "HIGH: CVE-1 in cure" || m["priority"] != float64(4) || m["click"] != "https://osv.dev/vulnerability/GHSA-1" {
		t.Errorf("published %v", m)
	}
	if f.auth[0] != "Bearer tk_secret" {
		t.Errorf("auth = %q", f.auth[0])
	}
}

func TestDispatcherRoutesAndRetries(t *testing.T) {
	smtpSrv := newFakeSMTP(t)
	ntfy := &fakeNtfy{failures: 2}
	ntfySrv := httptest.NewServer(ntfy)
	defer ntfySrv.Close()
	d := &Dispatcher{
		Email:   &SMTP{Addr: smtpSrv.addr, From: "skope@example.com", To: []string{"me@example.com"}},
		Ntfy:    &Ntfy{URL: ntfySrv.URL, Topic: "t", HTTP: ntfySrv.Client()},
		Backoff: []time.Duration{time.Millisecond, time.Millisecond},
		Now:     time.Now,
	}

	medium := scan.Change{Kind: scan.Opened, FindingID: 1, Project: "cure", VulnID: "CVE-1", Severity: osv.Medium,
		Advisories: []*osv.Advisory{{ID: "GHSA-1"}}, Ecosystem: "Hex", Name: "plug", Versions: "1.0.0"}
	d.Notify(context.Background(), []scan.Change{medium})
	if len(smtpSrv.sent()) != 1 || ntfy.pushes() != 0 {
		t.Errorf("medium: %d emails, %d pushes; want 1, 0", len(smtpSrv.sent()), ntfy.pushes())
	}

	high := medium
	high.Severity, high.VulnID = osv.High, "CVE-2"
	d.Notify(context.Background(), []scan.Change{high})
	if len(smtpSrv.sent()) != 2 || ntfy.pushes() != 1 {
		t.Errorf("high (push fails twice, then succeeds): %d emails, %d pushes; want 2, 1", len(smtpSrv.sent()), ntfy.pushes())
	}

	ntfy.mu.Lock()
	ntfy.failures = 5
	ntfy.mu.Unlock()
	d.Notify(context.Background(), []scan.Change{high})
	ntfy.mu.Lock()
	left := ntfy.failures
	ntfy.mu.Unlock()
	if ntfy.pushes() != 1 || left != 2 {
		t.Errorf("gives up after 3 attempts: pushes %d, failures left %d", ntfy.pushes(), left)
	}
}

func TestFromEnv(t *testing.T) {
	t.Setenv("SKOPE_SMTP_ADDR", "")
	t.Setenv("SKOPE_NTFY_TOPIC", "")
	d, err := FromEnv()
	if err != nil || len(d.Channels()) != 0 {
		t.Errorf("nothing set: %v %v", d.Channels(), err)
	}

	t.Setenv("SKOPE_SMTP_ADDR", "smtp.example.com:587")
	if _, err := FromEnv(); err == nil {
		t.Error("SMTP without from/to should be rejected")
	}
	t.Setenv("SKOPE_EMAIL_FROM", "skope@example.com")
	t.Setenv("SKOPE_EMAIL_TO", "a@example.com, b@example.com")
	t.Setenv("SKOPE_NTFY_TOPIC", "skope")
	d, err = FromEnv()
	if err != nil || strings.Join(d.Channels(), ",") != "email,ntfy" || len(d.Email.To) != 2 || d.Ntfy.URL != "https://ntfy.sh" {
		t.Errorf("configured: %+v %v", d, err)
	}
}

func TestBrokenEmailDoesNotDelayPush(t *testing.T) {
	ntfy := &fakeNtfy{}
	ntfySrv := httptest.NewServer(ntfy)
	defer ntfySrv.Close()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close() // nothing listens here: every email attempt fails

	d := &Dispatcher{
		Email:   &SMTP{Addr: dead, From: "skope@example.com", To: []string{"me@example.com"}},
		Ntfy:    &Ntfy{URL: ntfySrv.URL, Topic: "t", HTTP: ntfySrv.Client()},
		Backoff: []time.Duration{time.Second, time.Second},
		Now:     time.Now,
	}
	high := scan.Change{Kind: scan.Opened, Project: "cure", VulnID: "CVE-1", Severity: osv.High,
		Advisories: []*osv.Advisory{{ID: "GHSA-1"}}, Ecosystem: "Hex", Name: "plug", Versions: "1.0.0"}
	go d.Notify(context.Background(), []scan.Change{high})

	deadline := time.Now().Add(500 * time.Millisecond)
	for ntfy.pushes() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if ntfy.pushes() != 1 {
		t.Error("push should go out while email is still retrying")
	}
}
