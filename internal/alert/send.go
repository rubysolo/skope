package alert

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rubysolo/skope/internal/scan"
	"github.com/rubysolo/skope/internal/store"
)

// SMTP sends email through a submission server. Port 465 uses implicit TLS;
// any other port upgrades with STARTTLS when the server offers it.
type SMTP struct {
	Addr     string // host:port
	User     string
	Password string
	From     string
	To       []string
}

func (s *SMTP) Send(ctx context.Context, e Email) error {
	host, port, err := net.SplitHostPort(s.Addr)
	if err != nil {
		return err
	}
	var id [12]byte
	rand.Read(id[:])
	msg := strings.Join([]string{
		"From: " + s.From,
		"To: " + strings.Join(s.To, ", "),
		"Subject: " + mime.QEncoding.Encode("utf-8", e.Subject),
		"Date: " + time.Now().Format(time.RFC1123Z),
		"Message-ID: <" + hex.EncodeToString(id[:]) + "@skope>",
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"Content-Transfer-Encoding: 8bit",
		"",
		strings.ReplaceAll(e.Body, "\n", "\r\n"),
	}, "\r\n")

	var auth smtp.Auth
	if s.User != "" {
		auth = smtp.PlainAuth("", s.User, s.Password, host)
	}
	if port != "465" {
		return smtp.SendMail(s.Addr, auth, s.From, s.To, []byte(msg))
	}

	d := tls.Dialer{Config: &tls.Config{ServerName: host}}
	conn, err := d.DialContext(ctx, "tcp", s.Addr)
	if err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return err
		}
	}
	if err := c.Mail(s.From); err != nil {
		return err
	}
	for _, to := range s.To {
		if err := c.Rcpt(to); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// Ntfy publishes to a topic on an ntfy server.
type Ntfy struct {
	URL   string // server root, e.g. https://ntfy.sh
	Topic string
	Token string
	HTTP  *http.Client
}

func (n *Ntfy) Send(ctx context.Context, p Push) error {
	body, err := json.Marshal(map[string]any{
		"topic": n.Topic, "title": p.Title, "message": p.Message,
		"priority": p.Priority, "tags": p.Tags, "click": p.Click,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(n.URL, "/"), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if n.Token != "" {
		req.Header.Set("Authorization", "Bearer "+n.Token)
	}
	resp, err := n.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("ntfy: %s", resp.Status)
	}
	return nil
}

// Dispatcher sends each batch of changes to every configured channel. It
// implements the server's Notifier.
type Dispatcher struct {
	Email *SMTP // nil when email isn't configured
	Ntfy  *Ntfy // nil when push isn't configured
	// Backoff is the wait before each retry; a send is tried len(Backoff)+1 times.
	Backoff []time.Duration
	Now     func() time.Time
}

// FromEnv configures a Dispatcher from the environment:
//
//	SKOPE_SMTP_ADDR, SKOPE_SMTP_USER, SKOPE_SMTP_PASSWORD, SKOPE_EMAIL_FROM, SKOPE_EMAIL_TO
//	SKOPE_NTFY_TOPIC, SKOPE_NTFY_URL (default https://ntfy.sh), SKOPE_NTFY_TOKEN
func FromEnv() (*Dispatcher, error) {
	d := &Dispatcher{Backoff: []time.Duration{5 * time.Second, 30 * time.Second, 2 * time.Minute}, Now: time.Now}
	if addr := os.Getenv("SKOPE_SMTP_ADDR"); addr != "" {
		to := strings.FieldsFunc(os.Getenv("SKOPE_EMAIL_TO"), func(r rune) bool { return r == ',' || r == ' ' })
		from := os.Getenv("SKOPE_EMAIL_FROM")
		if from == "" || len(to) == 0 {
			return nil, errors.New("SKOPE_SMTP_ADDR is set, so SKOPE_EMAIL_FROM and SKOPE_EMAIL_TO must be too")
		}
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return nil, fmt.Errorf("SKOPE_SMTP_ADDR must be host:port: %w", err)
		}
		d.Email = &SMTP{Addr: addr, User: os.Getenv("SKOPE_SMTP_USER"), Password: os.Getenv("SKOPE_SMTP_PASSWORD"), From: from, To: to}
	}
	if topic := os.Getenv("SKOPE_NTFY_TOPIC"); topic != "" {
		url := os.Getenv("SKOPE_NTFY_URL")
		if url == "" {
			url = "https://ntfy.sh"
		}
		d.Ntfy = &Ntfy{URL: url, Topic: topic, Token: os.Getenv("SKOPE_NTFY_TOKEN"), HTTP: &http.Client{Timeout: 30 * time.Second}}
	}
	return d, nil
}

// Channels names the configured channels, for the startup log.
func (d *Dispatcher) Channels() []string {
	var cs []string
	if d.Email != nil {
		cs = append(cs, "email")
	}
	if d.Ntfy != nil {
		cs = append(cs, "ntfy")
	}
	return cs
}

func (d *Dispatcher) retry(ctx context.Context, channel string, send func() error) {
	for attempt := 0; ; attempt++ {
		err := send()
		if err == nil {
			return
		}
		if attempt >= len(d.Backoff) {
			slog.Error("alert not delivered", "channel", channel, "attempts", attempt+1, "err", err)
			return
		}
		slog.Warn("alert delivery failed; retrying", "channel", channel, "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(d.Backoff[attempt]):
		}
	}
}

// deliver sends to each channel concurrently, so one that's down and
// retrying doesn't hold up the others — above all, not an urgent push.
func (d *Dispatcher) deliver(ctx context.Context, e Email, sendEmail bool, p Push, sendPush bool) {
	var wg sync.WaitGroup
	if sendEmail && d.Email != nil {
		wg.Go(func() { d.retry(ctx, "email", func() error { return d.Email.Send(ctx, e) }) })
	}
	if sendPush && d.Ntfy != nil {
		wg.Go(func() { d.retry(ctx, "ntfy", func() error { return d.Ntfy.Send(ctx, p) }) })
	}
	wg.Wait()
}

// Notify alerts about one sync run's or one report's finding changes.
func (d *Dispatcher) Notify(ctx context.Context, changes []scan.Change) {
	for _, c := range changes {
		slog.Info("finding "+c.Kind.String(), "project", c.Project, "vulnerability", c.VulnID,
			"package", c.Name, "versions", c.Versions, "severity", c.Severity, "quiet", c.Quiet)
	}
	e, okE := ComposeEmail(changes)
	p, okP := ComposePush(changes)
	d.deliver(ctx, e, okE, p, okP)
}

// Stale alerts about projects that have stopped reporting.
func (d *Dispatcher) Stale(ctx context.Context, projects []store.StaleProject) {
	for _, p := range projects {
		slog.Warn("project stale", "project", p.Name, "since", p.Since)
	}
	e, p := ComposeStale(projects, d.Now())
	d.deliver(ctx, e, true, p, true)
}
