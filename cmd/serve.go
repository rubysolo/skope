package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/rubysolo/skope/internal/alert"
	"github.com/rubysolo/skope/internal/osvsync"
	"github.com/rubysolo/skope/internal/server"
	"github.com/rubysolo/skope/internal/store"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the skope server",
	Long: `Run the skope server: the report endpoint, the admin API, and the hourly
advisory sync.

Configuration comes from the environment:
  SKOPE_ADMIN_TOKEN    required; authenticates the admin API
  SKOPE_DB             database path (default skope.db)
  SKOPE_LISTEN         listen address (default 127.0.0.1:8080)
  SKOPE_SYNC_INTERVAL  time between syncs (default 1h)
  SKOPE_ECOSYSTEMS     comma-separated ecosystems to sync (default all:
                       Hex,crates.io,RubyGems,npm,Go,PyPI)

Alerts (each channel is optional):
  SKOPE_SMTP_ADDR      SMTP submission server, host:port (465 = implicit TLS)
  SKOPE_SMTP_USER, SKOPE_SMTP_PASSWORD
  SKOPE_EMAIL_FROM, SKOPE_EMAIL_TO (comma-separated)
  SKOPE_NTFY_TOPIC     ntfy topic for urgent findings
  SKOPE_NTFY_URL       ntfy server (default https://ntfy.sh)
  SKOPE_NTFY_TOKEN     ntfy access token`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		adminToken := os.Getenv("SKOPE_ADMIN_TOKEN")
		if len(adminToken) < 32 {
			return errors.New("SKOPE_ADMIN_TOKEN must be set to a secret of at least 32 characters (try: openssl rand -hex 32)")
		}
		interval, err := time.ParseDuration(env("SKOPE_SYNC_INTERVAL", "1h"))
		if err != nil {
			return err
		}

		st, err := store.Open(env("SKOPE_DB", "skope.db"))
		if err != nil {
			return err
		}
		defer st.Close()

		alerts, err := alert.FromEnv()
		if err != nil {
			return err
		}
		if len(alerts.Channels()) == 0 {
			slog.Warn("no alert channels configured; findings will only be logged (set SKOPE_SMTP_ADDR and/or SKOPE_NTFY_TOPIC)")
		}

		srv := server.New(st, osvsync.New(st), adminToken, alerts)
		if eco := os.Getenv("SKOPE_ECOSYSTEMS"); eco != "" {
			if err := srv.SetEcosystems(strings.Split(eco, ",")); err != nil {
				return fmt.Errorf("SKOPE_ECOSYSTEMS: %w", err)
			}
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		httpSrv := &http.Server{Addr: env("SKOPE_LISTEN", "127.0.0.1:8080"), Handler: srv.Handler(),
			ReadHeaderTimeout: 10 * time.Second}
		go srv.Run(ctx, interval)
		go func() {
			<-ctx.Done()
			shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			httpSrv.Shutdown(shutdown)
		}()

		slog.Info("skope listening", "addr", httpSrv.Addr, "version", Version, "alerts", alerts.Channels())
		if err := httpSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	},
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
