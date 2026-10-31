# AGENTS.md

Guidance for AI coding agents working in this repository.

## What this project is

**Skope** watches the dependencies of the operator's projects. Each project's CI reports its inventory (a CycloneDX SBOM or a purl list); Skope syncs advisories from OSV.dev, matches them against every inventory, and alerts by email and ntfy when a finding opens. One Go binary, embedded SQLite.

Read `GLOSSARY.md` before naming anything — use its terms (Advisory, not CVE; Vulnerability for a group of aliased advisories; Report, not upload; Finding, not match). `docs/DESIGN.md` is the agreed design; `docs/adr/` records the hard-to-reverse choices.

## Repository layout

- `internal/pkgid/` — purl → OSV package identity, per-ecosystem name normalisation.
- `internal/osv/` — OSV advisory model, range evaluation, severity.
- `internal/report/` — decodes a report body (CycloneDX or purl list).
- `internal/store/` — SQLite schema (`schema.sql`) and queries; all writes go through `Store.Tx`.
- `internal/osvsync/` — downloads OSV exports (full archive first, then incremental).
- `internal/scan/` — matching and the finding lifecycle (opened, resolved, reactivated), one finding per vulnerability (alias group).
- `internal/server/` — HTTP API (report endpoint, admin API), the sync loop and housekeeping (ignore expiry, stale projects).
- `internal/alert/` — composes and delivers alerts: SMTP email for everything, ntfy push for urgent findings.
- `internal/api/` — JSON shapes shared by server, CLI client and CI.
- `internal/client/` — admin API client used by the CLI.
- `cmd/` — Cobra commands: `serve`, `project`, `token`, `finding`, `sync`, `version`.

## Build, test, run

```bash
go build ./...
go test ./...
go vet ./...
SKOPE_LIVE=Hex,crates.io go test ./internal/scan -run TestLiveOSV -v   # against real osv.dev
```

Keep code `gofmt`-clean. Tests sit next to the code (`*_test.go`); store-backed tests use a real SQLite file in `t.TempDir()`, not mocks.

## Conventions

- **Output streams:** command output meant for piping (a token, a table) goes to stdout; everything else to stderr. `skope project add x | gh secret set SKOPE_TOKEN` depends on it.
- **Secrets come from the environment, never flags** (`SKOPE_ADMIN_TOKEN`), so they stay out of shell history and `ps`.
- Schema changes are new entries in `migrations` (`internal/store/store.go`); never edit a shipped migration.
- Project tokens are stored only as SHA-256 hashes; never log or return them except at creation/rotation.
- An advisory Skope can't evaluate is logged and skipped, never allowed to fail a sync or a report.
