# Skope design

Agreed 2026-10-30. Vocabulary is defined in `GLOSSARY.md`; the hard-to-reverse choices are in `docs/adr/`.

## Shape

- One Go binary, `skope`: `skope serve` runs the server; every other subcommand is a client of the admin API (`SKOPE_URL` + `SKOPE_ADMIN_TOKEN`).
- Embedded SQLite (pure Go). Litestream in the container entrypoint replicates it to S3-compatible storage; the binary knows nothing about backups.
- Plain HTTP on a loopback port; TLS is the reverse proxy's job.
- Single operator, no user accounts, no web UI in v1.

## Advisories

- Source: OSV bulk exports, one zip per ecosystem — Hex, crates.io, RubyGems, npm, Go, PyPI, Alpine, Debian (ADR-0004).
- Distro ecosystems carry their release (`Alpine:v3.24`, `Debian:12`); distro advisories match by source package name and source version (syft's `upstream=`). Distro entries are stored without their enumerated `versions` lists, which their ranges already decide (verified over 7.3M versions).
- An advisory's `upstream` ids (distro advisories put their CVE there) count as aliases when grouping vulnerabilities.
- Sync runs hourly. The first sync for an ecosystem downloads `all.zip`; later syncs read `modified_id.csv` and fetch only advisories modified since the last sync.
- `ECOSYSTEM` and `SEMVER` ranges are evaluated with per-ecosystem version ordering; `GIT` ranges are ignored. Explicit `versions` lists are honoured.
- Malicious Package Advisories (`MAL-*`) are included and always critical.
- Severity: from the CVSS vector when present, else the ecosystem-specific label, else unknown.

## Reports

- `POST /v1/reports` with `Authorization: Bearer <project token>`.
- Body: a CycloneDX JSON SBOM, or `{"packages": ["pkg:hex/phoenix@1.7.14", …]}`. Optional metadata: commit SHA, ref, CI run URL.
- A report has a source (`Skope-Source` header): `repo` (default) or `image:<name>`, tag and digest dropped. It replaces only that source's part of the inventory; matching always covers every source. Only default-branch builds report.
- The response lists the project's open findings.
- Report log (time, commit, ref, run URL, package count) is kept 90 days.

## Findings

- Identity: (project, vulnerability, package name). The version is an attribute, updated in place.
- A vulnerability is the connected group of advisories linked by aliases (EEF-CVE-… ↔ GHSA-… ↔ CVE-…). Its key is the smallest CVE ID in the group, or the smallest advisory ID when there is no CVE (other aliases, like Bitnami's BIT-…, never become the key). When a new advisory merges two groups, open findings are re-keyed in place, not resolved and reopened. One finding per vulnerability: severity is the highest among its matching advisories, and ignoring it ignores all of them. Added 2026-10-30 after a real Hex repo showed 23 of 60 findings were alias pairs.
- Matching runs after every sync (changed advisories × all inventories) and after every report (that inventory × all advisories).
- Resolved when no affected version remains or every advisory is withdrawn; recurrence is a new finding.
- Ignored with a reason and optional expiry; reactivated when any of its advisories changes.
- Unfixed (no matching advisory names a fixed version) findings are tracked but quiet: no alert on open, reactivation or resolution, until a fix appears ("fix available"). Malicious packages alert regardless. Unfixed findings don't count toward the action's `findings` output or `fail-on`.
- Each finding records the report that introduced it.

## Alerts

- One batched alert per sync run or report, grouped by vulnerability.
- Email (SMTP): every new and resolved finding.
- ntfy (publish to a topic, token auth): new findings that are high/critical, unknown severity, or malicious. OS-package findings push only when high/critical (Debian's urgency is the fallback severity). Malicious → priority 5, otherwise 4.
- Stale project: alert after 30 days without a report (configurable per project), then weekly.

## Operator commands

- `skope project add|list|archive|delete`, `skope token rotate <project>`
- `skope finding list|ignore|unignore`
- `skope sync` (trigger now)

Project tokens are `skope_`-prefixed random strings, stored as SHA-256 hashes; one active token per project. Archive revokes the token, stops matching and staleness checks, and resolves open findings silently.

## CI integration

- Composite action `rubysolo/skope/report@v0` (a floating major tag that moves with each release, matching the binary's major version): runs syft on the checkout, skipping build output and installed-dependency directories, posts the report, prints findings, optional `fail-on`. Refuses to report from non-default branches unless `any-branch: true`.
- Triggered on push to the default branch, weekly `schedule:`, and `workflow_dispatch`.
- Agent skill `skills/skope-ci/SKILL.md`: `skope project add` → `gh secret set SKOPE_TOKEN` → add the workflow. The token is never echoed.

## Release and hosting

- GoReleaser: darwin/linux × amd64/arm64 binaries and a multi-arch GHCR image, from tags. `go install` works too.
- Hosted on the operator's Linode via Docker Compose, after the OrderedPath Phoenix migration; hostname TBD. Until then, built and tested locally.
