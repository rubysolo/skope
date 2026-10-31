# skope

A small, self-hosted dependency vulnerability watcher.

Register your projects, give each one a token, and have CI report its dependencies on every push to the default branch. Skope syncs advisories from [OSV.dev](https://osv.dev) for Hex, crates.io, RubyGems, npm, Go and PyPI, matches them against every project, and alerts you by email and [ntfy](https://ntfy.sh) when something you ship is affected — including when a new advisory lands for a dependency you added months ago.

**Status:** early development, not yet battle-tested. See [`docs/DESIGN.md`](docs/DESIGN.md).

## Run the server

With Docker Compose ([`deploy/compose.yml`](deploy/compose.yml)), behind a reverse proxy that terminates TLS:

```sh
cp deploy/skope.env.example deploy/skope.env   # set SKOPE_ADMIN_TOKEN (openssl rand -hex 32), alerts, backups
docker compose -f deploy/compose.yml up -d
```

The image (`ghcr.io/rubysolo/skope:v0`) bundles [Litestream](https://litestream.io): set `LITESTREAM_REPLICA_URL` and the database streams continuously to S3-compatible storage, and an empty volume is restored from it on start.

Or run the binary directly (`go install github.com/rubysolo/skope@latest`, or a [release](https://github.com/rubysolo/skope/releases)):

```sh
export SKOPE_ADMIN_TOKEN=$(openssl rand -hex 32)   # keep it; the CLI needs it too
skope serve                                        # see `skope serve --help` for all settings
```

Alerts go to email (`SKOPE_SMTP_ADDR`, `SKOPE_EMAIL_FROM`, `SKOPE_EMAIL_TO`, …) and/or an [ntfy](https://ntfy.sh) topic (`SKOPE_NTFY_TOPIC`, `SKOPE_NTFY_TOKEN`). Email gets every new and resolved finding; ntfy only urgent ones (malicious packages, high/critical, unrated).

## Watch a project

From anywhere with `SKOPE_URL` and `SKOPE_ADMIN_TOKEN` set:

```sh
skope project add my-app | gh secret set SKOPE_TOKEN --repo me/my-app
gh variable set SKOPE_URL --repo me/my-app --body "$SKOPE_URL"
```

Then add `.github/workflows/skope.yml`:

```yaml
name: skope
on:
  push:
    branches: [main]
  schedule:
    - cron: "17 6 * * 2"
  workflow_dispatch:
permissions:
  contents: read
jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: rubysolo/skope/report@v0
        with:
          url: ${{ vars.SKOPE_URL }}
          token: ${{ secrets.SKOPE_TOKEN }}
```

The action runs [syft](https://github.com/anchore/syft) over the checkout's lockfiles, reports to skope, and prints the project's open findings. Its inputs (`path`, `fail-on`, `exclude`, `any-branch`) are documented in [`report/action.yml`](report/action.yml).

### Let a coding agent do it

The [`skope-ci` skill](skills/skope-ci/SKILL.md) walks an agent (Claude Code, Codex, Cursor, …) through all of the above for a repo, including monorepos. In Claude Code:

```
/plugin marketplace add rubysolo/skope
/plugin install skope@skope
```

or with the skills CLI: `npx skills add rubysolo/skope`.

## Manage findings

```sh
skope finding list [--project my-app] [--all]
skope finding ignore 42 --reason "code path not reachable" --until 2027-01-01
skope project archive old-app      # stop watching; revokes its token
```
