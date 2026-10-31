---
name: skope-ci
description: Connect a repository to a skope server so its CI reports dependencies for vulnerability alerts. Use when the user wants a project watched by skope, asks to "add skope", "register this repo with skope", "report dependencies to skope", set up dependency vulnerability alerts with their skope server, or rotate a project's skope token.
---

# Connect a repository to skope

[skope](https://github.com/rubysolo/skope) watches the operator's projects for published vulnerabilities. Each project's CI sends a **report**, an SBOM of its lockfiles, to the skope server. The server matches every **inventory** against OSV advisories and alerts the operator when a **finding** opens. Covered ecosystems: Hex, crates.io, RubyGems, npm, Go modules, PyPI.

Your job is to register the repository as a skope **project**, store its **project token** as a CI secret, and add a workflow that reports on every push to the default branch. If the repo builds container images, you'll also report each built image, so the OS packages inside it (Alpine, Debian) are watched as well. Three things matter most:
- **Never print, log or write a token anywhere but `gh secret set`.**
- **Only the default branch reports.** Each report replaces the project's whole inventory, so a feature branch must not send one.
- **Don't fix vulnerabilities you see** unless the user asks. Report them.

## 0. Preconditions

Check these before changing anything. Stop and tell the user about any that fail.

```bash
skope version                                           # the CLI
test -n "$SKOPE_URL" && test -n "$SKOPE_ADMIN_TOKEN" && echo configured
gh auth status                                          # gh can set secrets on the repo
gh repo view --json nameWithOwner,defaultBranchRef      # the repo and its default branch
```

- **No `skope`:** install it with `go install github.com/rubysolo/skope@latest`, or a release binary from https://github.com/rubysolo/skope/releases.
- **`SKOPE_URL` / `SKOPE_ADMIN_TOKEN` unset:** ask the user to export them in their shell. Don't ask them to paste the admin token into the chat.
- **The repo isn't on GitHub:** this skill covers GitHub Actions only. Say so and stop.

## 1. Find the lockfiles

skope only knows exact versions from **committed lockfiles**. A manifest without a lock (a `package.json` with no lockfile) reports nothing useful.

| Ecosystem | Lockfile syft reads |
|---|---|
| Hex (Elixir/Erlang) | `mix.lock`, `rebar.lock` |
| crates.io | `Cargo.lock` |
| RubyGems | `Gemfile.lock` |
| npm | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| Go | `go.mod` (+ `go.sum`) |
| PyPI | `poetry.lock`, `uv.lock`, `Pipfile.lock`, pinned `requirements*.txt` |

```bash
git ls-files | grep -E '(^|/)(mix\.lock|rebar\.lock|Cargo\.lock|Gemfile\.lock|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|go\.mod|poetry\.lock|uv\.lock|Pipfile\.lock|requirements[^/]*\.txt)$'
```

If an ecosystem's manifest is present but its lockfile isn't committed, tell the user. Their call; don't commit one on their behalf.

## 2. Decide the project(s)

- **One deployable app per repo (the usual case):** one project, named after the repo (`gh repo view --json name -q .name`).
- **Monorepo with independently deployed apps:** one project per app, named `<repo>-<app>`, each scanning its own directory with its own secret (`SKOPE_TOKEN_<APP>`, upper snake case). Ask the user if it's unclear which directories are separate apps.

Project names use letters, digits, `-`, `_` and `.`.

## 3. Register the project and store its token

The token is printed once, on stdout only. Pipe it straight into the secret:

```bash
set -o pipefail
skope project add NAME | gh secret set SKOPE_TOKEN --repo OWNER/REPO
gh variable set SKOPE_URL --repo OWNER/REPO --body "$SKOPE_URL"
```

- **`project "NAME" already exists (409)`:** the project was registered before, and its token can't be recovered. Ask the user before rotating, because the old token stops working everywhere. Then run `skope token rotate NAME | gh secret set SKOPE_TOKEN --repo OWNER/REPO`.
- **Any other failure:** check `gh secret list --repo OWNER/REPO` before retrying, so you don't leave a project registered with no secret.

## 4. Add the workflow

Create `.github/workflows/skope.yml`. Don't fold it into existing CI workflows: it has different triggers and needs no build. Use the repo's real default branch. Pick a random minute and weekday for the cron, so many repos don't all report at the same moment.

```yaml
name: skope

on:
  push:
    branches: [main]          # the default branch
  schedule:
    - cron: "17 6 * * 2"      # weekly, so a quiet repo still checks in
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

**Monorepo:** use one job per app, each with `path: apps/<app>` and `token: ${{ secrets.SKOPE_TOKEN_<APP> }}`, and add `paths:` filters to the push trigger if the user wants them.

**Optional inputs**, only if the user asks:
- `fail-on: high` fails the job when an unignored high or critical finding is open. The default never fails; alerts come by email and ntfy anyway.
- `exclude:` replaces the default skip list (build output and installed-dependency directories: `_build`, `deps`, `target`, `node_modules`, `vendor`, `dist`, `build`). Change it only if the user's lockfiles live in one of those directories.

## 4b. Report container images (if the repo builds any)

Look for image builds in the existing workflows: `docker build`, `docker/build-push-action` and the like. An image is a separate **source** for the same project, so its report never replaces the lockfile report. Covered base images: **Alpine and Debian** (Ubuntu and others are skipped silently).

Add one step to the job that builds the image, **after** the build or push, in a step that only runs on the default branch:

```yaml
      - uses: rubysolo/skope/report@v0
        if: github.ref == format('refs/heads/{0}', github.event.repository.default_branch)
        with:
          url: ${{ vars.SKOPE_URL }}
          token: ${{ secrets.SKOPE_TOKEN }}
          image: ghcr.io/OWNER/APP:${{ github.sha }}    # the exact tag that job just built or pushed
```

- **A build with `docker/build-push-action` and `push: true` but no `load: true`:** the image isn't in the runner's Docker daemon, and syft pulls it from the registry instead. That needs the job's registry login to still be in effect, which it is when the step runs later in the same job.
- **Several images (web, worker):** use one step per image. Each image is its own source.
- **Don't** add image scanning to `skope.yml`. It has nothing to build, and the hourly sync keeps matching the last reported image against new advisories anyway.

Distro advisories with **no fix yet** are tracked quietly: they appear in `skope finding list` as "no fix yet" and only alert once a fixed package is published. Expect the first image report to show more findings than alerts.

## 5. Ship it and verify

1. Commit the workflow the way the repo usually takes changes, normally a branch and PR. The workflow doesn't report from the PR; that's expected.
2. After it reaches the default branch, trigger it and watch it:

   ```bash
   gh workflow run skope.yml --repo OWNER/REPO
   gh run watch --repo OWNER/REPO "$(gh run list --repo OWNER/REPO --workflow skope.yml --limit 1 --json databaseId -q '.[0].databaseId')"
   ```

3. Confirm the server received it:

   ```bash
   skope project list                    # NAME shows a LAST REPORT time
   skope finding list --project NAME     # what it found
   ```

4. Tell the user what was set up, plus the open findings by severity. If the run reported 0 packages, the lockfiles weren't found: check step 1 and the `exclude` list.

## Don't

- Echo, log or commit a token, or pass it on a command line other than the pipe into `gh secret set`.
- Report from pull requests or feature branches (don't set `any-branch: true`).
- Add `fail-on` unless the user asked for a gate.
- Archive or delete skope projects. If the user wants a repo un-watched, that's `skope project archive NAME`, and you should confirm it with them first.
