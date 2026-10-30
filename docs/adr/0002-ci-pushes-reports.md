# CI pushes reports instead of Skope reading a forge's dependency graph

Each project's CI generates an inventory (a CycloneDX SBOM via syft, or a bare purl list) and pushes it to Skope with a per-project token. We considered relying on GitHub's dependency graph and Dependabot alerts instead, which are free and already enabled, but on 2026-10-30 GitHub's dependency graph listed no Hex packages for an Elixir repo with a committed `mix.lock`, and Elixir is the operator's largest ecosystem. Pushing from CI makes ecosystem coverage our choice (whatever syft reads), keeps Skope independent of any one forge, and needs no forge API credentials.

## Consequences

- An inventory is only as fresh as the project's last report, so Skope must detect stale projects.
- Every project needs a CI change; the `skope-ci` agent skill and the composite action exist to make that one step.
- Skope never parses lockfiles itself; it accepts SBOMs and purls only.
