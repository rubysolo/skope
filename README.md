# skope

A small, self-hosted dependency vulnerability watcher.

Register your projects, give each one a token, and have CI report its dependencies on every push to the default branch. Skope syncs advisories from [OSV.dev](https://osv.dev) for Hex, crates.io, RubyGems, npm, Go and PyPI, matches them against every project, and alerts you by email and [ntfy](https://ntfy.sh) when something you ship is affected — including when a new advisory lands for a dependency you added months ago.

**Status:** early development. The server, CLI, matching and alerts work; the CI action, agent skill and release packaging are in progress. See [`docs/DESIGN.md`](docs/DESIGN.md).
