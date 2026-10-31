# OSV is the advisory source, not NVD

We sync advisories from OSV.dev's per-ecosystem bulk exports rather than the NVD CVE feed. NVD identifies affected software by CPE strings (`cpe:2.3:a:vendor:product:…`), which map poorly and ambiguously onto registry package names like `phoenix_html` or `serde`. OSV states the ecosystem, package name and exact affected version ranges, and aggregates GitHub Security Advisories, RustSec, the Erlang Ecosystem Foundation's Hex advisories, PyPI, npm, Go and RubyGems advisories plus malicious-package reports. Matching becomes exact and cheap.

## Consequences

- The core concept is an **Advisory**, not a CVE. Many OSV advisories have only a GHSA, RUSTSEC or MAL identifier; a CVE ID is just one alias.
- Software that is not distributed through a supported package registry (OS packages, vendored C libraries) is out of scope. Superseded for Alpine and Debian packages in container images by ADR-0004.
- Each ecosystem needs its own version-ordering rules to evaluate OSV `ECOSYSTEM` ranges.
