# Container images: Alpine and Debian OS packages, not Ubuntu

Supersedes the "out of scope" consequence of ADR-0001 for OS packages. CI can now report a built container image as its own **source**. Skope syncs OSV's Alpine and Debian advisories and matches the image's OS packages against them. Ubuntu is left out: its export is 769 MB (mostly per-advisory lists of binary package names), and none of the operator's images use it (as of 2026-10-30 nearly all are Alpine, with Debian in build stages and one legacy app).

## Consequences

- Distro advisories are per release (`Alpine:v3.24`, `Debian:12`), so an OS package's ecosystem includes its release, taken from syft's `distro=` qualifier. Language ecosystems still ignore OSV's `:suffix`.
- Distro advisories name **source** packages and compare **source** versions. Skope uses syft's `upstream=` qualifier (name, and version when given) rather than the binary package, which can differ (`libssl3` from `openssl`; `bash 5.2.15-2+b13` built from source `5.2.15-2`).
- Debian publishes many advisories with no fix. These open findings in the **unfixed** state, which don't alert until a fix appears. Debian's urgency is the fallback severity, and only high/critical OS-package findings push to the phone.
