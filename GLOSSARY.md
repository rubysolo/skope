# Skope

Skope watches the dependencies of the operator's software projects and raises alerts when a published vulnerability affects one of them.

## Language

### Projects and dependencies

**Operator**:
The single person who runs Skope, registers projects, and receives alerts.
_Avoid_: User, admin, owner

**Project**:
A piece of software registered with Skope whose dependencies are watched. A monorepo with independent apps is several projects.
_Avoid_: Repo, app, service

**Project Token**:
The secret credential a project's CI uses to report its inventory to Skope.
_Avoid_: API key, secret

**Inventory**:
The complete set of packages a project depends on, as of its most recent report. Each report replaces the previous inventory entirely.
_Avoid_: Dependency list, SBOM, manifest, snapshot

**Report**:
A single submission of a project's inventory from CI.
_Avoid_: Upload, post, scan

**Package**:
A specific name and version within an ecosystem, identified by a purl (e.g. `pkg:hex/phoenix@1.7.14`).
_Avoid_: Dependency, component, library

**Ecosystem**:
A package registry with its own naming and version-ordering rules (Hex, crates.io, RubyGems, npm, Go modules, PyPI).
_Avoid_: Language, platform

### Vulnerabilities

**Advisory**:
A published record describing a vulnerability and the package versions it affects. A CVE ID is one possible alias of an advisory, not the advisory itself.
_Avoid_: CVE, vuln

**Vulnerability**:
A single flaw, as identified by the group of advisories that name each other (or a shared CVE) as aliases. Several databases often publish the same vulnerability; Skope counts it once.
_Avoid_: CVE, advisory group, issue

**Malicious Package Advisory**:
An advisory stating that a package release was published with malicious intent, as opposed to containing an accidental flaw. Always treated as critical.
_Avoid_: Malware, typosquat

**Sync**:
A periodic refresh of Skope's advisory data from the upstream source.
_Avoid_: Download, import, fetch

### Findings and alerts

**Finding**:
The fact that a project's inventory contains a version of a package affected by a vulnerability. Identified by project, vulnerability and package name; the version is not part of its identity.
_Avoid_: Match, hit, issue, vulnerability

**Resolved**:
The state of a finding whose project no longer contains an affected version, or whose advisories were all withdrawn. A finding that recurs after resolution is a new finding.
_Avoid_: Closed, fixed

**Ignored**:
The state of a finding the operator has muted, with a reason and an optional expiry. A change to any of its vulnerability's advisories makes it active again.
_Avoid_: Suppressed, snoozed, acknowledged

**Alert**:
A single batched notification to the operator about new or resolved findings arising from one sync or one report.
_Avoid_: Notification, message

**Stale Project**:
A project that has sent no report within its staleness threshold, so its inventory can no longer be trusted.
_Avoid_: Inactive, dead

### Access

**Admin Token**:
The operator's credential for managing projects, project tokens and findings, locally or remotely.
_Avoid_: Master key, root token
