#!/usr/bin/env bash
# Generate an SBOM of a checkout with syft and report it to a skope server.
#
# Environment:
#   SKOPE_URL, SKOPE_TOKEN     server and project token (required)
#   SKOPE_PATH                 directory to scan (default .)
#   SKOPE_EXCLUDE              comma-separated syft exclude globs
#   SKOPE_FAIL_ON              fail when an open, unignored finding is at least
#                              this severe: low|medium|high|critical ("" = never)
#   SKOPE_COMMIT, SKOPE_REF, SKOPE_RUN_URL   CI context sent with the report
#   SYFT                       syft command (default syft)
#   GITHUB_OUTPUT, GITHUB_STEP_SUMMARY       set by GitHub Actions, optional
set -euo pipefail

: "${SKOPE_URL:?SKOPE_URL is required}"
: "${SKOPE_TOKEN:?SKOPE_TOKEN is required (the project token, from a secret)}"
path=${SKOPE_PATH:-.}
syft=${SYFT:-syft}

rank() {
	case "$1" in
	low) echo 1 ;;
	medium) echo 2 ;;
	high | unknown) echo 3 ;; # unrated findings count as high: silence is the worse failure
	critical) echo 4 ;;
	*) echo 0 ;;
	esac
}
threshold=0
if [ -n "${SKOPE_FAIL_ON:-}" ]; then
	threshold=$(rank "$SKOPE_FAIL_ON")
	if [ "$threshold" = 0 ] || [ "$SKOPE_FAIL_ON" = unknown ]; then
		echo "::error::fail-on must be one of low, medium, high, critical (got '$SKOPE_FAIL_ON')"
		exit 1
	fi
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

excludes=()
IFS=',' read -ra patterns <<<"${SKOPE_EXCLUDE:-}"
for p in "${patterns[@]}"; do
	p=$(echo "$p" | xargs)
	[ -n "$p" ] && excludes+=(--exclude "$p")
done

echo "Scanning $path with $("$syft" version -o json 2>/dev/null | jq -r '"syft " + .version' || echo syft)"
"$syft" scan "dir:$path" "${excludes[@]}" -o "cyclonedx-json=$work/sbom.json" -q

status=$(curl -sS --retry 3 --retry-all-errors -o "$work/result.json" -w '%{http_code}' \
	-X POST "${SKOPE_URL%/}/v1/reports" \
	-H "Authorization: Bearer $SKOPE_TOKEN" \
	-H "Content-Type: application/json" \
	-H "Skope-Commit: ${SKOPE_COMMIT:-}" \
	-H "Skope-Ref: ${SKOPE_REF:-}" \
	-H "Skope-Run-Url: ${SKOPE_RUN_URL:-}" \
	--data-binary "@$work/sbom.json")
if [ "$status" != 200 ]; then
	msg=$(jq -r '.error // empty' "$work/result.json" 2>/dev/null || true)
	echo "::error::skope rejected the report (HTTP $status): ${msg:-$(head -c 300 "$work/result.json")}"
	exit 1
fi

result="$work/result.json"
open=$(jq '[.findings[] | select(.ignored == null)] | length' "$result")
jq -r '"skope: \(.project): \(.packages) packages reported (\(.skipped) skipped), \(.findings | length) open findings"' "$result"
jq -r '.findings[] | "  \(.severity | ascii_upcase)  \(.vulnerability)  \(.ecosystem) \(.package) \(.versions)\(if .ignored then "  (ignored: \(.ignored.reason))" else "" end)\n      \(.summary // "")  \(.url)"' "$result"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
	{
		jq -r '"### skope: \(.project)\n\n\(.packages) packages reported, \(.findings | length) open findings.\n"' "$result"
		if [ "$(jq '.findings | length' "$result")" -gt 0 ]; then
			echo "| Severity | Vulnerability | Package | Versions | |"
			echo "|---|---|---|---|---|"
			jq -r '.findings[] | "| \(.severity) | [\(.vulnerability)](\(.url)) | \(.ecosystem) \(.package) | \(.versions) | \(if .ignored then "ignored" else "" end) |"' "$result"
		fi
	} >>"$GITHUB_STEP_SUMMARY"
fi
if [ -n "${GITHUB_OUTPUT:-}" ]; then
	echo "findings=$open" >>"$GITHUB_OUTPUT"
	echo "packages=$(jq .packages "$result")" >>"$GITHUB_OUTPUT"
fi

if [ "$threshold" -gt 0 ]; then
	failing=0
	while read -r sev; do
		[ "$(rank "$sev")" -ge "$threshold" ] && failing=$((failing + 1))
	done < <(jq -r '.findings[] | select(.ignored == null) | .severity' "$result")
	if [ "$failing" -gt 0 ]; then
		echo "::error::$failing open finding(s) at or above $SKOPE_FAIL_ON"
		exit 1
	fi
fi
