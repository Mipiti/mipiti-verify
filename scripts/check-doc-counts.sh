#!/usr/bin/env bash
# check-doc-counts.sh — fail if any tracked .md doc carries a stale count.
#
# Source of truth: scripts/canonical-counts.sh. Match form:
# <!--KEY-->N<!--/KEY-->. Same shape as parent repo's gate.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

source scripts/canonical-counts.sh

MODE="check"
if [ "${1:-}" = "--fix" ]; then
  MODE="fix"
fi

DOC_FILES=()
while IFS= read -r f; do DOC_FILES+=("$f"); done < <(
  git ls-files '*.md' 2>/dev/null || true
)

declare -A METRICS=(
  [ASSERTION_TYPE_COUNT]=assertion_type_count
  [PACKAGE_VERSION]=package_version
)

violations=0
fixed=0

for f in "${DOC_FILES[@]}"; do
  [ -f "$f" ] || continue
  for key in "${!METRICS[@]}"; do
    fn="${METRICS[$key]}"
    expected="$($fn)"
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      lineno="${line%%:*}"
      content="${line#*:}"
      actual="$(printf '%s' "$content" \
        | sed -nE "s|.*<!--${key}-->([^<]*)<!--/${key}-->.*|\1|p")"
      [ -z "$actual" ] && continue
      if [ "$actual" != "$expected" ]; then
        if [ "$MODE" = "fix" ]; then
          sed -i -E \
            "${lineno}s|<!--${key}-->[^<]*<!--/${key}-->|<!--${key}-->${expected}<!--/${key}-->|g" \
            "$f"
          fixed=$((fixed+1))
          echo "FIXED $f:$lineno  $key: $actual → $expected"
        else
          echo "::error file=$f,line=$lineno::Stale ${key}: marker carries '${actual}', canonical is '${expected}'"
          violations=$((violations+1))
        fi
      fi
    done < <(grep -nE "<!--${key}-->[^<]*<!--/${key}-->" "$f" 2>/dev/null || true)
  done
done

if [ "$MODE" = "fix" ]; then
  echo ""
  echo "Fixed $fixed marker(s)."
  exit 0
fi

if [ "$violations" -gt 0 ]; then
  echo ""
  echo "$violations stale doc count marker(s). Run: bash scripts/check-doc-counts.sh --fix"
  exit 1
fi

echo "Doc counts OK ($(printf '%s ' "${!METRICS[@]}"))."
exit 0
