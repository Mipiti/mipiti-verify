#!/usr/bin/env bash
# canonical-counts.sh — single source of truth for numeric facts cited
# in this repo's docs.
#
# Same shape as the parent repo's scripts/canonical-counts.sh, scoped
# to mipiti-verify's own truths.
#
# Usage:
#   source scripts/canonical-counts.sh
#   echo "Assertion types: $(assertion_type_count)"

set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Assertion-type count: number of @register("...") decorators across
# all verifier modules. Each registration declares a distinct typed
# assertion mipiti-verify can check (function_exists, pattern_matches,
# etc.).
assertion_type_count() {
  grep -rn '^@register' "$REPO_ROOT/src/mipiti_verify/verifiers/" | wc -l | tr -d ' '
}

# Package version (PyPI release tag).
package_version() {
  grep -E '^version[[:space:]]*=' "$REPO_ROOT/pyproject.toml" \
    | head -1 \
    | sed -E 's/.*"([^"]+)".*/\1/'
}

emit_all_counts() {
  cat <<EOF
assertion_type_count=$(assertion_type_count)
package_version="$(package_version)"
EOF
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  emit_all_counts
fi
