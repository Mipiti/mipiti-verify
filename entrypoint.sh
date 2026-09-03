#!/bin/bash
set -e

# In a GitHub Actions container action, the runner overrides HOME to
# /github/home, owned by the runner uid — which the non-root `verifier` user
# can't write to. That breaks the Sigstore TUF cache (~/.cache), so signing
# fails and attestations are silently dropped. Point HOME back at our own
# writable home so the cache (and any HOME-based state) works.
export HOME=/home/verifier

# A test result becomes evidence by being recorded from the report your own
# test step produced. Done here so using the action is a single step: the
# alternative would be installing the CLI separately just to run one command.
# This reads the report; it does not run tests.
if [ -n "$INPUT_JUNIT_REPORT" ]; then
  for report in $INPUT_JUNIT_REPORT; do
    # Accept a path relative to project-root (the natural way to write it) or
    # one that already resolves as given. A plain `[ -f x ] && y=z` would abort
    # the script under `set -e` whenever the first location misses, so the
    # branch is explicit.
    if [ -f "$INPUT_PROJECT_ROOT/$report" ]; then
      resolved="$INPUT_PROJECT_ROOT/$report"
    elif [ -f "$report" ]; then
      resolved="$report"
    else
      echo "::error::junit-report '$report' not found. Point it at the report your test step wrote, relative to project-root."
      exit 1
    fi
    ATTEST_ARGS=("attest-tests" "--junit" "$resolved" "--project-root" "$INPUT_PROJECT_ROOT")
    if [ -n "$INPUT_ATTESTATION_SIGNING_KEY" ]; then
      ATTEST_ARGS+=("--signing-key" "$INPUT_ATTESTATION_SIGNING_KEY")
    fi
    if [ -n "$INPUT_SIGSTORE_TUF_URL" ]; then
      ATTEST_ARGS+=("--sigstore-tuf-url" "$INPUT_SIGSTORE_TUF_URL")
    fi
    if [ -n "$INPUT_SIGSTORE_TRUST_CONFIG" ]; then
      ATTEST_ARGS+=("--sigstore-trust-config" "$INPUT_SIGSTORE_TRUST_CONFIG")
    fi
    mipiti-verify "${ATTEST_ARGS[@]}"
  done
fi

ARGS=("run")

if [ -n "$INPUT_MODEL_ID" ]; then
  ARGS+=("$INPUT_MODEL_ID")
elif [ "$INPUT_ALL" = "true" ]; then
  ARGS+=("--all")
else
  echo "::error::Provide model-id or set all: true"
  exit 1
fi

ARGS+=("--project-root" "$INPUT_PROJECT_ROOT")
ARGS+=("--output" "github")

if [ -n "$INPUT_TIER2_PROVIDER" ]; then
  ARGS+=("--tier2-provider" "$INPUT_TIER2_PROVIDER")
fi

if [ -n "$INPUT_TIER2_MODEL" ]; then
  ARGS+=("--tier2-model" "$INPUT_TIER2_MODEL")
fi

if [ "$INPUT_REVERIFY" = "false" ]; then
  ARGS+=("--no-reverify")
fi

if [ "$INPUT_DRY_RUN" = "true" ]; then
  ARGS+=("--dry-run")
fi

if [ -n "$INPUT_CONCURRENCY" ] && [ "$INPUT_CONCURRENCY" != "1" ]; then
  ARGS+=("--concurrency" "$INPUT_CONCURRENCY")
fi

if [ -n "$INPUT_SIGSTORE_TUF_URL" ]; then
  ARGS+=("--sigstore-tuf-url" "$INPUT_SIGSTORE_TUF_URL")
fi

if [ -n "$INPUT_SIGSTORE_TRUST_CONFIG" ]; then
  ARGS+=("--sigstore-trust-config" "$INPUT_SIGSTORE_TRUST_CONFIG")
fi

if [ -n "$INPUT_WORKSPACE_SIGNING_KEY" ]; then
  ARGS+=("--workspace-signing-key" "$INPUT_WORKSPACE_SIGNING_KEY")
fi

if [ -n "$INPUT_SIGNING_PREFER" ] && [ "$INPUT_SIGNING_PREFER" != "sigstore" ]; then
  ARGS+=("--signing-prefer" "$INPUT_SIGNING_PREFER")
fi

if [ "$INPUT_REQUIRE_ATTESTATION" = "true" ]; then
  ARGS+=("--require-attestation")
fi

exec mipiti-verify "${ARGS[@]}"
