#!/bin/bash
set -euo pipefail

# In a GitHub Actions container action, the runner overrides HOME to
# /github/home, owned by the runner uid — which the non-root `verifier` user
# can't write to. That breaks the Sigstore TUF cache (~/.cache), so signing
# fails and attestations are silently dropped. Point HOME back at our own
# writable home so the cache (and any HOME-based state) works.
export HOME=/home/verifier

ARGS=("run")

if [ -n "$INPUT_MODEL_ID" ]; then
  # Positional argument; appended behind "--" once every option is in
  # place, so the id is passed as an operand whatever it starts with.
  MODEL_ID="$INPUT_MODEL_ID"
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

# The provider key is handed only to the SDK of the provider selected:
# each SDK reads its own variable, and the one for a provider that is
# not in use has no reader in this process.
if [ -n "$INPUT_TIER2_API_KEY" ]; then
  case "$(printf '%s' "$INPUT_TIER2_PROVIDER" | tr '[:upper:]' '[:lower:]')" in
    openai)    export OPENAI_API_KEY="$INPUT_TIER2_API_KEY" ;;
    anthropic) export ANTHROPIC_API_KEY="$INPUT_TIER2_API_KEY" ;;
  esac
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
elif [ "$INPUT_DRY_RUN" != "true" ] \
  && [ -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] \
  && [ -z "$INPUT_WORKSPACE_SIGNING_KEY" ] \
  && [ -z "${MIPITI_WORKSPACE_SIGNING_KEY:-}" ] \
  && [ -z "${MIPITI_CUSTOMER_SIGNING_KEY:-}" ]; then
  # No signer can be reached from this job: the runner exposes no OIDC
  # token (the job lacks `id-token: write`) and no signing key is
  # configured. The run still submits, unsigned, as it always has; the
  # annotation makes that visible in the job summary instead of only in
  # verbose output.
  echo "::warning title=Unsigned submission::No attestation signer is available (no OIDC token — grant 'id-token: write' — and no workspace-signing-key), so results are submitted unsigned. Set 'require-attestation: true' to fail the run instead."
fi

if [ -n "${MODEL_ID:-}" ]; then
  ARGS+=("--" "$MODEL_ID")
fi

exec mipiti-verify "${ARGS[@]}"
