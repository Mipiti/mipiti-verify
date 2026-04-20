#!/bin/bash
set -e

ARGS="run"

if [ -n "$INPUT_MODEL_ID" ]; then
  ARGS="$ARGS $INPUT_MODEL_ID"
elif [ "$INPUT_ALL" = "true" ]; then
  ARGS="$ARGS --all"
else
  echo "::error::Provide model-id or set all: true"
  exit 1
fi

ARGS="$ARGS --project-root $INPUT_PROJECT_ROOT"
ARGS="$ARGS --output github"

if [ -n "$INPUT_TIER2_PROVIDER" ]; then
  ARGS="$ARGS --tier2-provider $INPUT_TIER2_PROVIDER"
fi

if [ -n "$INPUT_TIER2_MODEL" ]; then
  ARGS="$ARGS --tier2-model $INPUT_TIER2_MODEL"
fi

if [ "$INPUT_REVERIFY" = "false" ]; then
  ARGS="$ARGS --no-reverify"
fi

if [ "$INPUT_DRY_RUN" = "true" ]; then
  ARGS="$ARGS --dry-run"
fi

if [ -n "$INPUT_CONCURRENCY" ] && [ "$INPUT_CONCURRENCY" != "1" ]; then
  ARGS="$ARGS --concurrency $INPUT_CONCURRENCY"
fi

if [ -n "$INPUT_SIGSTORE_TUF_URL" ]; then
  ARGS="$ARGS --sigstore-tuf-url $INPUT_SIGSTORE_TUF_URL"
fi

if [ -n "$INPUT_SIGSTORE_TRUST_CONFIG" ]; then
  ARGS="$ARGS --sigstore-trust-config $INPUT_SIGSTORE_TRUST_CONFIG"
fi

exec mipiti-verify $ARGS
