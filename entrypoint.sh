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

if [ "$INPUT_REVERIFY" = "true" ]; then
  ARGS="$ARGS --reverify"
fi

if [ "$INPUT_DRY_RUN" = "true" ]; then
  ARGS="$ARGS --dry-run"
fi

if [ -n "$INPUT_CONCURRENCY" ] && [ "$INPUT_CONCURRENCY" != "1" ]; then
  ARGS="$ARGS --concurrency $INPUT_CONCURRENCY"
fi

exec mipiti-verify $ARGS
