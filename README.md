# mipiti-verify

Turnkey CI verification for [Mipiti](https://mipiti.io) threat model assertions. Security controls that never drift.

## Install

```bash
pip install mipiti-verify[all]
```

## Usage

```bash
# Verify all models in the workspace (recommended)
mipiti-verify run --all \
  --api-key $MIPITI_API_KEY \
  --tier2-provider openai \
  --tier2-model gpt-4o-mini \
  --project-root .

# Verify a single model
mipiti-verify run <model_id> \
  --api-key $MIPITI_API_KEY \
  --tier2-provider openai \
  --project-root .

# List pending assertions
mipiti-verify list <model_id>

# Show verification report
mipiti-verify report <model_id>
```

API keys are workspace-scoped — `--all` verifies every model accessible by the key.

### API key scopes

| Prefix | Scope | Use |
|--------|-------|-----|
| `mk_` | Developer | Local development. Runs assertions but does not submit results. |
| `mv_` | Verifier | CI pipelines. Runs assertions and submits results to update verification status. |

Developer keys skip result submission automatically — no `--dry-run` needed.

### Key flags

| Flag | Default | Description |
|------|---------|-------------|
| `--reverify / --no-reverify` | `--reverify` | Re-verify all assertions, not just pending. Catches regressions. |
| `--changed-files FILE` | none | Only verify assertions referencing files listed in FILE. Use `git diff --name-only HEAD~1 > changed.txt`. |
| `--concurrency N` | 1 | Max concurrent Tier 2 LLM calls. Tune based on API rate limits. |
| `--dry-run` | off | Run verifiers but don't submit results. |
| `--output github` | `text` | Emit GitHub Actions annotations (errors, warnings, notices). |
| `--tier2-provider` | none | AI provider: `openai`, `anthropic`, or `ollama`. Omit for Tier 1 only. |
| `--tier2-model` | `gpt-4o` | Model name (e.g., `gpt-4o-mini`, `claude-sonnet-4-5-20250514`). |

## GitHub Action

```yaml
- uses: Mipiti/mipiti-verify@v0.10.0
  with:
    api-key: ${{ secrets.MIPITI_API_KEY }}
    all: true
    tier2-provider: openai
    tier2-model: gpt-4o-mini
    tier2-api-key: ${{ secrets.OPENAI_API_KEY }}
```

All assertions are re-verified by default. Use `reverify: false` to only check new assertions (e.g., to reduce Tier 2 API costs on PRs). Omitting `tier2-provider` runs Tier 1 only — controls won't reach "verified" status without Tier 2.

## Development

```bash
git clone https://github.com/Mipiti/mipiti-verify.git
cd mipiti-verify
pip install -e ".[dev]"
python -m pytest -v
```

## License

Proprietary. Copyright (c) 2026 Mipiti, LLC. All rights reserved. See [LICENSE](LICENSE) for details.
