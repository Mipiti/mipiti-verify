# mipiti-verify

Turnkey CI verification for [Mipiti](https://mipiti.io) threat model assertions. Security controls that never drift.

## Install

```bash
pip install mipiti-verify[all]      # OpenAI + Anthropic support
pip install mipiti-verify[openai]   # OpenAI only
pip install mipiti-verify[anthropic] # Anthropic only
pip install mipiti-verify           # Tier 1 only (no AI provider)
```

## Commands

### `run` — Verify assertions against a model

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
```

API keys are workspace-scoped — `--all` verifies every model accessible by the key.

### `verify` — Check a single assertion locally

```bash
mipiti-verify verify function_exists -p file=app/auth.py -p name=verify_token
mipiti-verify verify pattern_matches -p file=nginx.conf -p pattern="Strict-Transport-Security"
mipiti-verify verify dependency_exists -p manifest=requirements.txt -p package=bcrypt
mipiti-verify verify import_present -p file=app/main.py -p module=fastapi
```

No API key needed — runs Tier 1 locally against your codebase.

### `check` — Verify assertions from a JSON file

```bash
mipiti-verify check assertions.json --project-root .
```

Offline batch verification from a JSON file. No API key needed.

### `list` — Show pending assertions

```bash
mipiti-verify list <model_id> --api-key $MIPITI_API_KEY
```

### `report` — Show verification results

```bash
mipiti-verify report <model_id> --api-key $MIPITI_API_KEY
```

Shows Tier 1/2 pass/fail counts, control verification status, drift detection, and sufficiency status.

### `audit` — Verify signed reports

```bash
mipiti-verify audit report.html
mipiti-verify audit audit-package.json
```

Independently verifies ECDSA document signatures on exported HTML reports and JSON audit packages. Validates OIDC provenance, content integrity, and per-assertion reasoning.

## API Key Scopes

| Prefix | Scope | Use |
|--------|-------|-----|
| `mk_` | Developer | Local development. Runs assertions but does not submit results. |
| `mv_` | Verifier | CI pipelines. Runs assertions and submits results to update verification status. |

Developer keys skip result submission automatically — no `--dry-run` needed.

## Key Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--reverify / --no-reverify` | `--reverify` | Re-verify all assertions, not just pending. Catches regressions. |
| `--changed-files FILE` | none | Only verify assertions referencing listed files. Use `git diff --name-only HEAD~1 > changed.txt`. |
| `--component ID` | none | Only verify assertions for controls scoped to this component. Use when a model spans multiple repos. |
| `--concurrency N` | 1 | Max concurrent Tier 2 LLM calls. |
| `--dry-run` | off | Run verifiers but don't submit results. |
| `--output` | `text` | Output format: `text`, `json`, or `github` (GitHub Actions annotations). |
| `--tier2-provider` | none | AI provider: `openai`, `anthropic`, or `ollama`. Omit for Tier 1 only. |
| `--tier2-model` | `gpt-4o` | Model name (e.g., `gpt-4o-mini`, `claude-sonnet-4-5-20250514`). |
| `--verbose` | off | Show per-assertion detail. |
| `--repo` | auto-detected | Repository name for multi-repo setups. Auto-detected from `GITHUB_REPOSITORY` or git remote. |

## GitHub Action

```yaml
- uses: Mipiti/mipiti-verify@956c40a9adf742e2c7436f6902e07117acefeeff # v0.26.9
  with:
    # Required
    api-key: ${{ secrets.MIPITI_API_KEY }}

    # Model selection (one of these)
    all: true                    # Verify all models in the workspace
    # model-id: "tm-abc123"     # Or verify a specific model

    # Tier 2 semantic verification (omit for Tier 1 only)
    tier2-provider: openai       # openai, anthropic, or ollama
    tier2-model: gpt-4o-mini     # e.g. gpt-4o, claude-sonnet-4-5-20250514
    tier2-api-key: ${{ secrets.OPENAI_API_KEY }}

    # Optional
    # reverify: true             # Re-verify all assertions, not just pending (default: true)
    # dry-run: false             # Run without submitting results (default: false)
    # concurrency: 1             # Max concurrent Tier 2 LLM calls (default: 1)
    # project-root: "."          # Project root directory (default: ".")
    # base-url: "https://api.mipiti.io"  # API base URL (default: https://api.mipiti.io)
```

All assertions are re-verified by default. Use `reverify: false` to only check new assertions (reduces Tier 2 API costs on PRs). Omitting `tier2-provider` runs Tier 1 only — controls won't reach "verified" status without Tier 2.

### Action Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `api-key` | **Yes** | | Mipiti API key (`mv_` verifier scope) |
| `model-id` | No | `""` | Specific model ID (omit if using `all`) |
| `all` | No | `false` | Verify all models in the workspace |
| `tier2-provider` | No | `""` | AI provider: `openai`, `anthropic`, or `ollama` |
| `tier2-model` | No | `""` | Model name (e.g., `gpt-4o`, `gpt-4o-mini`, `claude-sonnet-4-5-20250514`) |
| `tier2-api-key` | No | `""` | Provider API key (OpenAI or Anthropic) |
| `project-root` | No | `"."` | Project root directory |
| `reverify` | No | `true` | Re-verify all assertions, not just pending. Catches regressions. |
| `dry-run` | No | `false` | Run verifiers but don't submit results |
| `concurrency` | No | `1` | Max concurrent Tier 2 LLM calls |
| `base-url` | No | `https://api.mipiti.io` | API base URL |

### Action Output

| Output | Description |
|--------|-------------|
| `content-hash` | SHA-256 hash of verified assertions (`sha256:<hex>`). Use with `actions/attest-build-provenance` for Sigstore attestation. |

## Two-Tier Verification

**Tier 1 (Mechanical)** — deterministic code analysis, no external API calls:
- `function_exists`, `class_exists`, `decorator_present`, `function_calls`
- `pattern_matches`, `pattern_absent`, `import_present`
- `file_exists`, `file_hash`
- `config_key_exists`, `config_value_matches`
- `dependency_exists`, `dependency_version`
- `test_passes`, `test_exists`
- `env_var_referenced`, `error_handled`
- `no_plaintext_secret`, `middleware_registered`, `http_header_set`

**Tier 2 (Semantic)** — AI evaluates whether matched code actually implements the control's intent. Supports OpenAI, Anthropic, and Ollama (local).

**Sufficiency** — evaluated server-side: do all assertions collectively cover every aspect of the control?

## Formal Verification

The verification pipeline is formally verified using TLA+ specifications with independent model checking (TLC), exhaustive state exploration, and cross-checks against the real code. Key guarantees: all error paths fail-closed (no silent PASS), and LLM semantic checks can never override mechanical verification failures.

See [`formal/README.md`](formal/README.md) for the full methodology, invariants, and verification chain.

## Development

```bash
git clone https://github.com/Mipiti/mipiti-verify.git
cd mipiti-verify
pip install -e ".[dev]"
python -m pytest -v
```

### Updating dependencies

After changing dependencies in `pyproject.toml`, regenerate the lockfiles:

```bash
pip install uv
python lock-deps.py
```

This produces `requirements.lock` and `requirements-all.lock` with SHA-256 hashes. Commit them alongside `pyproject.toml` changes.

## License

Proprietary. Copyright (c) 2026 Mipiti, LLC. All rights reserved. See [LICENSE](LICENSE) for details.
