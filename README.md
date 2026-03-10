# mipiti-verify

Turnkey CI verification for [Mipiti](https://mipiti.io) threat model assertions.

## Install

```bash
pip install mipiti-verify[all]
```

## Usage

```bash
# Verify a single model
mipiti-verify run <model_id> \
  --api-key $MIPITI_API_KEY \
  --tier2-provider openai \
  --project-root .

# Verify all models in the workspace
mipiti-verify run --all \
  --api-key $MIPITI_API_KEY \
  --tier2-provider openai \
  --project-root .

# List pending assertions
mipiti-verify list <model_id>

# Show verification report
mipiti-verify report <model_id>
```

API keys are workspace-scoped — `--all` verifies every model accessible by the key.

## GitHub Action

```yaml
- uses: mipiti/mipiti-verify@v1
  with:
    model-id: ${{ secrets.MIPITI_MODEL_ID }}
    api-key: ${{ secrets.MIPITI_API_KEY }}
    tier2-provider: openai
    tier2-api-key: ${{ secrets.OPENAI_API_KEY }}
```

## Docker

```bash
docker run ghcr.io/mipiti/mipiti-verify:latest \
  run <model_id> --api-key $MIPITI_API_KEY --tier2-provider openai
```

## Development

```bash
git clone https://github.com/Mipiti/mipiti-verify.git
cd mipiti-verify
pip install -e ".[dev]"
python -m pytest -v
```

## License

Proprietary. Copyright (c) 2026 Mipiti, LLC. All rights reserved. See [LICENSE](LICENSE) for details.
