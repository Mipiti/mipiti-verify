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

**Bundle binding.** When an audit package carries a Sigstore bundle, the envelope must also carry `content_integrity.bundle_bind_hash` — the explicit hash the verifier compares against the bundle's in-toto Subject digest (no canonicalisation, no rehashing). Older envelopes that omit this field are rejected. Re-export the audit package from a current Mipiti build to obtain the bundle-bind coverage.

## Audit Envelope Contract

What an auditor running `mipiti-verify audit <report>` actually verifies, and what each check does (or doesn't) defend against. The contract is what makes the verifier defensible without trusting the platform: every claim the audit reports is anchored in either a public-anchor cryptographic chain or an auditor-supplied pin.

### What's inside the envelope

A signed audit package (PDF or JSON) carries the following per-row evidence:

| Field | What it is | Trust source |
|-------|-----------|--------------|
| `provenance.bundle` | Sigstore bundle from the customer's CI run (Fulcio cert + DSSE signature + Rekor inclusion proof) | Public Sigstore TUF root + Rekor transparency log |
| `content_integrity.results_hash` | SHA-256 over the canonical `verification_run.results` payload | Bound to the bundle's in-toto Subject digest via `bundle_bind_hash` |
| `content_integrity.bundle_bind_hash` | Explicit hash the verifier compares to the bundle's Subject digest (no rehashing on either side) | Pinned by `bundle_bind_signature` (platform key) |
| `content_integrity.bundle_bind_signature` | Platform ECDSA signature over `bundle_bind_hash` | Platform JWKS key (verifies independently of bundle) |
| `content_integrity.signature` + `public_key_pem` | Workspace-ECDSA signature over the row's content (when key_source is `workspace`) | Customer's workspace ECDSA key |
| `content_integrity.dsse_bundle` | Self-contained customer-keyed DSSE / in-toto attestation, signed offline with the customer's own ECDSA P-256 key (when key_source is `customer_dsse`) | Customer's own key, pinned out-of-band by fingerprint |
| `content_integrity.key_source` | One of `sigstore` / `platform` / `workspace` / `customer_dsse` / `unverifiable_orphan` / `legacy` | Tells the verifier which trust anchor to use for this row |

### Each check the verifier runs

| Check | Anchor | Fails when | What it defends against |
|-------|--------|-----------|------------------------|
| **Document signature** (PDF/HTML) | JWKS-published platform key (`/.well-known/jwks`) or Rekor anchor / snapshot | PDF body bytes were modified after signing | Tampering with the rendered report |
| **Bundle signature** (Sigstore) | Fulcio root via Sigstore TUF | DSSE signature invalid or cert chain broken | Forgery of the customer-CI-side evidence |
| **Rekor inclusion proof** | Rekor public log Merkle root | Inclusion proof can't be reconstructed | Off-log signing (impersonation outside the public transparency log) |
| **Bundle bind** | `bundle_bind_hash` ↔ bundle in-toto Subject digest (compared directly, no rehashing) | Subject digest doesn't equal `bundle_bind_hash` | Bundle/envelope swap (a real bundle paired with a different envelope's content) |
| **Bundle-bind signature** | Platform JWKS key (resolved via PDF outer-sig pubkey, `--platform-pubkey`, or envelope `public_key_pem`) | Signature invalid or no key resolvable | Tampering with `bundle_bind_hash` after the platform signed it |
| **Content-integrity signature** | Workspace ECDSA key embedded in envelope `public_key_pem` | Signature doesn't verify against embedded key | Tampering with `verification_run.results` for workspace-keyed rows |
| **Customer-keyed DSSE** (when key_source is `customer_dsse`) | The DSSE PAE over the customer-signed in-toto Statement, verified against the auditor-pinned customer public key (`--expected-customer-key`) | DSSE signature invalid, subject digest doesn't bind to the report content hash, or the signing key's fingerprint doesn't match the pinned key | Forgery of the customer-CI-side evidence in air-gapped / non-Sigstore CI; vendor substitution of the signing key |
| **Identity policy** (when pinned via `--expected-ci-identity`) | Auditor's out-of-band knowledge of the customer's CI workflow | Bundle's Fulcio SAN doesn't equal the pin (or issuer doesn't equal `--expected-issuer`) | Compromised-Mipiti forgery: a real bundle minted under an attacker's CI identity passes Sigstore but fails the pin |
| **Workspace key pin** (when `--expected-workspace-key`) | Auditor's out-of-band knowledge of the customer's workspace key | Recomputed fingerprint of the public key actually used for verification doesn't match the pin | Forged-key attack: an attacker-held key with `claimed_fp` set to the customer's known fp |
| **Predicate pins** (when `--expected-model-id` / `--expected-commit-sha`) | Bundle's signed in-toto predicate | Predicate fields don't equal the pins | Replay of an older verification run; cross-model substitution |

### What's signed vs. what's only present

- **Signed by Fulcio** (provable identity): bundle DSSE payload (per-tier verification statement, including assertion specs and verdicts).
- **Signed by platform JWKS key**: `bundle_bind_signature` (platform's attestation that this `bundle_bind_hash` came out of an authorized Mipiti instance).
- **Signed by workspace key**: `content_integrity.signature` over `results_hash` for workspace-keyed rows.
- **Recorded in Rekor**: every Sigstore bundle (publicly auditable, immutable transparency log).
- **Not signed**: the package's outer JSON metadata (`generated_at`, `model.title`, etc.) — those are unsigned and forgeable. The verifier never reads pin-relevant values from outer metadata.

### Auditor pins and what each one buys

Pins are **out-of-band knowledge** the auditor brings to the verification: they're what closes the gap between "this bundle is internally consistent" and "this bundle came from the customer's actual release process." Without pins, the verifier can confirm cryptographic integrity but not identity.

- `--expected-ci-identity '<SAN>'` — pin the workflow identity. SAN format: `https://github.com/Org/Repo/.github/workflows/<file>.yml@<git-ref>`. Source the value from the customer's release docs / security policy, never from the bundle itself.
- `--ci-identity-from-env` — auto-derive from `GITHUB_WORKFLOW_REF` when running `audit` inside CI for the same workflow that generated the report.
- `--expected-issuer` — pin the OIDC issuer. Required for self-hosted GitHub Enterprise / GitLab; auto-derived from SAN prefix for github.com / gitlab.com.
- `--expected-workspace-key '<fp>'` — pin the workspace ECDSA key fingerprint (SHA-256 hex of DER SubjectPublicKeyInfo).
- `--expected-customer-key '<path-to-pubkey.pem>'` — pin the customer's public key (PEM) for the customer-keyed offline DSSE path. The verifier requires the SHA-256 fingerprint of this key's DER SubjectPublicKeyInfo to equal the key that actually signed the bundle. Source the public key from the customer out-of-band, never from the envelope. Required whenever the package carries a `customer_dsse` envelope — without it, the audit fails closed.
- `--expected-model-id`, `--expected-commit-sha` — pin predicate fields signed inside the bundle. For `customer_dsse`, `--expected-customer-key` is the analogue of a SAN pin: it makes the predicate pins meaningful (the predicate is signed by the customer's own key), so predicate pins may be used together with it without `--expected-ci-identity`.

The verifier emits a "Trust contract" summary block at the end of each audit listing which pins were enforced and which were skipped, so an auditor can see at a glance what their command actually checked.

### Failure modes (every check fails closed)

The verifier exits non-zero on any of:

- Cryptographic check fails (bundle signature, Rekor proof, bundle-bind, content-integrity sig).
- Identity pin set but bundle's SAN/issuer doesn't match.
- Workspace key pin set but the recomputed fingerprint doesn't match.
- Predicate pin set but the bundle's predicate field doesn't match.
- Bundle-bind signature present but no platform key resolvable (would be silent skip otherwise).
- Document signature on the PDF/HTML body is missing or invalid.
- Pinning flags supplied to a format that can't honour them (e.g. identity pins on an HTML report — fails-closed instead of silently dropping the pin).

There is no `--allow-unsigned`, no soft-fail, and no fallback that treats a missing signature as "good." When the auditor needs to enforce attestation on the producer side too (CI runner), use `--require-attestation` on `mipiti-verify run` to make missing/failed signing a non-zero exit.

### Independent re-verification

Every published audit can be re-checked offline using only:

- The Sigstore TUF root (cacheable; pinnable via `--sigstore-trust-config <path>`).
- The Mipiti instance's JWKS (`/.well-known/jwks`; pinnable via `--platform-pubkey <pem>` for fully offline runs).
- The customer's workspace key fingerprint (auditor's out-of-band knowledge).
- The customer's CI workflow identity (auditor's out-of-band knowledge).
- For the customer-keyed offline DSSE path: the customer's public key, pinned out-of-band by the auditor via `--expected-customer-key`.

No live Mipiti API access is required at audit time. The verifier produces the same verdict on the same input regardless of network reachability to api.mipiti.io.

### Customer-keyed offline signing (air-gapped / non-Sigstore CI)

Sigstore signing needs a Fulcio-trusted OIDC token and reachability to public Sigstore infrastructure at sign time. CI that structurally cannot do this — Jenkins, self-managed or older GitLab, Buildkite/CircleCI without OIDC, regulated/air-gapped networks — can instead sign with a **customer-controlled key**, fully offline, and have the result remain independently verifiable in the standard DSSE / in-toto format.

**Producer side (`mipiti-verify run`).** Generate an ECDSA P-256 keypair, keep the private half local, and register the public half on the Mipiti workspace. Then:

```bash
mipiti-verify run tm-abc123 \
  --api-key "$MIPITI_API_KEY" \
  --customer-key ./customer-signing-key.pem \
  --customer-key-passphrase "$KEY_PASSPHRASE"   # omit for an unencrypted key
```

`--customer-key` (env: `MIPITI_CUSTOMER_SIGNING_KEY`; passphrase env: `MIPITI_CUSTOMER_SIGNING_KEY_PASSPHRASE`) builds a standard in-toto Statement (same shape as the Sigstore path — assertion specs + verdicts in the predicate), computes the DSSE Pre-Authentication Encoding, and signs it with the customer's key. No Fulcio, no Rekor, no network at sign time. When supplied, this path is preferred over Sigstore. Combine with `--require-attestation` to fail the run if signing did not occur.

**Auditor side (`mipiti-verify audit`).** Obtain the customer's public key out-of-band (release docs / security policy) and pin it:

```bash
mipiti-verify audit report.json \
  --expected-customer-key ./customer-public-key.pem \
  --expected-model-id tm-abc123        # optional predicate pins, now meaningful
```

The verifier reconstructs the DSSE PAE from the embedded payload, checks the signature, requires the SHA-256 fingerprint of the pinned key's DER SubjectPublicKeyInfo to equal the key that actually signed the bundle (the vendor-independence gate — a swapped key fails here), and binds the Statement subject digest to the report's content hash. Entirely offline. If the package carries a `customer_dsse` envelope but `--expected-customer-key` is not supplied, the audit fails closed and says so — the embedded PEM is never silently trusted.

For this path the vendor-independence property holds without caveat: the auditor verifies the chain from the envelope bytes plus a fingerprint pinned **from the customer**. Mipiti is pure transport — it holds no customer private key and cannot substitute the key without failing the fingerprint gate. Revocation is out-of-band (the customer tells auditors to stop trusting a fingerprint), the same as any pinned key.

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
permissions:
  id-token: write    # required: mints the OIDC token used for Sigstore signing
  contents: read

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1
      - uses: Mipiti/mipiti-verify@dad64a896208225ad79b98ac9063c6b77f0d5b09 # v0.45.1
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
          # sigstore-tuf-url: "..."    # Private Sigstore deployment (default: public sigstore.dev)
```

All assertions are re-verified by default. Use `reverify: false` to only check new assertions (reduces Tier 2 API costs on PRs). Omitting `tier2-provider` runs Tier 1 only — controls won't reach "verified" status without Tier 2.

### Attestation (Sigstore)

`mipiti-verify` signs every submitted result set with [Sigstore](https://sigstore.dev): the runner's short-lived OIDC token is exchanged at Fulcio for a signing certificate, the verified content hash is signed, and the entry is recorded in Rekor (the public transparency log). Mipiti's backend receives only the resulting bundle — **the raw OIDC token never leaves CI**.

**Offline verification**. The bundle is self-contained: it carries the signing certificate, signature, Rekor inclusion proof, and signed Merkle tree checkpoint. An auditor can re-verify the bundle **without contacting Rekor or Mipiti** — they need only the Sigstore trust root (Fulcio CA chain + Rekor public key + CT log keys). The [`sigstore`](https://pypi.org/project/sigstore/) client fetches the trust root from TUF on first use and caches it; the TUF timestamp expires in ~1 week, so repeat verifications on the same workstation are network-free until then. For fully air-gapped review, pin a trust root snapshot and pass it to `mipiti-verify audit --sigstore-trust-config <path>`.

**Network dependencies at CI-time**. Signing requires outbound access to `fulcio.sigstore.dev` (certificate issuance), `rekor.sigstore.dev` (transparency log), and `tuf-repo-cdn.sigstore.dev` (trust root). Each CI job starts from a cold TUF cache, so expect ~1–3s of trust-root fetch on every run. To eliminate the TUF fetch entirely — e.g. for air-gapped CI — download a Sigstore `ClientTrustConfig` JSON out-of-band and pass it via `sigstore-trust-config`. Private Sigstore deployments can redirect the whole stack via `sigstore-tuf-url`.

Private or air-gapped deployments can also redirect signing itself at their own Sigstore instance via `sigstore-tuf-url` on the `run` command.

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
| `sigstore-tuf-url` | No | `""` | Custom Sigstore TUF root URL for private deployments (default public `sigstore.dev`) |
| `sigstore-trust-config` | No | `""` | Path to a pre-downloaded Sigstore ClientTrustConfig JSON for fully air-gapped CI (skips all TUF fetches) |
| `workspace-signing-key` | No | `""` | PEM ECDSA P-256 private key for workspace-attested submission. Used when no OIDC token is available (Jenkins, Buildkite, self-managed GitLab without ID tokens) or when `signing-prefer=workspace` |
| `signing-prefer` | No | `sigstore` | When both an OIDC token and a workspace key are available, prefer this signer (`sigstore` or `workspace`) |
| `require-attestation` | No | `false` | Fail the run when no attestation is produced. Default behaviour is to log a warning and submit unsigned when both Sigstore and workspace-ECDSA signing are unavailable; set to `true` for security-sensitive CI gates that should fail-close on missing attestation |

### Action Output

| Output | Description |
|--------|-------------|
| `content-hash` | SHA-256 hash of verified assertions (`sha256:<hex>`). Use with `actions/attest-build-provenance` for Sigstore attestation. |

## Two-Tier Verification

**Tier 1 (Mechanical)** — <!--ASSERTION_TYPE_COUNT-->21<!--/ASSERTION_TYPE_COUNT--> typed assertion checks, deterministic code analysis, no external API calls:
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
