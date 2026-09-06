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
mipiti-verify audit audit-package.json --full
```

Independently verifies ECDSA document signatures on exported HTML reports and JSON audit packages. Validates OIDC provenance, content integrity, and per-assertion reasoning.

**Output modes.** The default output is a verdict-first workpaper summary: the verdict line, the trust contract, one line per contributing run, the producer-disclosure cross-check, an itemized Caveats section (each with its remediation hint), per-control pass/fail counts, condensed composition aggregates, and the compact cryptographic evidence blocks. Detail auto-expands only for elements that fail or degrade — a failed assertion prints its full row, a hash mismatch prints expected vs. recomputed hashes, an unverifiable run keeps its explanation — so a clean report is short and a problem report shows exactly the problem. `--full` restores the exhaustive listing in verification order (per-assertion detail, per-CO composition enumeration, inheritance-binding rows, the provenance-health panel). Exit codes are identical in both modes; scripted consumers should gate on the exit code.

**Bundle binding.** When an audit package carries a Sigstore bundle, the envelope must also carry `content_integrity.bundle_bind_hash` — the explicit hash the verifier compares against the bundle's in-toto Subject digest (no canonicalisation, no rehashing). Older envelopes that omit this field are rejected. Re-export the audit package from a current Mipiti build to obtain the bundle-bind coverage.

### `attest-tests` / `attest-dependence` / `attest-reach` — Record test evidence in the test job

```bash
pytest --junitxml=report.xml
mipiti-verify attest-tests --junit report.xml --coverage coverage.json
mipiti-verify attest-dependence --pair tests/test_auth.py::test_token_required=app/auth.py::require_token
mipiti-verify attest-reach --pair tests/test_auth.py::test_token_required=app/auth.py::require_token
```

`attest-tests` reads the report your test step wrote and signs it; it runs nothing. `attest-dependence` and `attest-reach` are the two opt-in commands that **run tests**: each named test once, with its mechanism disabled (does the test fail without it?) or alone under coverage (which lines of the mechanism's file does it execute?). Both go through the project's runner adapter (pytest, jest, vitest, mocha, go, cargo, maven, gradle, dotnet, rspec, phpunit, or a `--run-cmd` for simulators; `--suite-cmd` + `--suite-junit` for a harness that runs everything at once) and belong in the job that already runs your tests. See [Test-result attestations](#test-result-attestations-test_attested) and [Runners](#runners).

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

### Run-level provenance (`contributing_runs` + `provenance_health`)

Verification state in a report accumulates across (often partial) CI runs — each assertion's current status was earned by its most recent run. Newer envelopes disclose that history through two additive top-level keys:

- `contributing_runs` — one entry per status-determining run. Each entry carries the run's exact canonical results text (`results_canonical` — the exact bytes whose hash was signed), its own `content_integrity` block (`results_hash`, `signature`, key material), the assertion ids that run determines, and optionally a per-run Sigstore bundle (the canonical trust anchor for that run when present).
- `provenance_health` — the producer's own coverage disclosure (assertions run-covered vs. manifest-only, per-run key/serialization limitations, warnings). Rendered as a panel in `--full` output; the default summary surfaces its warnings in the Caveats section and reports the agreement/disagreement outcome of the auditor-side cross-check. The per-run verification is the independent auditor-side check in both modes.

The verifier checks each run independently: SHA-256 recomputed over the exact `results_canonical` bytes against `results_hash`, the signature over the hash with the run's key (embedded PEM or JWKS lookup by fingerprint), and the per-run Sigstore bundle when present. Each run is reported as `VERIFIED`, `UNRESOLVED KEY`, `UNVERIFIABLE SERIALIZATION`, `TAMPER-MISMATCH`, or `UNSIGNED`. A run whose `content_integrity` declares `unverifiable_serialization` (signed material exists but the signed bytes can no longer be re-derived; the serialization predates canonical freezing) is a coverage limitation — reported distinctly from a hash mismatch and never treated as tampering. A genuine mismatch over present `results_canonical` fails the audit.

Assertions carried by the report's records but determined by no embedded run are reported as **manifest-only provenance**, cross-checked against `provenance_health.assertions_manifest_only`. When contributing runs are embedded, the deprecated top-level `results_hash` + `signature` pair is superseded: a divergence there is rendered informationally (`NOT SCORED`) and tamper conclusions come solely from the per-run checks. Older envelopes without these keys verify exactly as before — the legacy pair stays strict, and the trust contract reports run-level provenance as `UNKNOWN` (latest-run evidence only), never as a failure.

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

The verifier emits a "Trust contract" summary block in every audit — immediately after the verdict in the default summary, at the end of the `--full` listing — naming which pins were enforced and which were skipped, so an auditor can see at a glance what their command actually checked.

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
| `--changed-files FILE` | none | Only verify assertions referencing listed files. Use `git diff --name-only HEAD~1 > changed.txt`. Test-backed assertions are always verified regardless. |
| `--test-file-pattern REGEX` | none | Additional repository-relative paths to treat as test files (on top of the layout heuristic), for repositories whose tests live outside the conventional layouts. |
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
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2

      # Your tests, run by you. Write a JUnit report so the result can be
      # recorded as evidence; verification reads it and runs nothing itself.
      - run: pytest --junitxml=report.xml

      - uses: Mipiti/mipiti-verify@49e2f62a4afb86e94cb4be41c9b0be043885ee04 # v0.53.0
        with:
          # Required
          api-key: ${{ secrets.MIPITI_API_KEY }}

          # Needed for test_attested assertions. Points at the report the step
          # above wrote; the action records a signed attestation from it before
          # verifying. Space-separate several paths for more than one suite.
          # Signed keylessly through Sigstore using the run's OIDC token — no
          # secret to create or rotate. Only CI without a workload identity
          # needs attestation-signing-key.
          junit-report: report.xml

          # Optional, opt-in, and the only inputs that run tests: dependence
          # and reach for the pairs named, through the project's runner.
          # dependence-pairs: tests/test_auth.py::test_token_required=app/auth.py::require_token
          # reach-pairs: tests/test_auth.py::test_token_required=app/auth.py::require_token
          # runner: go                 # override the detected runner; 'command' with run-cmd for simulators

          # Optional, for assertions that require the run to have used a
          # particular configuration. A suite can pass with the control it
          # exercises switched off, and a file in the repository shows what is
          # declared, not what the run had. Only these names are recorded, and
          # a name that looks like a credential is refused.
          attestation-env: FEATURE_AUTH ENFORCE_TLS

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

### Requiring an attestation (recommended)

When the job has no OIDC token (no `id-token: write`) and no `workspace-signing-key`, the action still submits results, unsigned, and emits a `::warning::` annotation saying so. For a CI gate whose results are meant to be audited, set `require-attestation: true` so a run that cannot produce an attestation fails instead of submitting one the audit side cannot pin to a signing identity:

```yaml
permissions:
  id-token: write
  contents: read

steps:
  - uses: Mipiti/mipiti-verify@<pinned-sha> # vX.Y.Z
    with:
      api-key: ${{ secrets.MIPITI_API_KEY }}
      all: true
      require-attestation: true
```

The default stays `false` so existing workflows on runners without workload identity keep working; the annotation is the signal to either grant the permission, configure a key, or opt into failing closed.

### Attestation (Sigstore)

`mipiti-verify` signs every submitted result set with [Sigstore](https://sigstore.dev): the runner's short-lived OIDC token is exchanged at Fulcio for a signing certificate, the verified content hash is signed, and the entry is recorded in Rekor (the public transparency log). Mipiti's backend receives only the resulting bundle — **the raw OIDC token never leaves CI**.

**Offline verification**. The bundle is self-contained: it carries the signing certificate, signature, Rekor inclusion proof, and signed Merkle tree checkpoint. An auditor can re-verify the bundle **without contacting Rekor or Mipiti** — they need only the Sigstore trust root (Fulcio CA chain + Rekor public key + CT log keys). The [`sigstore`](https://pypi.org/project/sigstore/) client fetches the trust root from TUF on first use and caches it; the TUF timestamp expires in ~1 week, so repeat verifications on the same workstation are network-free until then. For fully air-gapped review, pin a trust root snapshot and pass it to `mipiti-verify audit --sigstore-trust-config <path>`.

**What the attestation carries**. The signed in-toto predicate holds `model_id`, `tier`, `content_hash`, `pipeline` metadata, and a compressed `{assertions, results}` payload. `assertions` carries each assertion's verified content (`id`, `type`, `params`, `description`; the fields bound by `content_hash`), its binding (`control_id` / `assumption_id` / `functional_test_id` / `node_id`, `repo`), and provenance (`origin`, `inherited_from_model_id`, `created_by`, `created_at`). `results` carries this run's verdicts. The platform's stored verdict state from earlier runs is not part of the attestation. Verifiers bind on `content_hash` (the Subject digest) and the predicate pins; the payload arrays are evidence for a reader of the bundle, not an input to any signature check.

**Network dependencies at CI-time**. Signing requires outbound access to `fulcio.sigstore.dev` (certificate issuance), `rekor.sigstore.dev` (transparency log), and `tuf-repo-cdn.sigstore.dev` (trust root). Each CI job starts from a cold TUF cache, so expect ~1–3s of trust-root fetch on every run. To eliminate the TUF fetch entirely — e.g. for air-gapped CI — download a Sigstore `ClientTrustConfig` JSON out-of-band and pass it via `sigstore-trust-config`. Private Sigstore deployments can redirect the whole stack via `sigstore-tuf-url`.

Private or air-gapped deployments can also redirect signing itself at their own Sigstore instance via `sigstore-tuf-url` on the `run` command.

### Test-result attestations (`test_attested`)

A `test_attested` assertion is checked against a statement your CI signed about a test run your own workflow performed. `mipiti-verify attest-tests --junit <report>` (or the action's `junit-report` input) turns a JUnit report into an in-toto Statement with `predicateType` `https://mipiti.io/attestations/test-result/v1`, signs it, and writes it to `.mipiti/attestations/` in the checkout. Verification reads it and executes nothing.

**Predicate schema.** Published at [`schemas/test-result-v1.schema.json`](schemas/test-result-v1.schema.json). Any producer that emits a conforming statement, signed under an identity the verifier is pinned to, is accepted; the CLI is one producer, not the interface. The load-bearing fields are `commit` (must equal the commit under verification), `totals` and `selected.matched_count` (a run that selected nothing or in which nothing passed is refused), and `tests[]` with a per-test `status` (the named test must itself be `passed`; a skip is not evidence). `environment` records only the variables nominated with `attestation-env`, and an assertion's `env` param requires their values.

**Signing identity and what reaches the platform.** The attestation is signed the same way the verification run is: keylessly through Sigstore under the CI workload identity (`ci_oidc`) where one exists, with a customer-held ECDSA key (`customer_key`) where none does, and `unsigned` only where neither could apply. Each `test_attested` result submitted to the platform carries that class in a `provenance` field, so the audit envelope and the platform's sufficiency inputs can weigh a workflow-signed pass against a self-declared one as data rather than by reading prose.

**Tests and verification in separate jobs.** `.mipiti/attestations/` lives in the runner's working tree, not in the repository. If your tests run in one job and verification in another, upload that directory as a workflow artifact from the test job and download it before the verify step. This is sound because freshness is not the guard, the commit binding is: an attestation names the commit its run covered, so a file from an older run names an older commit and is refused, and a file that names the current commit could only have been produced by a run against that tree. No file committed into the repository can name its own commit, since the commit hash covers the file. What an attestation cannot say is whether something outside the tree, such as a live service, changed between the run and the read; `attested_at` and `ci.run_url` are recorded for exactly that reader.

**GitLab.** Keyless signing uses the `id_tokens` job keyword; expose the token as `SIGSTORE_ID_TOKEN` with audience `sigstore`. The retired `CI_JOB_JWT_V2` is still honoured.

**What the attestation now carries.** Beyond the run's outcome, each recorded test is bound to its content and, optionally, to what it did:

- *Definition.* `attest-tests` locates each test in the checkout (pytest `classname` → module → file, or the JUnit `file` attribute for other runners) and records `file` and `definition_sha256`, a hash over the definition block from its decorators to the end of its body, whitespace-normalised. A parametrized id (`test_x[case-1]`) resolves to the function; a method's hash covers the method. Each entry says what the hash covers (`definition_scope`: `symbol`, `block` or `file`) and what isolated it (`parser`); see [Languages](#languages) for how each language is cut and what the fallback can and cannot tell apart. A test that cannot be located carries neither field. The `test_attested` result reports the hash as `evidence_hash`, so a tier-2 acceptance is bound to the definition it was given, and a changed definition is re-judged rather than carried forward.
- *Reach.* `attest-tests --coverage <report>` reads a coverage report (coverage.py JSON, LCOV, Cobertura XML, JaCoCo XML, or a directory of one report per test; see [Languages](#languages)) and records, per test, `reached: [{file, lines}]` when the report attributes lines to that test, or `suite_reached` when it only says what the whole run executed. When the assertion names a `mechanism`, the result reports `reached: true|false`: whether the test executed a line of that mechanism's definition. An empty `reached` is a fact (the run had coverage and the test touched nothing); `suite_reached` and a run without `--coverage` leave it unknown.
- *Dependence.* `mipiti-verify attest-dependence` runs each `(test, mechanism)` pair once with the mechanism disabled and signs the outcome into a second attestation with `predicate.kind = "dependence"`. The result reports `depends: true|false`: a test that fails without the mechanism depends on it; one that still passes does not. **This command runs tests.** It is opt-in and lives in the job that already runs your tests next to `attest-tests`; `run` still executes nothing. Pairs come from `--pair <test>=<file>::<symbol>` (repeatable) or `--from-model <id>` (every `test_attested` assertion of the model that names a `mechanism`, fetched with the same credentials `run` uses). How the mechanism is disabled depends on the runner (see [Runners](#runners)): a pytest plugin stubs a Python symbol at import time (the module is imported at pytest configuration time, so nominate mechanisms in modules that are safe to import); jest, vitest and mocha load a setup file that mocks the module and replaces the export with a function that throws; every other language has the definition's body replaced in the source by one that aborts, compile-checked first and restored byte-for-byte afterwards. The fact is defined identically everywhere: the test's outcome is anything but `passed` with the mechanism disabled *and* the mutated tree compiled. A mutated tree that does not compile, a file with uncommitted changes, a runner that selected no test, or a mechanism that cannot be disabled records `status: error` with a `reason`, which the verifier reads as unknown, never as an outcome. Two clocks bound the command: `--timeout` per pair (default 300s) and `--total-timeout` for the whole run (default 1800s, also `MIPITI_DEPENDENCE_TOTAL_TIMEOUT`). A pair that would start after the total budget is spent is recorded as not run (`status: error` with a `reason`), so the attestation still names every requested pair.
- *Reach, per test, for any runner.* `mipiti-verify attest-reach` runs each nominated test **alone** under the language's coverage tool through the same runner adapter and signs the lines it executed in the mechanism's file into a third attestation with `predicate.kind = "reach"`, in the same per-test `reached: [{file, lines}]` shape `attest-tests --coverage` records. Running one test at a time is what makes it a claim about that test rather than the suite, which is why an aggregate report never yields `reached` on its own. Only the mechanism's file is recorded. Same pair sources, same two clocks, same signing as `attest-dependence`; a runner whose coverage tool is missing or produced no report records `status: error` with the `reason`. **Per-test reach requires running a test alone.** For a harness that cannot, `attest-reach --suite-cmd "<command>" --coverage-file <report>` runs the suite once under coverage and records, per nominated test, what the *suite* reached in its mechanism's file as `suite_reached`, with `predicate.reach_scope = "suite"`. That is information, not the fact: per-test reach is undefined for such a harness, so a suite-scope record never yields `reached`; the verifier reports `reached mechanism: unknown (suite-level coverage only)`. `attest-reach` without `--suite-cmd` (per test, through the adapter or `--run-cmd` with `{test}`) is what establishes the fact.

**The `mechanism` param.** A `test_attested` assertion may name the mechanism the test is meant to exercise as `mechanism: "<file>::<symbol>"` (`Class.method` for a method; `<kind>:<name>` to name the kind outright, e.g. `rtl/alu.sv::module:alu` or `rtl/fsm.sv::always:seq_logic`). It is what reach and dependence are computed against, and what the tier-2 reviewer is shown next to the test.

#### Languages

The proofs are language-agnostic; only one question is language-specific: which lines make up the definition of `(file, kind, name)`. It is answered by a parser where one exists and by a sound fallback otherwise, and every attestation entry says which (`parser`) and how exactly (`definition_scope`).

| Language | Parser | Kinds |
|---|---|---|
| Python | `ast` (always) | `function`, `class`, `Class.method` |
| JavaScript, TypeScript, Go, Rust, Java, Kotlin, C, C++, C#, Ruby, PHP, Swift | tree-sitter, from the optional extra `mipiti-verify[ast]` | `function`, `method`, `class` (struct / interface / trait / impl / enum), `Class.method` |
| Verilog / SystemVerilog (`.v`, `.vh`, `.sv`, `.svh`) | tree-sitter (same extra) | `module`, `interface`, `package`, `program`, `function`, `task`, `class`, `Class.method`, labelled `always` / `initial` (`begin : label`), `property`, `sequence`, labelled `assert` / `assume` / `cover` |
| VHDL (`.vhd`, `.vhdl`) | tree-sitter (same extra) | `entity`, `architecture`, `package`, labelled `process`, `function`, `procedure` |
| HDL without the extra | keyword-pair scanner: `module … endmodule`, `function … endfunction`, `task … endtask`, `class … endclass`, `property … endproperty`, `sequence … endsequence`, `begin … end` (nested), `label: always …` / `always … begin : label`, `label: assert …;`, `entity … end`, `architecture … end`, `label: process … end process`, `function … end`; comments and strings skipped | the same HDL kinds |
| Anything else, or no extra installed | a `{ … }` block with nesting, else an indentation block, starting at the first line that looks like the definition | `function`, `class`, `Class.method` |

In an HDL, `function` means any subprogram (a task or procedure too), since a test is nominated by name rather than by the keyword that declared it; `task` and `procedure` are strict. `definition_scope` is `symbol` when a parser or the keyword scanner isolated exactly the named definition (a `Class.method` name resolves inside its class); `block` when the line heuristic cut a block starting at the first match of the name, which cannot tell two same-named definitions apart, so a method name duplicated across classes in one file resolves to the first; `file` when nothing could be isolated and the hash covers the whole file. Every scope is sound for the pin: any change to the hashed text, or a move of the name, changes the hash. `parser` is `ast`, `tree-sitter`, `keyword` or `lines` (absent for `file`). The extra downloads each grammar into a local cache on first use; where it is not installed or a grammar is unavailable the fallbacks apply and the attestation records that.

Coverage formats accepted by `--coverage`: coverage.py JSON (`coverage json`; with `--show-contexts` lines are attributed to tests), LCOV (`.info` / `.lcov`, including what `verilator_coverage --write-info` writes), Cobertura XML and JaCoCo XML. The format is detected from the content. Reach is a claim about one test, so only a report that attributes lines to a test yields `reached`; an aggregate report is recorded as `suite_reached` (informational) and reach stays unknown. To attest reach in a language whose coverage tool has no per-test contexts, run each nominated test alone and write its report into one directory as `<test id>.<ext>` with `::` spelled `__` (for example `tests.test_guard__test_a.info`, or `test_a.info`); pass that directory to `--coverage` and each file is read as that test's own run.

**Tier 2 reads the closure.** For a `test_attested` review the reviewer is handed the test's definition from the checkout, the named mechanism's definition, and a facts block (definition hash match, reached, fails without). The criterion is YES only if the test as shown exercises the mechanism and asserts the stated outcome; a fact of `reached: no` or `fails without mechanism: no` is a NO whatever the test text says.

**Never skipped under `--changed-files`.** Test-backed assertions (`test_attested`, `test_exists`, and `function_exists` / `class_exists` whose file is a test file) are always verified, in both tiers, when `--changed-files` is set: a test's subject is the code it exercises, so its own file being unchanged says nothing about the claim. A test file is recognised by layout (`tests/`, `test/`, `__tests__/`, `test_*`, `conftest*`, `*_test.*`, `*_spec.*`, `*.test.*`, `*.spec.*`); repositories whose tests live outside the conventional layouts, e.g. `specs/auth.py`, add `--test-file-pattern '<regex>'` (also `MIPITI_TEST_FILE_PATTERN`), which marks additional repository-relative paths in addition to the heuristic.

```yaml
      - run: pytest --junitxml=report.xml --cov --cov-context=test && coverage json --show-contexts -o coverage.json
      - uses: Mipiti/mipiti-verify@<pinned-sha> # vX.Y.Z
        with:
          junit-report: report.xml
          coverage-report: coverage.json
          # Opt-in: runs each named test once with its mechanism disabled.
          dependence-pairs: "tests/test_auth.py::test_token_required=app/auth.py::require_token"
```

#### Runners

`attest-dependence` and `attest-reach` execute tests through a runner adapter, detected from the project's files; `--runner <name>` (action input `runner`) overrides it, and `--run-cmd` selects the command runner. In a polyglot checkout the language of the mechanisms breaks the tie; a checkout with no marker at all is treated as pytest.

| Runner | Detected by | Selects one test with | Needs installed | Coverage for `attest-reach` | Disables a mechanism by |
|---|---|---|---|---|---|
| `pytest` (also cocotb suites driven by pytest) | `pytest.ini`, `setup.cfg`, `tox.ini`, `conftest.py`, or `pyproject.toml` with pytest config / a `tests/` tree | node id, or `-k <name>` | `pytest`; `coverage` for reach | `coverage run` + `coverage json --show-contexts` | import-time stub (plugin) for Python; source mutation for Verilog / SystemVerilog / VHDL |
| `jest` | `package.json` with a `jest` dependency or key, `jest.config.*` | `--runTestsByPath <file> -t '^<name>$'` | `jest` (local `node_modules/.bin` or `npx --no-install`) | `--coverage --coverageReporters=lcov` | setup file via `--setupFilesAfterEnv` that `jest.mock`s the module path |
| `vitest` | `package.json` with `vitest`, `vitest.config.*` | `vitest run <file> -t '^<name>$'` | `vitest`; `@vitest/coverage-v8` or `-istanbul` for reach | `--coverage.enabled --coverage.reporter=lcov` | temporary config that extends the project's with a `setupFiles` entry whose `vi.mock` replaces the export |
| `mocha` | `package.json` with `mocha`, `.mocharc.*` | `mocha <file> -g '^<name>$'` | `mocha`; `c8` or `nyc` for reach | `c8 --reporter=lcov` (else `nyc`) | `--require` file that patches the CommonJS export object in place |
| `go` | `go.mod` (root or one level down) | `go test -run '^<Test>$' <pkg>` (`pkg::TestName` selects the package) | `go` | `-coverprofile` + `-coverpkg=./...`, converted to LCOV | source mutation, `go build ./...` check |
| `cargo` | `Cargo.toml` | `cargo test <path> -- --exact` | `cargo`; `cargo-llvm-cov` for reach | `cargo llvm-cov test --lcov` | source mutation, `cargo check --tests` |
| `maven` | `pom.xml` | `-Dtest=Class#method` (`Class::method`) | `mvn` | JaCoCo (`jacoco-maven-plugin` must be in the pom) → `target/site/jacoco/jacoco.xml` | source mutation, `mvn -DskipTests compile` |
| `gradle` | `build.gradle`, `build.gradle.kts` | `test --tests Class.method` | `gradle` or `./gradlew` | JaCoCo (`jacoco` plugin applied, XML report enabled) | source mutation, `compileJava` / `compileKotlin` |
| `dotnet` | `*.sln`, `*.csproj` | `dotnet test --filter FullyQualifiedName~Class.Method` | `dotnet` | `--collect "XPlat Code Coverage"` (coverlet, Cobertura) | source mutation, `dotnet build` |
| `rspec` | `.rspec`, or `Gemfile` + `spec/` | `rspec <file> -e <name>` (`bundle exec` with a Gemfile) | `rspec`; `simplecov` for reach | SimpleCov `.resultset.json`, converted to LCOV | not supported (recorded as `error`) |
| `phpunit` | `phpunit.xml*` | `phpunit --filter <name> <file>` | `phpunit` (`vendor/bin` first); xdebug or pcov for reach | `--coverage-clover`, converted to LCOV | not supported (recorded as `error`) |
| `command` | `--run-cmd` given | the command with `{test}` substituted; exit 0 passed, 1 failed, anything else `error` (wrap a harness so a failing test exits 1: `... || exit 1`) | whatever the command needs | `--coverage-cmd` (defaults to `--run-cmd`) then `--coverage-file <report>`: LCOV, Cobertura, JaCoCo or coverage.py JSON | source mutation in any language below |

**Source mutation.** For Go, Rust, Java, Kotlin, C, C++, C#, Swift, Verilog, SystemVerilog and VHDL the mechanism is disabled by rewriting its definition in place for the duration of the one run: a function or method body becomes one that aborts (`panic`, `panic!`, `throw`, `abort()` with `#include <stdlib.h>` added when missing, `fatalError`); a class, struct or `impl` has every method body replaced; a Verilog `module` becomes a stub with the same header whose outputs are driven to `x` (a non-ANSI module keeps its body port declarations, re-emitted verbatim; a port the header names without a declaration, or a declaration the header does not name, is `error` with the reason); a `function` / `task` body becomes `$fatal`; a labelled `always` / `initial` block, a `property` or `sequence` (with every assertion that instantiates it) or a labelled `assert` is removed; a VHDL `architecture` body is emptied, a labelled `process` removed, a `function` / `procedure` body replaced by `assert false ... severity failure`. Name the kind when a bare name would be ambiguous: `rtl/alu.sv::module:alu`, `rtl/fsm.sv::always:seq_logic`, `rtl/alu.sv::assert:a_no_overflow`, `rtl/top.vhd::process:p_clk`. Four invariants hold for every mutation: the definition must be isolated exactly by the language layer (a parser, or the HDL keyword scanner, which reads the name at the block's own start; a line-heuristic `block` span may be a different definition, and a mutation of the wrong block can still compile, which would attribute a test's outcome to the wrong mechanism, so such a pair is `error` with reason `definition not isolated exactly (install mipiti-verify[ast] or nominate a unique symbol)`); the file must be committed with no uncommitted changes (otherwise the pair is `error`, so a run can never leave a change behind the tree did not already have); the mutated tree is compile- or lint-checked before the test runs (`go build`, `cargo check`, `mvn compile` / `gradle compileJava` / `javac`, `kotlinc`, `cc -fsyntax-only`, `dotnet build`, `swift build` / `swiftc -typecheck`, `verilator --lint-only` / `slang --lint-only` / `iverilog -t null`, `ghdl -a` / `nvc -a`, whichever is present), and a failing check is `error` with the tool's output as the reason, never `failed`; and the original bytes are written back afterwards and verified by hash, whatever happened in between.

**Suite mode: dependence from a whole-suite run.** A simulator or a Makefile harness often has no way to run one test, and its pass/fail is a JUnit report rather than an exit status. `attest-dependence --suite-cmd "<command>" --suite-junit <report>` covers that route with any runner (the runner supplies the disable strategy; the command runs the tests): pairs are grouped by mechanism, and for each distinct mechanism the mechanism is disabled (same compile/lint gate, same byte-exact restore), the suite command runs once, and the report it wrote gives every nominated test naming that mechanism its outcome: `passed`, `failed`, or `error` from the report as they are (an errored test did not pass, so it counts as dependence); a test the report skipped is `error` with reason `skipped under mutation`; a test absent from the report is `error` with reason `not in report`; a command that wrote no report is `error` with reason `no report` for every pair on that mechanism, as is a failed gate. `--timeout` applies per suite run and `--total-timeout` across mechanisms; a mechanism that would start after the budget records its pairs as not run. The result is the same `kind: "dependence"` attestation, so verification reads it unchanged. A stale report is removed before each run so an old one can never be read as this run's.

**Strategy B: hook-instrumented build (`--strategy hook`).** The mutation strategy above recompiles once per mechanism. A compiled codebase that would rather build once can place a *tripwire* inside each mechanism instead, and `attest-dependence --strategy hook` (also `attest-reach --strategy hook`) builds once with the tripwires compiled in, then runs each nominated test with its mechanism named. The contract, stated exactly:

- The tripwire goes **inside the mechanism's own body**, and nowhere else: never in a test helper, a fixture, `TestMain`, a constructor the tests share, or a module initialiser. It is gated out of production builds by a build flag (Go build tag `mipiti_hooks`, Rust feature `mipiti_hooks`, C/C++ `MIPITI_HOOKS`, Swift `MIPITI_HOOKS`, Verilog `` `MIPITI_HOOKS ``, a VHDL generic); Java and Kotlin have no build-time gate, so their check is compiled always and is inert unless the variable is set.
- It reads `MIPITI_DISABLE_MECHANISM` (a plusarg or generic for HDL) and, **only when the value equals its own mechanism id**, aborts with a message that carries `mipiti-hook <file>::<symbol> at <file>:<line>`, where `<file>:<line>` is the tripwire's own position. Any other value, including unset, is a no-op.
- The verifier runs the go runner as `go test -c -tags mipiti_hooks` (one test binary per package, built once), cargo as `cargo test --no-run --features mipiti_hooks`, and the command runner as `--build-cmd` once (with `-DMIPITI_HOOKS`, `+define+MIPITI_HOOKS`, or whatever the build takes) then `--run-cmd` per pair with `{test}` and `{mechanism}` substituted and the variable set. No source is rewritten and the tree need not be clean. pytest, jest, vitest and mocha refuse `--strategy hook` with a reason: they disable at runtime already.

Why the placement rule: a tripwire in a helper every test calls fires for every test, and one placed next to the mechanism rather than in it fires for tests that never reached the mechanism. Either would credit dependence the tests do not have. Two checks make a misplaced tripwire visible instead of credited, and both are recorded in the attestation:

1. **Location proof.** A failing run is credited as dependence only when its output carries the marker for *this* mechanism and the marker's `<file>:<line>` falls inside the mechanism's exactly located definition (the same `symbol` scope the mutation strategy requires). A test that failed without the marker records `error` with reason `test failed without the hook firing` (it could be any failure); a marker outside the span or in another file records `error` with reason `hook fired outside the mechanism`, one for another mechanism `a hook for a different mechanism fired`. The location is recorded on the `fails_without` entry as `hook_location`.
2. **Control run.** Before any pair, every nominated test runs once with `MIPITI_DISABLE_MECHANISM=mipiti-control-<random>`. Every test must pass. Any failure records `error` with reason `hook fires unconditionally (control run failed)` for every pair and the run stops. The run is recorded at the predicate level as `control_run: {status, mechanism, tests}`, and the record carries `strategy: "hook"`.

Helper snippets, one per language (these are the whole helper; there is no library to install):

```go
// hooks_on.go
//go:build mipiti_hooks

package guard

import ("fmt"; "os"; "runtime")

// Tripwire aborts when MIPITI_DISABLE_MECHANISM names this mechanism.
func Tripwire(id string) {
	if os.Getenv("MIPITI_DISABLE_MECHANISM") != id {
		return
	}
	_, file, line, _ := runtime.Caller(1)
	panic(fmt.Sprintf("mipiti-hook %s at %s:%d", id, file, line))
}

// hooks_off.go
//go:build !mipiti_hooks

package guard

func Tripwire(string) {}

// in the mechanism:
func RequireToken(t string) bool {
	Tripwire("internal/auth/guard.go::RequireToken")
	...
}
```

```rust
#[cfg(feature = "mipiti_hooks")]
macro_rules! mipiti_tripwire {
    ($id:expr) => {
        if std::env::var("MIPITI_DISABLE_MECHANISM").as_deref() == Ok($id) {
            panic!("mipiti-hook {} at {}:{}", $id, file!(), line!());
        }
    };
}
#[cfg(not(feature = "mipiti_hooks"))]
macro_rules! mipiti_tripwire { ($id:expr) => {}; }

pub fn require_token(t: &str) -> bool {
    mipiti_tripwire!("src/guard.rs::require_token");
    ...
}
```

```c
/* mipiti_hooks.h */
#ifdef MIPITI_HOOKS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define MIPITI_TRIPWIRE(id) do { const char *v = getenv("MIPITI_DISABLE_MECHANISM"); \
    if (v && strcmp(v, (id)) == 0) { fprintf(stderr, "mipiti-hook %s at %s:%d\n", (id), __FILE__, __LINE__); abort(); } } while (0)
#else
#define MIPITI_TRIPWIRE(id) do {} while (0)
#endif

int require_token(const char *t) {
    MIPITI_TRIPWIRE("src/guard.c::require_token");
    ...
}
```

```java
// No build-time gate in Java or Kotlin: compiled always, inert unless the variable is set.
final class MipitiHooks {
    static void tripwire(String id) {
        if (!id.equals(System.getenv("MIPITI_DISABLE_MECHANISM"))) return;
        StackTraceElement at = new Throwable().getStackTrace()[1];
        throw new IllegalStateException("mipiti-hook " + id + " at " + at.getFileName() + ":" + at.getLineNumber());
    }
}
```

```swift
@inline(__always) func mipitiTripwire(_ id: String, file: StaticString = #file, line: UInt = #line) {
    #if MIPITI_HOOKS
    if ProcessInfo.processInfo.environment["MIPITI_DISABLE_MECHANISM"] == id {
        fatalError("mipiti-hook \(id) at \(file):\(line)")
    }
    #endif
}
```

```verilog
// inside the module, compiled with +define+MIPITI_HOOKS; the run passes +MIPITI_DISABLE_MECHANISM=<id>
`ifdef MIPITI_HOOKS
  string mipiti_target;
  initial if ($value$plusargs("MIPITI_DISABLE_MECHANISM=%s", mipiti_target) && mipiti_target == "rtl/alu.sv::module:alu")
    $fatal(1, "mipiti-hook rtl/alu.sv::module:alu at %s:%0d", `__FILE__, `__LINE__);
`endif
```

```vhdl
-- a generic on the entity, set by the simulator (-gMIPITI_DISABLE_MECHANISM=<id>); inside the architecture:
assert MIPITI_DISABLE_MECHANISM /= "rtl/alu.vhd::architecture:rtl"
  report "mipiti-hook rtl/alu.vhd::architecture:rtl at rtl/alu.vhd:" & integer'image(42) severity failure;
```

For a Java file the marker's `<file>` is the bare source file name; the location proof accepts a marker whose path ends with the mechanism's file. Reach under `--strategy hook` runs each test alone under coverage against the same build with the variable unset.

**Suite mode: reach from a whole-suite run.** `attest-reach --suite-cmd "<command>" --coverage-file <report>` runs the suite ONCE under coverage and reads the report (any accepted format). Every nominated test records the lines the suite executed in its mechanism's file as `suite_reached`, and the record carries `reach_scope: "suite"`; each entry's `status` is the command's exit (`passed` on 0), a command that could not run or wrote no report is `error` with the reason for every pair. This is stated exactly for what it is: per-test reach is undefined for a harness that cannot run one test alone, so suite mode records suite reach as information and never credits reach. Only per-test `attest-reach` establishes the fact.

```bash
# Verilator or Icarus harness whose Makefile runs every testbench and writes JUnit:
# one make per mechanism, the RTL mutated and linted first
mipiti-verify attest-dependence --suite-cmd "make sim JUNIT=out.xml" --suite-junit out.xml \
  --pair 'tb_alu_overflow=rtl/alu.sv::module:alu' \
  --pair 'tb_fsm_reset=rtl/fsm.sv::always:seq_logic'
```

**Examples.**

```bash
# Go: go test -run selects the test; go build checks the mutated tree; reach through -coverprofile
mipiti-verify attest-dependence --pair 'internal/auth::TestRequiresToken=internal/auth/guard.go::RequireToken'
mipiti-verify attest-reach      --pair 'internal/auth::TestRequiresToken=internal/auth/guard.go::RequireToken'

# jest: file::test name; the export is mocked for the run
mipiti-verify attest-dependence --pair 'src/auth.test.ts::rejects a missing token=src/auth.ts::requireToken'
mipiti-verify attest-reach      --pair 'src/auth.test.ts::rejects a missing token=src/auth.ts::Auth.check'

# cocotb driven by a Makefile: the command runner, the RTL mutated and linted with whichever of verilator / slang / iverilog is installed
mipiti-verify attest-dependence --run-cmd 'make -C sim sim TESTCASE={test}' \
  --pair 'test_alu_overflow=rtl/alu.sv::module:alu'

# Verilator harness: coverage written by the run and converted to LCOV, then read for the one test
mipiti-verify attest-reach --run-cmd 'make -C sim run TEST={test}' \
  --coverage-cmd 'make -C sim run TEST={test} COVERAGE=1 && verilator_coverage --write-info sim/coverage.info sim/coverage.dat' \
  --coverage-file sim/coverage.info \
  --pair 'test_alu_overflow=rtl/alu.sv::always:alu_ff'
```

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
| `junit-report` | No | `""` | JUnit XML report(s) your test step wrote, relative to `project-root`; recorded as a signed test-result attestation before verifying |
| `attestation-env` | No | `""` | Environment variable names the attestation records |
| `attestation-signing-key` | No | `""` | ECDSA P-256 key (PEM) to sign attestations on CI without a workload identity |
| `coverage-report` | No | `""` | coverage.py JSON export with contexts, relative to `project-root`; passed to `attest-tests --coverage` so each test records what it reached |
| `dependence-pairs` | No | `""` | Space-separated `test=file::symbol` pairs. When set, the action runs `attest-dependence` before verifying. **Runs those tests** with the mechanism disabled through the project's runner; opt-in |
| `reach-pairs` | No | `""` | Space-separated `test=file::symbol` pairs. When set, the action runs `attest-reach` before verifying: each test alone under coverage. **Runs those tests**; opt-in |
| `runner` | No | `""` | Runner adapter for the two inputs above (`pytest`, `jest`, `vitest`, `mocha`, `go`, `cargo`, `maven`, `gradle`, `dotnet`, `rspec`, `phpunit`, `command`); default detected from the project's files |
| `run-cmd` | No | `""` | Command that runs one test (`{test}` substituted) for the `command` runner; setting it selects that runner |
| `coverage-cmd` | No | `""` | Command that runs one test under coverage for the `command` runner (defaults to `run-cmd`) |
| `coverage-file` | No | `""` | Report the coverage command writes, relative to `project-root`, for the `command` runner; with `suite-cmd`, the report the suite run writes |
| `suite-cmd` | No | `""` | Suite mode, for a harness that cannot select one test. `dependence-pairs`: command that runs the whole suite and writes a JUnit report; run once per mechanism with it disabled (needs `suite-junit`). `reach-pairs`: the command runs once under coverage and must write `coverage-file`; suite-level reach is recorded as `suite_reached` (`reach_scope: suite`) and never establishes per-test reach |
| `suite-junit` | No | `""` | The JUnit report `suite-cmd` writes, relative to `project-root` |
| `strategy` | No | `mutation` | `mutation` or `hook` for `dependence-pairs` / `reach-pairs`; `hook` builds once with the repository's build-flagged tripwires compiled in (see Strategy B) |
| `build-cmd` | No | `""` | The build with the hooks compiled in, for the `command` runner under strategy `hook` |

### Action Output

| Output | Description |
|--------|-------------|
| `content-hash` | SHA-256 hash of verified assertions (`sha256:<hex>`). Use with `actions/attest-build-provenance` for Sigstore attestation. |

## Two-Tier Verification

**Tier 1 (Mechanical)** — <!--ASSERTION_TYPE_COUNT-->28<!--/ASSERTION_TYPE_COUNT--> typed assertion checks, deterministic code analysis, no external API calls. No assertion type executes project code:
- `function_exists`, `class_exists`, `decorator_present`, `function_calls`
- `pattern_matches`, `pattern_absent`, `import_present`
- `file_exists`, `file_hash`
- `config_key_exists`, `config_value_matches`
- `dependency_exists`, `dependency_version`
- `test_attested`, `test_exists`
- `env_var_referenced`, `error_handled`
- `no_plaintext_secret`, `middleware_registered`, `http_header_set`
- `module_exists`, `module_instantiated`, `port_exists`, `parameter_defined`, `signal_exists`, `sva_assertion_present`, `register_reset` (RTL/Verilog)

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

Proprietary. Copyright (c) 2026 Mipiti, Inc. All rights reserved. See [LICENSE](LICENSE) for details.
