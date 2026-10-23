"""The check of a design proof bundle: the archive a model's behavioural
model is downloaded as, with every obligation and what decides it, the
certificates and proofs that decide them, and a manifest signed by the
platform over every file's hash.

``read`` opens the archive safely (regular files under
``design-proof-bundle/`` only, no path leaving it, bounded in size), then
``check``:

- the signature over ``manifest.json``, by the key ``signature.json``
  embeds, which must be the key the caller trusts (the platform's JWKS, or a
  key the auditor holds);
- every file the manifest names, by its hash, and no file it does not name;
- the coverage the manifest states, counted again from ``obligations.json``;
- each obligation a certificate or proof decides: the certificate and proof
  it names are in the bundle, of that obligation and its kind, with their
  texts in the files the bundle holds them in; an objective satisfied by
  design rests only on obligations so decided;
- each certificate and proof before anything runs, and with ``recheck`` the
  checkers on each (``behavioural.recheck_certificate``,
  ``behavioural.recheck_proof``), all of them or a seeded sample.

Nothing in the bundle is run: not ``recheck.sh``, not a command it names.
Every command is built here.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import random
import tarfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Optional

from . import behavioural as B

#: The bundle format this verifier reads.
FORMAT = 2
ROOT = "design-proof-bundle/"
#: Bounds on what is read: a bundle past them is refused, not read in part.
MAX_FILES = 20_000
MAX_BYTES = 512 * 1024 * 1024

#: How an obligation is decided, as ``obligations.json`` states it.
CERTIFIED = "certified"
PROVED = "proved"
TO_JUDGE = "to_judge"
NOT_EVALUATED = "not_evaluated"
DECIDED_BY = (CERTIFIED, PROVED, TO_JUDGE, NOT_EVALUATED)


def pinned_image() -> str:
    """The tools image this release re-checks with, by digest, or ``""``
    when none is pinned (``design_check_image.json``, written when the image
    built from ``design-check/`` is published)."""
    from importlib import resources

    try:
        pin = json.loads(resources.files(__package__).joinpath(
            "design_check_image.json").read_text())
    except (OSError, ValueError):
        return ""
    image = pin.get("image") if isinstance(pin, dict) else ""
    return image if isinstance(image, str) and "@sha256:" in image else ""


class BundleError(Exception):
    """The archive cannot be read as a design proof bundle."""


@dataclass
class Bundle:
    files: dict  # path under the bundle's directory -> bytes

    def json(self, name: str):
        try:
            return json.loads(self.files[name])
        except KeyError:
            raise BundleError(f"the bundle holds no {name}") from None
        except ValueError as e:
            raise BundleError(f"{name} is not JSON: {e}") from None

    def text(self, name: str) -> Optional[str]:
        data = self.files.get(name)
        return data.decode("utf-8") if data is not None else None

    @property
    def manifest(self) -> dict:
        return self.json("manifest.json")

    @property
    def signature(self) -> dict:
        return self.json("signature.json")


@dataclass
class Result:
    manifest: dict = field(default_factory=dict)
    #: What does not hold up: the bundle is refused when any is listed.
    problems: list = field(default_factory=list)
    #: The key the manifest was signed with, its fingerprint.
    key_fingerprint: str = ""
    coverage: dict = field(default_factory=dict)
    objectives: dict = field(default_factory=dict)
    #: The re-checks, one per certificate and proof checked.
    rechecks: list = field(default_factory=list)
    #: The obligations a sample left out, when sampled.
    not_sampled: int = 0
    tools_missing: dict = field(default_factory=dict)

    @property
    def failed(self) -> bool:
        return bool(self.problems) or any(r.status == B.FAILED for r in self.rechecks)

    def count(self, status: str, kind: Optional[str] = None) -> int:
        return sum(1 for r in self.rechecks
                   if r.status == status and (kind is None or r.kind == kind))

    def unsettled(self) -> list:
        return [r for r in self.rechecks if r.status in (B.NOT_RECHECKED, B.MISSING)]


def read(data: bytes) -> Bundle:
    """The bundle's files from the archive's bytes. Raises
    :class:`BundleError` for an archive that is not a bundle: a member that is
    not a regular file, a path outside ``design-proof-bundle/`` or leaving
    it, a name twice, or more than the bounds."""
    try:
        tar = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
    except (tarfile.TarError, OSError, EOFError) as e:
        raise BundleError(f"not a gzip tar archive: {e}") from None
    files: dict = {}
    total = 0
    with tar:
        for i, member in enumerate(tar):
            if i >= MAX_FILES:
                raise BundleError(f"more than {MAX_FILES} members")
            name = member.name
            if not member.isreg():
                raise BundleError(f"{name!r} is not a regular file")
            if not name.startswith(ROOT) or name.startswith("/"):
                raise BundleError(f"{name!r} is outside {ROOT}")
            rel = name[len(ROOT):]
            parts = rel.split("/")
            if not rel or any(p in ("", ".", "..") for p in parts) or "\\" in rel:
                raise BundleError(f"{name!r} is not a plain path in the bundle")
            if rel in files:
                raise BundleError(f"{name!r} appears twice")
            total += member.size
            if total > MAX_BYTES:
                raise BundleError(f"more than {MAX_BYTES} bytes")
            fh = tar.extractfile(member)
            files[rel] = fh.read() if fh is not None else b""
    return Bundle(files)


def fingerprint(public_key) -> str:
    """The hex SHA-256 of a public key's DER SubjectPublicKeyInfo: the
    fingerprint the platform's JWKS names its keys by."""
    from cryptography.hazmat.primitives import serialization

    return hashlib.sha256(public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def embedded_fingerprint(bundle: Bundle) -> str:
    """The fingerprint ``signature.json`` names, to look the trusted key up
    by."""
    value = bundle.signature.get("key_fingerprint")
    return value if isinstance(value, str) else ""


def _check_signature(bundle: Bundle, trusted_key, result: Result) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    sig = bundle.signature
    if sig.get("algorithm") != "ECDSA-P256-SHA256" or sig.get("signed") != "manifest.json":
        result.problems.append("signature.json is not an ECDSA P-256 signature of "
                               "manifest.json")
        return
    try:
        embedded = serialization.load_pem_public_key(str(sig.get("public_key_pem")).encode())
        der = base64.b64decode(str(sig.get("signature_der_b64")), validate=True)
    except (ValueError, TypeError) as e:
        result.problems.append(f"signature.json cannot be read: {e}")
        return
    result.key_fingerprint = fingerprint(embedded)
    if result.key_fingerprint != sig.get("key_fingerprint"):
        result.problems.append("the embedded key is not the key the fingerprint names")
        return
    if trusted_key is None or fingerprint(trusted_key) != result.key_fingerprint:
        result.problems.append("the manifest is signed by a key other than the platform's")
        return
    try:
        trusted_key.verify(der, bundle.files["manifest.json"], ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        result.problems.append("the signature does not verify over manifest.json")


def _check_files(bundle: Bundle, manifest: dict, result: Result) -> None:
    named = manifest.get("files")
    if not isinstance(named, dict):
        result.problems.append("the manifest names no files")
        return
    for name, digest in sorted(named.items()):
        data = bundle.files.get(name)
        if data is None:
            result.problems.append(f"{name} is named by the manifest and not in the bundle")
        elif hashlib.sha256(data).hexdigest() != digest:
            result.problems.append(f"{name} does not hash to what the manifest names")
    extra = sorted(set(bundle.files) - set(named) - {"manifest.json", "signature.json"})
    for name in extra:
        result.problems.append(f"{name} is in the bundle and not named by the manifest")


def _rows(value, what: str, result: Result) -> list:
    if not isinstance(value, list) or not all(isinstance(r, dict) for r in value):
        result.problems.append(f"{what} is not a list of records")
        return []
    return value


def _assemble(bundle: Bundle, result: Result) -> tuple:
    """``(obligations, certificates, proofs)`` by id and key, each
    certificate and proof with its texts read from the files the bundle
    holds them in, every disagreement recorded on ``result``."""
    obligations = {}
    for o in _rows(bundle.json("obligations.json"), "obligations.json", result):
        ob = o.get("obligation")
        decided = o.get("decided") if isinstance(o.get("decided"), dict) else {}
        if not isinstance(ob, str) or ob in obligations or decided.get("by") not in DECIDED_BY:
            result.problems.append(f"obligation {ob!r} is not stated once with how it is "
                                   "decided")
            continue
        obligations[ob] = o
    certificates = {}
    for c in _rows(bundle.json("certificates.json"), "certificates.json", result):
        key = str(c.get("key_hash") or "")
        name = str(c.get("module_name") or "")
        module = bundle.text(f"modules/{key}/{name}.tla")
        inv_name = B._module_name(str(c.get("invariant") or ""))
        invariant = bundle.text(f"modules/{key}/{inv_name}.tla")
        if not key or key in certificates or module is None or invariant != c.get("invariant"):
            result.problems.append(f"certificate {key[:16] or '?'}: its module and invariant "
                                   "are not in the bundle as listed")
            continue
        certificates[key] = {**c, "module_text": module}
    proofs = {}
    for p in _rows(bundle.json("proofs.json"), "proofs.json", result):
        key = str(p.get("key_hash") or "")
        name = str(p.get("module_name") or "")
        module = bundle.text(f"proofs/{key}/{name}.tla")
        text = bundle.text(f"proofs/{key}/{B._module_name(str(p.get('proof_text') or ''))}.tla")
        if not key or key in proofs or module is None or text != p.get("proof_text"):
            result.problems.append(f"proof {key[:16] or '?'}: its module and proof are not "
                                   "in the bundle as listed")
            continue
        proofs[key] = {**p, "module_text": module}
    return obligations, certificates, proofs


def _check_decisions(obligations: dict, certificates: dict, proofs: dict,
                     objectives: dict, result: Result) -> list:
    """The obligations a certificate or proof decides, each with them:
    ``[(obligation, certificate, proof or None)]``."""
    decided = []
    used_certs, used_proofs = set(), set()
    for ob, o in sorted(obligations.items()):
        d = o["decided"]
        if d["by"] not in (CERTIFIED, PROVED):
            continue
        cert = certificates.get(str(d.get("certificate") or ""))
        if cert is None or cert.get("obligation_id") != ob:
            result.problems.append(f"{ob}: decided {d['by']} and the bundle holds no "
                                   "certificate of it")
            continue
        if cert.get("kind") != o.get("kind"):
            result.problems.append(f"{ob}: its certificate is of another kind "
                                   f"({cert.get('kind')!r}, not {o.get('kind')!r})")
            continue
        proof = None
        if d["by"] == PROVED:
            proof = proofs.get(str(d.get("proof") or ""))
            if proof is None or proof.get("obligation_id") != ob or \
                    proof.get("certificate") != cert["key_hash"]:
                result.problems.append(f"{ob}: decided proved and the bundle holds no proof "
                                       "of its certificate")
                continue
            used_proofs.add(proof["key_hash"])
        used_certs.add(cert["key_hash"])
        decided.append((ob, cert, proof))
    for key in sorted(set(certificates) - used_certs):
        result.problems.append(f"certificate {key[:16]} decides no obligation")
    for key in sorted(set(proofs) - used_proofs):
        result.problems.append(f"proof {key[:16]} decides no obligation")
    for co_id, obj in sorted(objectives.items()):
        obs = obj.get("obligations") if isinstance(obj, dict) else None
        if not isinstance(obs, list):
            result.problems.append(f"objective {co_id} lists no obligations")
            continue
        missing = [ob for ob in obs if ob not in obligations]
        if missing:
            result.problems.append(f"objective {co_id} names obligations the bundle does "
                                   f"not state: {', '.join(map(str, missing))}")
        if obj.get("standing") == "satisfied_by_design" and any(
                obligations.get(ob, {}).get("decided", {}).get("by") not in (CERTIFIED, PROVED)
                for ob in obs):
            result.problems.append(f"objective {co_id} is stated satisfied by design and "
                                   "rests on an obligation no certificate decides")
    return decided


def check(bundle: Bundle, trusted_key, *, recheck: bool = False, tools=None,
          timeout: float = 600.0, jobs: int = 1, sample: int = 0,
          seed: Optional[int] = None) -> Result:
    """Everything the bundle states, checked; with ``recheck`` the checkers
    run on every certificate and proof through ``tools``, or on those of
    ``sample`` obligations drawn with ``seed``."""
    result = Result()
    try:
        manifest = bundle.manifest
    except BundleError as e:
        result.problems.append(str(e))
        return result
    result.manifest = manifest
    if manifest.get("format") != FORMAT:
        result.problems.append(f"the bundle is format {manifest.get('format')!r}; this "
                               f"verifier reads format {FORMAT}")
        return result
    try:
        _check_signature(bundle, trusted_key, result)
    except BundleError as e:
        result.problems.append(str(e))
    _check_files(bundle, manifest, result)
    if result.problems:
        return result
    try:
        obligations, certificates, proofs = _assemble(bundle, result)
        objectives = bundle.json("objectives.json")
    except BundleError as e:
        result.problems.append(str(e))
        return result
    if not isinstance(objectives, dict):
        result.problems.append("objectives.json is not a record of objectives")
        objectives = {}
    result.objectives = objectives
    by = [o["decided"]["by"] for o in obligations.values()]
    result.coverage = {"obligations": len(by), **{k: by.count(k) for k in DECIDED_BY}}
    if result.coverage != manifest.get("coverage"):
        result.problems.append("the coverage the manifest states is not what "
                               "obligations.json gives")
    decided = _check_decisions(obligations, certificates, proofs, objectives, result)
    if sample and sample < len(decided):
        chosen = sorted(random.Random(seed).sample(range(len(decided)), sample))
        result.not_sampled = len(decided) - sample
        decided = [decided[i] for i in chosen]

    def one(item):
        _ob, cert, proof = item
        out = [B.recheck_certificate(cert, tools if recheck else None, timeout)]
        if proof is not None:
            out.append(B.recheck_proof(proof, cert, tools if recheck else None, timeout))
        return out

    with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        for rechecks in pool.map(one, decided):
            result.rechecks += rechecks
    return result


__all__ = ["Bundle", "BundleError", "FORMAT", "Result", "check", "embedded_fingerprint",
           "fingerprint", "read"]
