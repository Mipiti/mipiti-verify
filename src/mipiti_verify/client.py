"""Synchronous HTTP client for the Mipiti verification API."""

from __future__ import annotations

import os
from typing import Any

import httpx

DEFAULT_BASE_URL = "https://api.mipiti.io"

# How much of the response body to surface in the diagnostic message on
# HTTP errors. Trimmed because some endpoints return verbose validation
# detail (e.g. FastAPI's 422 with per-field errors) and we don't want to
# spam CI logs, but enough to identify the root cause.
_ERROR_BODY_PREVIEW_CHARS = 2000


def _raise_for_status_with_body(resp: httpx.Response) -> None:
    """Drop-in replacement for ``resp.raise_for_status()`` that surfaces
    the response body in the raised exception.

    Stock httpx prints only the status line + URL on error, which makes
    diagnosing 4xx/5xx from the API painful — a 422 from FastAPI carries
    the failing field path and message in the body, but the default error
    swallows it. This helper preserves the same exception type
    (``httpx.HTTPStatusError``) so callers that catch it still work, but
    enriches the message with up to ``_ERROR_BODY_PREVIEW_CHARS`` of
    response content.
    """
    if not resp.is_error:
        return
    try:
        body = resp.text or "(empty body)"
    except Exception as e:
        body = f"(could not read body: {e})"
    if len(body) > _ERROR_BODY_PREVIEW_CHARS:
        body = body[:_ERROR_BODY_PREVIEW_CHARS] + " …(truncated)"
    raise httpx.HTTPStatusError(
        f"HTTP {resp.status_code} {resp.reason_phrase} for {resp.request.url}\n"
        f"Response body: {body}",
        request=resp.request,
        response=resp,
    )


class UnsafePath(ValueError):
    """A request path with a dot segment: an id that would move the request
    to another endpoint."""


def is_dot_segment(seg: str) -> bool:
    """Whether a path segment is a dot segment in any form a URL resolver
    reads as one: ``.`` or ``..``, with either dot written ``%2e`` (either
    case), and with any tab or newline deleted, as the WHATWG URL standard
    reads it (httpx does neither, but a proxy on the way may)."""
    read = seg.replace("\t", "").replace("\n", "").replace("\r", "")
    return read.lower().replace("%2e", ".") in (".", "..")


class _GuardedClient(httpx.Client):
    """An ``httpx.Client`` that refuses a request whose path has a dot
    segment before it is resolved. The paths interpolate ids (a model id from
    the configuration, ids the API returns), and httpx resolves dot segments:
    an id of ``..`` would move the request, with the key, to another endpoint
    than the one meant. No id is a dot segment, so nothing legitimate is
    refused; a guarded path resolves to itself (``tests/test_path_guard.py``
    drives this guard against httpx's own resolution)."""

    def build_request(self, method, url, *args, **kwargs):
        path = str(url).split("?", 1)[0].split("#", 1)[0]
        if any(is_dot_segment(seg) for seg in path.split("/")):
            raise UnsafePath(f"refused a request path with a dot segment: {path!r}")
        return super().build_request(method, url, *args, **kwargs)


class MipitiClient:
    """Sync httpx client for pulling pending assertions and submitting results."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
    ) -> None:
        self.api_key = api_key or os.environ.get("MIPITI_API_KEY", "")
        self.base_url = (
            base_url or os.environ.get("MIPITI_BASE_URL", DEFAULT_BASE_URL)
        ).rstrip("/")
        if not self.api_key:
            raise ValueError(
                "MIPITI_API_KEY is required. Set it as an environment variable "
                "or pass api_key= to MipitiClient."
            )
        self.key_scope = "verifier" if self.api_key.startswith("mv_") else "developer"
        from ._tls import tls_context
        self._client = _GuardedClient(
            base_url=self.base_url,
            headers={"X-API-Key": self.api_key},
            timeout=httpx.Timeout(connect=10.0, read=120.0, write=10.0, pool=10.0),
            verify=tls_context(),
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> MipitiClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Pending assertions (CI pull)
    # ------------------------------------------------------------------

    def get_pending(
        self, model_id: str, tier: int = 1, stale_after: int = 24, repo: str = "",
    ) -> dict[str, Any]:
        """GET /api/models/{id}/verification/pending?tier={t}&repo={r}

        Returns ``{"model_id": ..., "tier": ..., "controls": {ctrl_id: [assertions]}, "assumptions": {as_id: [assertions]}}``
        """
        params: dict[str, Any] = {"tier": tier, "stale_after": stale_after}
        if repo:
            params["repo"] = repo
        resp = self._client.get(
            f"/api/models/{model_id}/verification/pending",
            params=params,
        )
        _raise_for_status_with_body(resp)
        return resp.json()

    # ------------------------------------------------------------------
    # All assertions (for --reverify mode)
    # ------------------------------------------------------------------

    def get_all_assertions(self, model_id: str, repo: str = "") -> dict[str, Any]:
        """GET /api/models/{id}/verification/assertions?repo={r}

        Returns ``{"model_id": ..., "controls": {ctrl_id: [assertions]}, "assumptions": {as_id: [assertions]}}``
        """
        params: dict[str, Any] = {}
        if repo:
            params["repo"] = repo
        resp = self._client.get(
            f"/api/models/{model_id}/verification/assertions",
            params=params,
        )
        _raise_for_status_with_body(resp)
        return resp.json()

    # ------------------------------------------------------------------
    # Submit results
    # ------------------------------------------------------------------

    def submit_results(
        self,
        model_id: str,
        pipeline: dict[str, Any],
        results: list[dict[str, Any]],
        bundle: str = "",
        signature: str = "",
        signed_hash: str = "",
        content_hash: str = "",
        dsse_bundle: str = "",
    ) -> dict[str, Any]:
        """POST /api/models/{id}/verification/results

        CI-side attestation is carried by `bundle` — a Sigstore bundle (JSON-
        serialised, bundle_v0.3) minted locally from the runner's OIDC token.
        The raw token never leaves the runner; the backend verifies the bundle
        against the Sigstore transparency log.

        Self-hosted deployments without OIDC supply `signature` + `signed_hash`
        produced with a workspace ECDSA key instead.

        Air-gapped / non-Sigstore CI supplies `dsse_bundle` — a self-contained
        customer-keyed DSSE attestation (standard DSSE / in-toto, signed
        offline with the customer's ECDSA P-256 key). The backend verifies it
        against the customer's registered workspace public key and stores it
        opaquely in the audit envelope; no network at sign or verify time.
        """
        body: dict[str, Any] = {
            "pipeline": pipeline,
            "results": results,
            "content_hash": content_hash,
        }
        if bundle:
            body["bundle"] = bundle
        if signature:
            body["signature"] = signature
        if signed_hash:
            body["signed_hash"] = signed_hash
        if dsse_bundle:
            body["dsse_bundle"] = dsse_bundle

        resp = self._client.post(
            f"/api/models/{model_id}/verification/results",
            json=body,
        )
        _raise_for_status_with_body(resp)
        return resp.json()

    # ------------------------------------------------------------------
    # Model listing (for --all mode)
    # ------------------------------------------------------------------

    def list_models(self) -> list[dict[str, Any]]:
        """GET /api/models — list models accessible by this API key's workspace."""
        resp = self._client.get("/api/models")
        _raise_for_status_with_body(resp)
        return resp.json()

    # ------------------------------------------------------------------
    # Model / controls info (for context)
    # ------------------------------------------------------------------

    def get_model(self, model_id: str) -> dict[str, Any]:
        """GET /api/models/{id} — full model with controls."""
        resp = self._client.get(f"/api/models/{model_id}")
        _raise_for_status_with_body(resp)
        return resp.json()

    def get_controls(self, model_id: str, component_id: str = "") -> dict[str, Any]:
        """GET /api/models/{id}/controls — returns controls response dict."""
        params: dict[str, str] = {}
        if component_id:
            params["component_id"] = component_id
        resp = self._client.get(f"/api/models/{model_id}/controls", params=params)
        _raise_for_status_with_body(resp)
        return resp.json()

    def get_verification_report(self, model_id: str) -> dict[str, Any]:
        """GET /api/models/{id}/verification/report"""
        resp = self._client.get(f"/api/models/{model_id}/verification/report")
        _raise_for_status_with_body(resp)
        return resp.json()


