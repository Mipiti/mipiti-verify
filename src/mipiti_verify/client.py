"""Synchronous HTTP client for the Mipiti verification API."""

from __future__ import annotations

import os
from typing import Any

import httpx

DEFAULT_BASE_URL = "https://api.mipiti.io"


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
        self._client = httpx.Client(
            base_url=self.base_url,
            headers={"X-API-Key": self.api_key},
            timeout=httpx.Timeout(connect=10.0, read=120.0, write=10.0, pool=10.0),
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

        Returns ``{"model_id": ..., "tier": ..., "controls": {ctrl_id: [assertions]}}``
        """
        params: dict[str, Any] = {"tier": tier, "stale_after": stale_after}
        if repo:
            params["repo"] = repo
        resp = self._client.get(
            f"/api/models/{model_id}/verification/pending",
            params=params,
        )
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # All assertions (for --reverify mode)
    # ------------------------------------------------------------------

    def get_all_assertions(self, model_id: str, repo: str = "") -> dict[str, Any]:
        """GET /api/models/{id}/verification/assertions?repo={r}

        Returns ``{"model_id": ..., "controls": {ctrl_id: [assertions]}}``
        """
        params: dict[str, Any] = {}
        if repo:
            params["repo"] = repo
        resp = self._client.get(
            f"/api/models/{model_id}/verification/assertions",
            params=params,
        )
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Submit results
    # ------------------------------------------------------------------

    def submit_results(
        self,
        model_id: str,
        pipeline: dict[str, Any],
        results: list[dict[str, Any]],
        oidc_token: str = "",
        signature: str = "",
        signed_hash: str = "",
    ) -> dict[str, Any]:
        """POST /api/models/{id}/verification/results"""
        body: dict[str, Any] = {
            "pipeline": pipeline,
            "results": results,
        }
        if signature:
            body["signature"] = signature
        if signed_hash:
            body["signed_hash"] = signed_hash

        headers: dict[str, str] = {}
        if oidc_token:
            headers["X-CI-Attestation"] = oidc_token

        resp = self._client.post(
            f"/api/models/{model_id}/verification/results",
            json=body,
            headers=headers,
        )
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Model listing (for --all mode)
    # ------------------------------------------------------------------

    def list_models(self) -> list[dict[str, Any]]:
        """GET /api/models — list models accessible by this API key's workspace."""
        resp = self._client.get("/api/models")
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Model / controls info (for context)
    # ------------------------------------------------------------------

    def get_model(self, model_id: str) -> dict[str, Any]:
        """GET /api/models/{id} — full model with controls."""
        resp = self._client.get(f"/api/models/{model_id}")
        resp.raise_for_status()
        return resp.json()

    def get_controls(self, model_id: str) -> list[dict[str, Any]]:
        """GET /api/models/{id}/controls — returns list of controls."""
        resp = self._client.get(f"/api/models/{model_id}/controls")
        resp.raise_for_status()
        data = resp.json()
        return data.get("controls", [])

    def get_verification_report(self, model_id: str) -> dict[str, Any]:
        """GET /api/models/{id}/verification/report"""
        resp = self._client.get(f"/api/models/{model_id}/verification/report")
        resp.raise_for_status()
        return resp.json()

    def get_verification_config(self) -> dict[str, Any]:
        """GET /api/verification/config — fetch attestation audience etc."""
        resp = self._client.get("/api/verification/config")
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Evidence sufficiency (CI pull + submit)
    # ------------------------------------------------------------------

    def get_pending_sufficiency(self, model_id: str) -> dict[str, Any]:
        """GET /api/models/{id}/verification/pending-sufficiency

        Returns ``{"model_id": ..., "controls": {ctrl_id: {control_description, assertion_count, sufficiency_prompt}}}``
        """
        resp = self._client.get(
            f"/api/models/{model_id}/verification/pending-sufficiency"
        )
        resp.raise_for_status()
        return resp.json()

    def submit_sufficiency_results(
        self,
        model_id: str,
        pipeline: dict[str, Any],
        results: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """POST /api/models/{id}/verification/sufficiency-results"""
        resp = self._client.post(
            f"/api/models/{model_id}/verification/sufficiency-results",
            json={"pipeline": pipeline, "results": results},
        )
        resp.raise_for_status()
        return resp.json()
