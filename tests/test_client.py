"""Tests for the Mipiti API client."""

import json

import httpx
import pytest
import respx

from mipiti_verify.client import MipitiClient


class TestMipitiClient:
    def test_init_requires_api_key(self):
        with pytest.raises(ValueError, match="MIPITI_API_KEY"):
            MipitiClient(api_key="")

    def test_init_with_api_key(self):
        client = MipitiClient(api_key="test-key", base_url="https://test.example.com")
        assert client.api_key == "test-key"
        assert client.base_url == "https://test.example.com"
        client.close()

    def test_init_strips_trailing_slash(self):
        client = MipitiClient(api_key="test-key", base_url="https://test.example.com/")
        assert client.base_url == "https://test.example.com"
        client.close()

    @respx.mock
    def test_get_pending_tier1(self):
        payload = {
            "model_id": "m1",
            "tier": 1,
            "controls": {
                "CTRL-01": [{"id": "asrt_001", "type": "function_exists"}],
            },
        }
        respx.get("https://test.example.com/api/models/m1/verification/pending").mock(
            return_value=httpx.Response(200, json=payload)
        )
        client = MipitiClient(api_key="test-key", base_url="https://test.example.com")
        result = client.get_pending("m1", tier=1)
        assert result["controls"]["CTRL-01"][0]["type"] == "function_exists"
        client.close()

    @respx.mock
    def test_get_pending_tier2(self):
        payload = {"model_id": "m1", "tier": 2, "controls": {}}
        respx.get("https://test.example.com/api/models/m1/verification/pending").mock(
            return_value=httpx.Response(200, json=payload)
        )
        client = MipitiClient(api_key="test-key", base_url="https://test.example.com")
        result = client.get_pending("m1", tier=2)
        assert result["controls"] == {}
        client.close()

    @respx.mock
    def test_submit_results(self):
        respx.post("https://test.example.com/api/models/m1/verification/results").mock(
            return_value=httpx.Response(200, json={"run_id": "run_123", "results_count": 2})
        )
        client = MipitiClient(api_key="test-key", base_url="https://test.example.com")
        result = client.submit_results(
            "m1",
            pipeline={"provider": "local"},
            results=[
                {"assertion_id": "asrt_001", "tier": 1, "result": "pass", "details": "ok"},
            ],
        )
        assert result["run_id"] == "run_123"
        client.close()

    @respx.mock
    def test_submit_results_with_bundle(self):
        route = respx.post("https://test.example.com/api/models/m1/verification/results").mock(
            return_value=httpx.Response(200, json={"run_id": "run_456", "results_count": 1})
        )
        client = MipitiClient(api_key="test-key", base_url="https://test.example.com")
        client.submit_results(
            "m1",
            pipeline={"provider": "github_actions"},
            results=[],
            bundle='{"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3", "verificationMaterial": {}}',
        )
        body = json.loads(route.calls[0].request.content)
        assert body["bundle"].startswith("{"), "bundle should be in the body, not a header"
        assert route.calls[0].request.headers.get("X-CI-Attestation") is None, (
            "legacy raw-token header must not be sent"
        )
        client.close()

    @respx.mock
    def test_get_model(self):
        respx.get("https://test.example.com/api/models/m1").mock(
            return_value=httpx.Response(200, json={"id": "m1", "title": "Test"})
        )
        client = MipitiClient(api_key="test-key", base_url="https://test.example.com")
        result = client.get_model("m1")
        assert result["id"] == "m1"
        client.close()

    @respx.mock
    def test_get_verification_report(self):
        payload = {"model_id": "m1", "total_assertions": 5, "tier1": {"pass": 3, "fail": 2}}
        respx.get("https://test.example.com/api/models/m1/verification/report").mock(
            return_value=httpx.Response(200, json=payload)
        )
        client = MipitiClient(api_key="test-key", base_url="https://test.example.com")
        result = client.get_verification_report("m1")
        assert result["total_assertions"] == 5
        client.close()

    @respx.mock
    def test_context_manager(self):
        with MipitiClient(api_key="test-key", base_url="https://test.example.com") as client:
            assert client.api_key == "test-key"
