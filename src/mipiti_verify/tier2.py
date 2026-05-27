"""Tier 2 AI provider abstraction for semantic verification.

Single-path runner-side rendering. The caller passes ``assertion_type``
+ ``assertion_params``; the runner loads the matching per-type Jinja
template from ``templates/`` and renders it locally via the vendored
``_prompt_renderer``. A fresh boundary token is minted at the call
site (in ``_prompt_renderer._mint_boundary_token``), used once for
that one render, and discarded. The token never crosses the network
and is never persisted. The instruction preamble lives in the
templates (trusted runner code) and sits outside the boundary;
assertion params and source code are wrapped inside via the
``| untrusted`` Jinja filter.

There is no legacy fallback. The runner refuses to evaluate when the
backend payload is missing ``type`` / ``params``, returning a clear
version-mismatch error rather than degrading to a less-defended path.
"""

from __future__ import annotations

import json
import os
import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Mapping, Tuple

# Resolve the templates directory once at import time. The package
# layout is ``mipiti_verify/templates/tier2_<type>.j2`` and we read
# templates via the filesystem (not importlib.resources) so the
# vendored Jinja Environment can render from a string. importlib
# would work too, but this is simpler given templates are tiny.
_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


class Tier2Provider(ABC):
    """Abstract base for Tier 2 semantic verification providers."""

    @abstractmethod
    def evaluate(
        self,
        *,
        assertion_type: str,
        assertion_params: Mapping[str, Any],
        source_code: str = "",
    ) -> Tuple[bool, str]:
        """Evaluate an assertion semantically.

        Returns ``(passed, reasoning)``. The runner picks the per-type
        template, renders it with a fresh boundary token, and submits
        the rendered message to the configured LLM provider.
        """


class OpenAIProvider(Tier2Provider):
    """Tier 2 provider using OpenAI API."""

    def __init__(self, model: str | None = None, api_key: str | None = None) -> None:
        try:
            from openai import OpenAI
        except ImportError:
            raise ImportError("openai package required: pip install mipiti-verify[openai]")

        self.model = model or "gpt-4o"
        self.client = OpenAI(api_key=api_key or os.environ.get("OPENAI_API_KEY"))

    def evaluate(
        self,
        *,
        assertion_type: str,
        assertion_params: Mapping[str, Any],
        source_code: str = "",
    ) -> Tuple[bool, str]:
        message = _build_message(
            assertion_type=assertion_type,
            assertion_params=assertion_params,
            source_code=source_code,
        )
        messages = [{"role": "user", "content": message}]
        # Newer OpenAI models (o-series, gpt-5+) require max_completion_tokens
        # instead of max_tokens.  Try the new param first, fall back on error.
        try:
            resp = self.client.chat.completions.create(
                model=self.model, messages=messages, temperature=0,
            )
        except Exception:
            resp = self.client.chat.completions.create(
                model=self.model, messages=messages, temperature=0,
            )
        text = resp.choices[0].message.content or ""
        return _parse_response(text)


class AnthropicProvider(Tier2Provider):
    """Tier 2 provider using Anthropic API."""

    def __init__(self, model: str | None = None, api_key: str | None = None) -> None:
        try:
            import anthropic
        except ImportError:
            raise ImportError("anthropic package required: pip install mipiti-verify[anthropic]")

        self.model = model or "claude-sonnet-4-5-20250514"
        self.client = anthropic.Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))

    def evaluate(
        self,
        *,
        assertion_type: str,
        assertion_params: Mapping[str, Any],
        source_code: str = "",
    ) -> Tuple[bool, str]:
        content = _build_message(
            assertion_type=assertion_type,
            assertion_params=assertion_params,
            source_code=source_code,
        )
        message = self.client.messages.create(
            model=self.model,
            max_tokens=8192,  # Anthropic requires max_tokens; high ceiling, model finishes naturally
            messages=[{"role": "user", "content": content}],
        )
        text = message.content[0].text if message.content else ""
        return _parse_response(text)


class OllamaProvider(Tier2Provider):
    """Tier 2 provider using local Ollama instance."""

    def __init__(
        self,
        model: str | None = None,
        ollama_url: str = "http://localhost:11434",
    ) -> None:
        import httpx
        from ._tls import tls_context

        self.model = model or "llama3.1"
        self.url = ollama_url.rstrip("/")
        self._client = httpx.Client(
            timeout=httpx.Timeout(connect=10.0, read=300.0),
            verify=tls_context(),
        )

    def evaluate(
        self,
        *,
        assertion_type: str,
        assertion_params: Mapping[str, Any],
        source_code: str = "",
    ) -> Tuple[bool, str]:
        content = _build_message(
            assertion_type=assertion_type,
            assertion_params=assertion_params,
            source_code=source_code,
        )
        resp = self._client.post(
            f"{self.url}/api/chat",
            json={
                "model": self.model,
                "messages": [{"role": "user", "content": content}],
                "stream": False,
                "options": {"temperature": 0},
            },
        )
        resp.raise_for_status()
        text = resp.json().get("message", {}).get("content", "")
        return _parse_response(text)


def get_provider(
    name: str,
    model: str | None = None,
    api_key: str | None = None,
    ollama_url: str = "http://localhost:11434",
) -> Tier2Provider:
    """Factory to get a Tier 2 provider by name."""
    name = name.lower()
    if name == "openai":
        return OpenAIProvider(model=model, api_key=api_key)
    elif name == "anthropic":
        return AnthropicProvider(model=model, api_key=api_key)
    elif name == "ollama":
        return OllamaProvider(model=model, ollama_url=ollama_url)
    else:
        raise ValueError(f"Unknown Tier 2 provider: {name}. Choose: openai, anthropic, ollama")


class UnknownAssertionTypeError(ValueError):
    """Raised when the assertion ``type`` has no matching tier-2 template.

    Surfaces a clear "the runner does not know how to evaluate this
    type semantically" error instead of silently degrading. Operators
    upgrading the platform ahead of the runner will see this and know
    to upgrade the runner.
    """


def _build_message(
    *,
    assertion_type: str,
    assertion_params: Mapping[str, Any],
    source_code: str = "",
) -> str:
    """Build the LLM input message via runner-side template rendering.

    The runner loads ``templates/tier2_<assertion_type>.j2`` and
    renders it with a fresh per-call boundary token. The instruction
    preamble lives in the template (trusted runner code) and sits
    outside the boundary; ``assertion_params`` and ``source_code``
    are wrapped inside via the ``| untrusted`` filter.

    Raises :class:`UnknownAssertionTypeError` when no template exists
    for the given type — the runner refuses to evaluate rather than
    falling back to a less-defended path.
    """
    template_path = _TEMPLATES_DIR / f"tier2_{assertion_type}.j2"
    if not template_path.is_file():
        raise UnknownAssertionTypeError(
            f"No tier 2 template for assertion type {assertion_type!r}. "
            "The runner does not know how to evaluate this type "
            "semantically. Upgrade mipiti-verify to a release that "
            "ships a template for this type."
        )
    from ._prompt_renderer import render_prompt

    template_text = template_path.read_text(encoding="utf-8")
    params_json = json.dumps(
        dict(assertion_params) if assertion_params else {},
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    )
    return render_prompt(
        template_text,
        {
            "ASSERTION_TYPE": assertion_type,
            "ASSERTION_PARAMS": params_json,
            "SOURCE_CODE": source_code,
        },
    )


def _parse_response(text: str) -> Tuple[bool, str]:
    """Parse YES/NO or PASS/FAIL from AI response.

    Returns (passed, reasoning).
    """
    text = text.strip()
    first_line = text.split("\n", 1)[0].strip().upper()
    reasoning = text.split("\n", 1)[1].strip() if "\n" in text else text

    if re.match(r"^(YES|PASS|VERIFIED|COHERENT|SUFFICIENT)\b", first_line):
        return True, reasoning
    if re.match(r"^(NO|FAIL|FAILED|NOT\s+VERIFIED|INCOHERENT|INSUFFICIENT)\b", first_line):
        return False, reasoning
    if "INJECTION_DETECTED" in first_line:
        return False, "Prompt injection detected in assertion content."

    # Ambiguous — fail safe
    return False, f"Ambiguous response: {text[:200]}"
