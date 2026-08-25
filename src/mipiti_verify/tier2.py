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
``| untrusted`` Jinja filter. The subject of the evaluation — a
repository file, or the model's feature description — is a
runner-chosen value and is rendered outside the boundary too, so a
template can frame its criterion for the thing actually being read.

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

# Subject of a tier-2 evaluation. An assertion is normally verified
# against a repository file, but some types may instead be verified
# against platform-held content — today the model's feature
# description, which is the design specification the threat model is
# derived from. The two subjects are read differently: a regex match
# in a repository file is code, while a regex match in a feature
# description is a design statement, so the per-type criterion the
# template states must name the right one. The runner resolves the
# subject when it loads the content and passes it down; everything
# that does not specify one is evaluated as a repository file, which
# is the pre-existing behaviour.
SUBJECT_REPOSITORY_FILE = "repository_file"
SUBJECT_FEATURE_DESCRIPTION = "feature_description"

_SUBJECT_LABELS: Mapping[str, str] = {
    SUBJECT_REPOSITORY_FILE: "the repository file under verification",
    SUBJECT_FEATURE_DESCRIPTION: (
        "the model's feature description, which is the design "
        "specification for the system"
    ),
}


def subject_label(subject_kind: str) -> str:
    """Human-readable name for a subject kind.

    Unrecognised kinds fall back to the repository-file label so an
    unexpected value degrades to the historical framing rather than
    handing the reviewer an unnamed subject.
    """
    return _SUBJECT_LABELS.get(subject_kind, _SUBJECT_LABELS[SUBJECT_REPOSITORY_FILE])


class Tier2Provider(ABC):
    """Abstract base for Tier 2 semantic verification providers."""

    @abstractmethod
    def evaluate(
        self,
        *,
        assertion_type: str,
        assertion_params: Mapping[str, Any],
        source_code: str = "",
        subject_kind: str = SUBJECT_REPOSITORY_FILE,
    ) -> Tuple[bool, str]:
        """Evaluate an assertion semantically.

        Returns ``(passed, reasoning)``. The runner picks the per-type
        template, renders it with a fresh boundary token, and submits
        the rendered message to the configured LLM provider.

        ``subject_kind`` names what ``source_code`` actually is (see
        the ``SUBJECT_*`` constants) so the template can state a
        criterion in the right terms. It defaults to the repository
        file, so a caller that does not set it gets the behaviour it
        got before the subject was modelled explicitly.
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
        subject_kind: str = SUBJECT_REPOSITORY_FILE,
    ) -> Tuple[bool, str]:
        message = _build_message(
            assertion_type=assertion_type,
            assertion_params=assertion_params,
            source_code=source_code,
            subject_kind=subject_kind,
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
        subject_kind: str = SUBJECT_REPOSITORY_FILE,
    ) -> Tuple[bool, str]:
        content = _build_message(
            assertion_type=assertion_type,
            assertion_params=assertion_params,
            source_code=source_code,
            subject_kind=subject_kind,
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
        subject_kind: str = SUBJECT_REPOSITORY_FILE,
    ) -> Tuple[bool, str]:
        content = _build_message(
            assertion_type=assertion_type,
            assertion_params=assertion_params,
            source_code=source_code,
            subject_kind=subject_kind,
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
    subject_kind: str = SUBJECT_REPOSITORY_FILE,
) -> str:
    """Build the LLM input message via runner-side template rendering.

    The runner loads ``templates/tier2_<assertion_type>.j2`` and
    renders it with a fresh per-call boundary token. The instruction
    preamble lives in the template (trusted runner code) and sits
    outside the boundary; ``assertion_params`` and ``source_code``
    are wrapped inside via the ``| untrusted`` filter.

    ``subject_kind`` and its derived label describe what the
    ``SOURCE_CODE`` payload is. Both are runner-chosen values, not
    payload data, so they are rendered OUTSIDE the boundary as part of
    the trusted instruction text. Templates that branch on the subject
    use them to state the per-type criterion in the terms of the thing
    actually being read.

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
    params = dict(assertion_params) if assertion_params else {}
    if subject_kind != SUBJECT_REPOSITORY_FILE:
        # The subject is platform-held content, which the caller has
        # already handed us as ``source_code`` — it is rendered below
        # as SOURCE_CODE. The same text also rides in the params as
        # ``target_content``; rendering it there too would show the
        # reviewer identical bytes under two different labels and
        # double the prompt for a long specification. Drop only that
        # one key: the pattern, the target name, any scoping and flags
        # are what the reviewer needs and are left exactly as they
        # arrived. This changes the prompt only — the stored params,
        # what tier 1 evaluated, and any hash taken over them are
        # untouched.
        params.pop("target_content", None)
    params_json = json.dumps(
        params,
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
            "SUBJECT_KIND": subject_kind,
            "SUBJECT_LABEL": subject_label(subject_kind),
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
