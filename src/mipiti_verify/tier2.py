"""Tier 2 AI provider abstraction for semantic verification."""

from __future__ import annotations

import os
import re
from abc import ABC, abstractmethod
from typing import Tuple


class Tier2Provider(ABC):
    """Abstract base for Tier 2 semantic verification providers."""

    @abstractmethod
    def evaluate(self, prompt: str, source_code: str) -> Tuple[bool, str]:
        """Evaluate an assertion semantically.

        Returns (passed, reasoning).
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

    def evaluate(self, prompt: str, source_code: str) -> Tuple[bool, str]:
        messages = [{"role": "user", "content": _build_message(prompt, source_code)}]
        resp = self.client.chat.completions.create(
            model=self.model, messages=messages, temperature=0, max_tokens=1000
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

    def evaluate(self, prompt: str, source_code: str) -> Tuple[bool, str]:
        message = self.client.messages.create(
            model=self.model,
            max_tokens=1000,
            messages=[{"role": "user", "content": _build_message(prompt, source_code)}],
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

        self.model = model or "llama3.1"
        self.url = ollama_url.rstrip("/")
        self._client = httpx.Client(timeout=httpx.Timeout(connect=10.0, read=300.0))

    def evaluate(self, prompt: str, source_code: str) -> Tuple[bool, str]:
        resp = self._client.post(
            f"{self.url}/api/chat",
            json={
                "model": self.model,
                "messages": [{"role": "user", "content": _build_message(prompt, source_code)}],
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


def _build_message(prompt: str, source_code: str) -> str:
    """Build the full prompt message with source code context."""
    if source_code:
        return f"{prompt}\n\n--- Source Code ---\n{source_code}"
    return prompt


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

    # Fallback: look for keywords anywhere in first line
    if any(w in first_line for w in ("YES", "PASS", "VERIFIED", "SUFFICIENT")):
        return True, reasoning
    if any(w in first_line for w in ("NO", "FAIL", "NOT", "INSUFFICIENT")):
        return False, reasoning

    # Ambiguous — fail safe
    return False, f"Ambiguous response: {text[:200]}"
