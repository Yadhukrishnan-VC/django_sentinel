"""
AI Model Providers — DjangoSentinel.

Provides a uniform abstraction over multiple LLM providers (Anthropic, OpenAI, Google Gemini).
Each provider implements the same interface: generate(system, user, max_tokens, timeout).

Provider selection (see select_provider):
    1. SENTINEL_AI_PROVIDER = anthropic | openai | gemini   (explicit choice), else
    2. the first provider that has an API key, in the order Anthropic, OpenAI, Gemini.

Environment variables:
    ANTHROPIC_API_KEY   - for Anthropic (Claude) models     (model: ANTHROPIC_MODEL)
    OPENAI_API_KEY      - for OpenAI GPT models             (model: OPENAI_MODEL)
    GOOGLE_API_KEY      - for Google Gemini models          (model: GEMINI_MODEL)
"""

import os
import json
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from typing import Optional


class AIModelProvider(ABC):
    """Abstract base for AI model providers."""

    def __init__(self):
        self.api_key = self._get_api_key()
        self.available = bool(self.api_key)

    @abstractmethod
    def _get_api_key(self) -> str:
        """Retrieve the API key from environment / configuration."""

    @abstractmethod
    def _call_api(self, system: str, user: str, max_tokens: int, timeout: int) -> Optional[str]:
        """Make the API call and return the response text, or None on failure."""

    def generate(self, system: str, user: str, max_tokens: int = 1500, timeout: int = 30) -> Optional[str]:
        """Public entry point: return None if unavailable, else API result."""
        if not self.available:
            return None
        try:
            return self._call_api(system, user, max_tokens, timeout)
        except Exception:
            return None


class AnthropicProvider(AIModelProvider):
    """Anthropic Claude model provider."""

    def _get_api_key(self) -> str:
        return os.environ.get("ANTHROPIC_API_KEY", "")

    def _call_api(self, system: str, user: str, max_tokens: int, timeout: int) -> Optional[str]:
        try:
            import urllib.request
            import urllib.error

            payload = json.dumps({
                "model": os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-20250514"),
                "max_tokens": max_tokens,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            }).encode("utf-8")

            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                },
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data["content"][0]["text"]
        except Exception:
            return None


class OpenAIProvider(AIModelProvider):
    """OpenAI GPT model provider (Chat Completions API)."""

    def _get_api_key(self) -> str:
        return os.environ.get("OPENAI_API_KEY", "")

    def _call_api(self, system: str, user: str, max_tokens: int, timeout: int) -> Optional[str]:
        try:
            import urllib.request
            import urllib.error

            # OpenAI Chat Completions expects messages as [{"role": "system", "content": ...}, ...]
            # We'll prepend system to the user message approach for compatibility
            messages = []
            if system.strip():
                messages.append({"role": "system", "content": system})
            messages.append({"role": "user", "content": user})

            payload = json.dumps({
                "model": os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": 0.0,
            }).encode("utf-8")

            req = urllib.request.Request(
                "https://api.openai.com/v1/chat/completions",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.api_key}",
                },
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data["choices"][0]["message"]["content"]
        except Exception:
            return None


class GeminiProvider(AIModelProvider):
    """Google Gemini model provider (Generative Language REST API)."""

    DEFAULT_MODEL = "gemini-2.5-flash"

    def _get_api_key(self) -> str:
        return os.environ.get("GOOGLE_API_KEY", "")

    def _call_api(self, system: str, user: str, max_tokens: int, timeout: int) -> Optional[str]:
        try:
            model = os.environ.get("GEMINI_MODEL", self.DEFAULT_MODEL)
            body = {
                "contents": [{"role": "user", "parts": [{"text": user}]}],
                "generationConfig": {"maxOutputTokens": max_tokens, "temperature": 0.0},
            }
            if system.strip():
                body["systemInstruction"] = {"parts": [{"text": system}]}

            req = urllib.request.Request(
                f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
                data=json.dumps(body).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    # key in a header (not the URL) so it never appears in logs
                    "x-goog-api-key": self.api_key,
                },
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data["candidates"][0]["content"]["parts"][0]["text"]
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Provider selection and the global default provider
# ---------------------------------------------------------------------------

_PROVIDERS = {
    "anthropic": AnthropicProvider,
    "claude": AnthropicProvider,
    "openai": OpenAIProvider,
    "gemini": GeminiProvider,
    "google": GeminiProvider,
}


def select_provider() -> AIModelProvider:
    """
    Pick the AI provider from the environment.

    SENTINEL_AI_PROVIDER (anthropic | openai | gemini) wins when set;
    otherwise the first provider with an API key is used, in the order
    Anthropic, OpenAI, Gemini. With no keys at all an (unavailable)
    Anthropic provider is returned, so AI features degrade gracefully.
    """
    wanted = os.environ.get("SENTINEL_AI_PROVIDER", "").strip().lower()
    if wanted in _PROVIDERS:
        return _PROVIDERS[wanted]()
    for cls in (AnthropicProvider, OpenAIProvider, GeminiProvider):
        provider = cls()
        if provider.available:
            return provider
    return AnthropicProvider()


# Module-level default; replace via set_ai_provider(), re-read env via refresh_ai_provider()
_default_provider: AIModelProvider = select_provider()


def set_ai_provider(provider) -> None:
    """Replace the global default AI model provider (e.g. in tests)."""
    global _default_provider
    _default_provider = provider


def refresh_ai_provider() -> AIModelProvider:
    """Re-select the default provider from the current environment."""
    global _default_provider
    _default_provider = select_provider()
    return _default_provider


def get_ai_provider() -> AIModelProvider:
    """Return the currently active AI model provider."""
    return _default_provider


def is_ai_available() -> bool:
    """True if the default provider has an API key configured."""
    return _default_provider.available


def ai_generate(system: str, user: str, max_tokens: int = 1500, timeout: int = 30) -> Optional[str]:
    """Generate text using the current default provider."""
    return _default_provider.generate(system, user, max_tokens, timeout)
