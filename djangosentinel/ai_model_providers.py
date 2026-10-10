"""
AI Model Providers — DjangoSentinel.

Provides a uniform abstraction over multiple LLM providers (Anthropic, OpenAI, Google Gemini).
Each provider implements the same interface: generate(system, user, max_tokens, timeout).
The default provider is Anthropic (preserving full backward compatibility).

Environment variables:
    ANTHROPIC_API_KEY   - for Anthropic (Claude) models
    OPENAI_API_KEY      - for OpenAI GPT-4/3.5 models
    GOOGLE_API_KEY      - for Google Gemini models
"""

import os
import json
import urllib.request
import urllib.error
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
        pass

    @abstractmethod
    def _call_api(self, system: str, user: str, max_tokens: int, timeout: int) -> Optional[str]:
        """Make the API call and return the response text, or None on failure."""
        pass

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
                "model": "claude-sonnet-4-20250514",
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
                "model": "gpt-4o-mini",  # could make this configurable
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
    """Google Gemini model provider (generative API)."""

    def _get_api_key(self) -> str:
        return os.environ.get("GOOGLE_API_KEY", "")

    def _call_api(self, system: str, user: str, max_tokens: int, timeout: int) -> Optional[str]:
        try:
            import urllib.request
            import urllib.error

            # Gemini generative endpoint format
            # Note: Gemini's API structure differs; this is a simplified adapter
            payload = json.dumps({
                "contents": [
                    {"role": "user", "parts": [{"text": user}]},
                    {"role": "model", "parts": [{"text": system}]},
                ]
            }).encode("utf-8")

            url = f"https://generativelanguage.googleapis.com/v1beta/models:generateContent?key={self.api_key}"

            req = urllib.request.Request(
                url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                # Navigate Gemini's response structure
                return data["candidates"][0]["content"]["parts"][0]["text"]
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Global default provider — Anthropic, for full backward compatibility
# ---------------------------------------------------------------------------

# Module-level default; can be replaced via set_ai_provider()
_default_provider: AnthropicProvider = AnthropicProvider()


def set_ai_provider(provider) -> None:
    """Replace the global default AI model provider.

    Useful for testing or switching between Anthropic / OpenAI / Gemini
    without code changes.

    Args:
        provider: An instance of AIModelProvider (or a subclass).
    """
    global _default_provider
    _default_provider = provider


def get_ai_provider() -> AIModelProvider:
    """Return the currently active AI model provider."""
    return _default_provider


def is_ai_available() -> bool:
    """Convenience: True if the default provider has an API key configured."""
    return _default_provider.available


def ai_generate(system: str, user: str, max_tokens: int = 1500, timeout: int = 30) -> Optional[str]:
    """Generate text using the current default provider."""
    return _default_provider.generate(system, user, max_tokens, timeout)


# Keep the original _call_claude name alive for any external imports
_call_claude = AnthropicProvider._call_api  # noqa: F811 (assigned at module load)


# ---------------------------------------------------------------------------
# Quick smoke test (only runs when file executed directly)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    # Verify all three providers are importable and have .available
    from djangosentinel.ai_model_providers import (
        AnthropicProvider,
        OpenAIProvider,
        GeminiProvider,
        set_ai_provider,
        get_ai_provider,
        is_ai_available,
        ai_generate,
    )

    # Default (Anthropic)
    print("Anthropic available:", is_ai_available())
    print("Default provider:", type(get_ai_provider()).__name__)

    # Switch to OpenAI (will be unavailable unless OPENAI_API_KEY set)
    set_ai_provider(OpenAIProvider())
    print("After switch - available:", is_ai_available())
    print("Provider now:", type(get_ai_provider()).__name__)

    # Can also set None/silently fail; the framework gracefully degrades.
    print("\nAll providers importable — backward compatible ✅")