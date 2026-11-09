"""LLM client protocols, Gemini client with lazy SDK loading, and deterministic test fakes."""

import logging
import os
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger("sentinelx.llm.client")


@runtime_checkable
class LLMClient(Protocol):
    """Protocol for LLM generation clients."""

    def generate(self, prompt: str, system_instruction: str, timeout: float = 8.0) -> str:
        """Generate response text from prompt and system instruction within timeout seconds."""
        ...


class GeminiClient:
    """Production client for Google Gemini models using the official google-genai SDK.

    Lazy loads the SDK on first invocation so import-time overhead is zero and environments
    without google-genai can run unit tests and template fallbacks safely.
    """

    def __init__(self, api_key: str | None = None, model: str | None = None):
        self._api_key = api_key or os.environ.get("GEMINI_API_KEY")
        self.model = model or os.environ.get("GEMINI_MODEL")
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is None:
            if not self._api_key:
                raise ValueError(
                    "GEMINI_API_KEY is not configured. Set GEMINI_API_KEY in the untracked environment."
                )
            if not self.model:
                raise ValueError(
                    "GEMINI_MODEL is not configured. Set GEMINI_MODEL (e.g. 'gemini-3.8-flash')."
                )
            try:
                from google import genai

                # Initialize client without logging secret key
                self._client = genai.Client(api_key=self._api_key)
            except ImportError as exc:
                raise ImportError(
                    f"google-genai SDK is not installed in the environment: {exc}"
                ) from exc
        return self._client

    def generate(self, prompt: str, system_instruction: str, timeout: float = 8.0) -> str:
        """Call Gemini model with structured output configuration."""
        client = self._get_client()

        try:
            from google.genai import types

            # google-genai client requires minimum 10s deadline
            deadline_ms = max(int(timeout * 1000), 10000)
            http_options = types.HttpOptions(timeout=deadline_ms)
            config = types.GenerateContentConfig(
                response_mime_type="application/json",
                system_instruction=system_instruction,
                temperature=0.1,
                http_options=http_options,
            )

            response = client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=config,
            )

            if not response.text:
                raise ValueError("Gemini returned an empty response.")
            return response.text
        except Exception as exc:
            # Safe logging: never format or log self._api_key
            logger.warning("Gemini generation failed on model '%s': %s", self.model, exc)
            raise


class FakeLLMClient:
    """Deterministic, network-free test double for unit and safety testing."""

    def __init__(
        self,
        default_response: str | None = None,
        responses: list[str] | None = None,
        raise_error: Exception | None = None,
    ):
        self.default_response = (
            default_response or '{"headline": "Test Security Incident", "claims": []}'
        )
        self.responses = list(responses) if responses else []
        self.raise_error = raise_error
        self.call_history: list[dict[str, Any]] = []

    def generate(self, prompt: str, system_instruction: str, timeout: float = 8.0) -> str:
        if self.raise_error is not None:
            raise self.raise_error

        self.call_history.append(
            {
                "prompt": prompt,
                "system_instruction": system_instruction,
                "timeout": timeout,
            }
        )

        if self.responses:
            return self.responses.pop(0)
        return self.default_response
