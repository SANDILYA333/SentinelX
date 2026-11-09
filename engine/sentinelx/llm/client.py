"""LLM client protocols, Gemini client with lazy SDK loading, and deterministic test fakes."""

import logging
import os
import time
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

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        thinking_budget: int = 0,
    ):
        self._api_key = api_key or os.environ.get("GEMINI_API_KEY")
        self.model = model or os.environ.get("GEMINI_MODEL") or "gemini-3.5-flash"
        self.thinking_budget = thinking_budget
        self._client: Any = None
        self.last_duration_seconds: float = 0.0
        self.last_raw_response: str | None = None
        self.last_usage_metadata: dict[str, int] | None = None
        self.hit_timeout: bool = False
        self.last_error: str | None = None

    def _get_client(self) -> Any:
        if self._client is None:
            if not self._api_key:
                raise ValueError(
                    "GEMINI_API_KEY is not configured. Set GEMINI_API_KEY in the untracked environment."
                )
            if not self.model:
                raise ValueError(
                    "GEMINI_MODEL is not configured. Set GEMINI_MODEL (e.g. 'gemini-3.5-flash')."
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
        t0 = time.perf_counter()
        self.hit_timeout = False
        self.last_error = None

        try:
            from google.genai import types

            # google-genai client requires minimum 10s deadline
            deadline_ms = max(int(timeout * 1000), 10000)
            http_options = types.HttpOptions(timeout=deadline_ms)
            thinking_config = types.ThinkingConfig(thinking_budget=self.thinking_budget)

            config = types.GenerateContentConfig(
                response_mime_type="application/json",
                system_instruction=system_instruction,
                temperature=0.1,
                thinking_config=thinking_config,
                http_options=http_options,
            )

            response = client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=config,
            )

            self.last_duration_seconds = time.perf_counter() - t0
            self.last_raw_response = response.text

            if hasattr(response, "usage_metadata") and response.usage_metadata:
                self.last_usage_metadata = {
                    "prompt_token_count": getattr(response.usage_metadata, "prompt_token_count", 0)
                    or 0,
                    "candidates_token_count": getattr(
                        response.usage_metadata, "candidates_token_count", 0
                    )
                    or 0,
                    "total_token_count": getattr(response.usage_metadata, "total_token_count", 0)
                    or 0,
                }

            if not response.text:
                raise ValueError("Gemini returned an empty response.")
            return response.text
        except Exception as exc:
            self.last_duration_seconds = time.perf_counter() - t0
            err_msg = str(exc)
            self.last_error = err_msg
            if "DEADLINE_EXCEEDED" in err_msg or "timeout" in err_msg.lower():
                self.hit_timeout = True
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
        model: str = "fake-model",
        thinking_budget: int = 0,
    ):
        self.default_response = (
            default_response or '{"headline": "Test Security Incident", "claims": []}'
        )
        self.responses = list(responses) if responses else []
        self.raise_error = raise_error
        self.call_history: list[dict[str, Any]] = []
        self.model = model
        self.thinking_budget = thinking_budget
        self.last_duration_seconds: float = 0.01
        self.last_raw_response: str | None = None
        self.last_usage_metadata: dict[str, int] | None = {
            "prompt_token_count": 100,
            "candidates_token_count": 50,
            "total_token_count": 150,
        }
        self.hit_timeout: bool = False
        self.last_error: str | None = None

    def generate(self, prompt: str, system_instruction: str, timeout: float = 8.0) -> str:
        if self.raise_error is not None:
            self.last_error = str(self.raise_error)
            if "timeout" in self.last_error.lower():
                self.hit_timeout = True
            raise self.raise_error

        self.call_history.append(
            {
                "prompt": prompt,
                "system_instruction": system_instruction,
                "timeout": timeout,
            }
        )

        resp = self.responses.pop(0) if self.responses else self.default_response
        self.last_raw_response = resp
        return resp
