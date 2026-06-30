"""Gemini API wrapper for structured scam analysis.

Uses the official google-genai SDK to query Gemini models with structured
Pydantic schemas, ensuring type-safe and consistent structured analysis.
"""
import os
from typing import Type, TypeVar
from pydantic import BaseModel, Field

# Graceful import of google-genai SDK
try:
    from google import genai
    from google.genai import types
    _HAS_GENAI = True
except ImportError:
    _HAS_GENAI = False

T = TypeVar("T", bound=BaseModel)


class ScamVerdictSchema(BaseModel):
    score: int = Field(
        description="Scam risk score from 0 (completely safe) to 100 (guaranteed scam)"
    )
    verdict: str = Field(
        description="Scam verdict: HIGH_RISK_SCAM, LIKELY_SCAM, SUSPICIOUS, or LIKELY_SAFE"
    )
    reasoning: str = Field(
        description="A clear and brief explanation of the key reasons behind the score and verdict."
    )
    red_flags: list[str] = Field(
        description="Specific red flags, phrases, lookalike domains, or scam strategies identified."
    )


class GeminiAnalyzer:
    """Helper to query the Gemini API with structured outputs."""

    def __init__(self, model_name: str = "gemini-2.5-flash"):
        self.model_name = model_name
        self.api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        self.client = None

        if _HAS_GENAI and self.api_key:
            # Initialize client with the API key explicitly or implicitly
            self.client = genai.Client(api_key=self.api_key)

    @property
    def is_enabled(self) -> bool:
        """Return True if google-genai is installed and an API key is available."""
        return _HAS_GENAI and self.client is not None

    def analyze(self, prompt: str, schema: Type[T] = ScamVerdictSchema) -> T | None:
        """
        Query Gemini with a prompt and retrieve structured response matching `schema`.

        Returns None if not enabled or on API failure.
        """
        if not self.is_enabled or not self.client:
            return None

        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=schema,
                    temperature=0.1,  # Low temperature for highly deterministic analysis
                ),
            )
            # Parse the JSON string into the Pydantic model
            if response.text:
                return schema.model_validate_json(response.text)
        except Exception:
            # Gracefully fail and let system fall back to rule-based analysis
            pass
        return None
