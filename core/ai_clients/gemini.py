"""Gemini API helper for query expansion."""

from __future__ import annotations

import os
from typing import Callable, Optional


def _load_google_genai():
    try:
        import google.generativeai as genai  # type: ignore
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise ImportError(
            "google-generativeai package is required to use the Gemini API. "
            "Install it via `pip install google-generativeai`."
        ) from exc
    return genai


def make_gemini_llm(
    model_name: str = "gemini-1.5-flash",
    *,
    api_key: Optional[str] = None,
    temperature: float = 0.2,
) -> Callable[[str], str]:
    """
    Return a callable(prompt:str)->str that queries the Gemini API.

    Parameters
    ----------
    model_name:
        Gemini model ID, e.g. "gemini-1.5-flash" or "gemini-1.5-pro".
    api_key:
        Google Generative AI API key. If None, read from environment variable
        `GEMINI_API_KEY`.
    temperature:
        Sampling temperature passed to the model.
    """

    key = api_key or os.environ.get("GEMINI_API_KEY")
    if not key:
        raise ValueError(
            "Gemini API key is required. Set GEMINI_API_KEY environment variable "
            "or pass api_key parameter."
        )

    genai = _load_google_genai()
    genai.configure(api_key=key, transport="rest")

    generation_config = {
        "temperature": temperature,
        "max_output_tokens": 256,
    }
    model = genai.GenerativeModel(model_name=model_name, generation_config=generation_config)

    def llm_callable(prompt: str) -> str:
        response = model.generate_content(prompt)
        if not response or not response.text:
            return ""
        return response.text.strip()

    return llm_callable
