"""
Backward-compatibility shim.

The real Gemini adapter now lives at `ai/providers/gemini_provider.py`.
This file exists so old imports like:

    from ai.gemini import GeminiProvider

keep working. New code should import from the new location.
"""
from ai.providers.gemini_provider import GeminiProvider

__all__ = ["GeminiProvider"]