"""
Backward-compatibility shim.

The real Hugging Face adapter now lives at `ai/providers/hf_provider.py`.
This file exists so old imports like:

    from ai.huggingface import HuggingFaceProvider

keep working. New code should import from the new location.
"""
from ai.providers.hf_provider import HuggingFaceProvider

__all__ = ["HuggingFaceProvider"]