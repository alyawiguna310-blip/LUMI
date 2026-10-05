"""
Backward-compatibility shim.

Old code imported `FallbackProvider` from `ai.fallback`. New code should
use `ai.provider_manager.ProviderManager` directly — it does everything
`FallbackProvider` did, plus health tracking, cooldowns, and error
classification.

This shim exists so existing imports don't break.
"""
from ai.provider_manager import ProviderManager

# Old name — alias it so any leftover `from ai.fallback import FallbackProvider`
# still resolves.
FallbackProvider = ProviderManager

__all__ = ["FallbackProvider", "ProviderManager"]