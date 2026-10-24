"""Choose the model backend from settings."""

from __future__ import annotations

from hipaa_audit.assess.llm import AnthropicBackend, HeuristicBackend, LLMBackend
from hipaa_audit.config import Settings


def make_backend(settings: Settings) -> LLMBackend:
    if settings.llm_backend == "heuristic":
        return HeuristicBackend()
    return AnthropicBackend(api_key=settings.anthropic_api_key, model=settings.model, effort=settings.effort)
