"""Model backends.

* ``AnthropicBackend`` asks Claude to call one tool per control (``record_assessment``) and parses it. The request follows the
  Claude Sonnet 5.5 rules: ``tool_choice`` is ``auto`` with a ``strict`` tool (that model rejects forced tool use with a 400),
  and no sampling parameters are sent (it rejects ``temperature``, ``top_p`` and ``top_k``).
* ``HeuristicBackend`` is an offline keyword matcher for demos, tests and CI. It is not an AI model and is labelled that way
  wherever its output appears.

Backends only produce a ``RawAssessment``. Checking the quotes and applying the downgrade rules happens in ``verify.finalize``
so it applies equally to every backend.
"""

from __future__ import annotations

import logging
import math
import re
from typing import Any, Protocol

from hipaa_audit.assess.prompts import SYSTEM_PROMPT, build_user_message
from hipaa_audit.assess.schema import TOOL_NAME, TOOL_SPEC, RawAssessment, RawEvidence
from hipaa_audit.catalog import Control, Criterion
from hipaa_audit.models import Chunk, Usage
from hipaa_audit.retrieval.text import tokenize

log = logging.getLogger(__name__)

_SENTENCES = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9(\"'])|\n+")


class LLMError(RuntimeError):
    """Base class for backend failures."""


class LLMAuthError(LLMError):
    """The key was rejected or the request was not permitted. Retrying cannot help."""


class LLMUnavailable(LLMError):
    """The service could not be reached or kept failing after the client's own retries."""


class LLMFormatError(LLMError):
    """The model did not return a usable tool call."""


RETRY_REMINDER = "Your previous answer could not be used. Respond only by calling the record_assessment tool, once."


class LLMBackend(Protocol):
    name: str

    async def assess(self, control: Control, excerpts: list[Chunk]) -> tuple[RawAssessment, Usage]: ...


def _usage(response: Any) -> Usage:
    u = getattr(response, "usage", None)
    return Usage(
        input_tokens=getattr(u, "input_tokens", 0) or 0,
        output_tokens=getattr(u, "output_tokens", 0) or 0,
        cache_read_tokens=getattr(u, "cache_read_input_tokens", 0) or 0,
        cache_creation_tokens=getattr(u, "cache_creation_input_tokens", 0) or 0,
    )


def _parse(response: Any) -> RawAssessment:
    if getattr(response, "stop_reason", None) == "max_tokens":
        raise LLMFormatError("the answer was cut off at the token limit")
    for block in getattr(response, "content", None) or []:
        if getattr(block, "type", None) == "tool_use" and getattr(block, "name", None) == TOOL_NAME:
            try:
                return RawAssessment.model_validate(block.input)
            except ValueError as exc:
                raise LLMFormatError(f"tool input did not match the schema: {exc}") from exc
    raise LLMFormatError(f"the response had no record_assessment tool call (stop_reason={getattr(response, 'stop_reason', None)})")


class AnthropicBackend:
    def __init__(
        self,
        *,
        api_key: str | None,
        model: str,
        max_tokens: int = 4096,
        timeout: float = 120.0,
        max_retries: int = 4,
        effort: str | None = "medium",
        client: Any = None,
    ) -> None:
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - depends on the environment
            raise RuntimeError("the anthropic package is not installed (pip install anthropic)") from exc
        if client is None and not api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not set. Set it in your environment or .env file, "
                "or use HIPAA_AUDIT_LLM_BACKEND=heuristic for an offline demo."
            )
        self._sdk = anthropic
        self.model = model
        self.name = f"anthropic:{model}"
        self._max_tokens = max_tokens  # covers thinking as well as the answer; the retry doubles it
        self._effort = effort
        # Transport retries (429, 5xx, connection errors) are handled by the SDK client itself.
        self._client = client or anthropic.AsyncAnthropic(api_key=api_key, timeout=timeout, max_retries=max_retries)

    def _request(self, user_message: str, attempt: int) -> dict[str, Any]:
        content = user_message if attempt == 1 else f"{user_message}\n\n{RETRY_REMINDER}"
        request: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self._max_tokens * attempt,
            "system": [{"type": "text", "text": SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}],
            "messages": [{"role": "user", "content": content}],
            "tools": [TOOL_SPEC],
            "tool_choice": {"type": "auto"},
        }
        if self._effort:  # passed through extra_body so SDK releases that predate the field still work
            request["extra_body"] = {"output_config": {"effort": self._effort}}
        return request

    async def assess(self, control: Control, excerpts: list[Chunk]) -> tuple[RawAssessment, Usage]:
        user_message = build_user_message(control, excerpts)
        total = Usage()
        last_error: Exception | None = None
        for attempt in (1, 2):  # a second attempt only for a malformed or truncated answer
            try:
                response = await self._client.messages.create(**self._request(user_message, attempt))
            except (self._sdk.AuthenticationError, self._sdk.PermissionDeniedError) as exc:
                raise LLMAuthError("the Anthropic API rejected the key, or the request was not permitted") from exc
            except self._sdk.APIError as exc:
                raise LLMUnavailable(f"Anthropic API error: {exc}") from exc
            total = total + _usage(response)
            try:
                return _parse(response), total
            except LLMFormatError as exc:
                last_error = exc
                log.warning("unusable answer for %s on attempt %d: %s", control.id, attempt, exc)
        raise LLMFormatError(f"no usable answer for {control.id}: {last_error}")


class HeuristicBackend:
    """Keyword matcher. For each expected element it looks for the sentence that contains most of the element's keywords."""

    name = "heuristic:keywords"

    def __init__(self, min_fraction: float = 0.5) -> None:
        self.min_fraction = min_fraction

    @staticmethod
    def _token_variants(keyword: str) -> list[set[str]]:
        variants = [set(tokenize(keyword))]
        if "-" in keyword:
            variants.append(set(tokenize(keyword.replace("-", ""))))
        return [v for v in variants if v]

    def _hits(self, criterion: Criterion, sentence: str) -> int:
        tokens = set(tokenize(sentence))
        return sum(any(v <= tokens for v in self._token_variants(kw)) for kw in criterion.keywords)

    def _best_sentence(self, criterion: Criterion, excerpts: list[Chunk]) -> tuple[str, str] | None:
        needed = max(2, math.ceil(len(criterion.keywords) * self.min_fraction))
        best: tuple[int, str, str] | None = None
        for chunk in excerpts:
            for sentence in _SENTENCES.split(chunk.text):
                sentence = sentence.strip()
                if not sentence:
                    continue
                hits = self._hits(criterion, sentence)
                if hits >= needed and (best is None or hits > best[0]):
                    best = (hits, chunk.id, sentence)
        return None if best is None else (best[1], best[2])

    async def assess(self, control: Control, excerpts: list[Chunk]) -> tuple[RawAssessment, Usage]:
        evidence: list[RawEvidence] = []
        missing: list[str] = []
        for criterion in control.criteria:
            found = self._best_sentence(criterion, excerpts)
            if found:
                evidence.append(RawEvidence(excerpt_id=found[0], quote=found[1]))
            else:
                missing.append(criterion.text)
        n, found_count = len(control.criteria), len(control.criteria) - len(missing)
        status = "met" if not missing else ("partial" if found_count else "gap")
        rationale = f"Keyword heuristic (not an AI model): {found_count} of {n} expected elements found."
        return (
            RawAssessment(status=status, rationale=rationale, evidence=evidence, missing_elements=missing, confidence=0.5),
            Usage(),
        )
