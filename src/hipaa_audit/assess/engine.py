"""Runs the assessment of many controls against one indexed document.

For each control: retrieve excerpts (hybrid search over the control's queries), look the answer up in the cache, otherwise ask
the backend, then verify the quotes and apply the downgrade rules. Controls run concurrently up to a limit. One control failing
does not stop the others; a rejected API key stops everything.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Protocol

from hipaa_audit.assess.injection import scan_chunks
from hipaa_audit.assess.llm import LLMAuthError, LLMBackend, LLMError
from hipaa_audit.assess.prompts import PROMPT_VERSION
from hipaa_audit.assess.schema import RawAssessment
from hipaa_audit.assess.verify import finalize
from hipaa_audit.catalog import Control
from hipaa_audit.models import Chunk, Finding, Usage
from hipaa_audit.retrieval import HybridIndex

log = logging.getLogger(__name__)

FindingCallback = Callable[[Finding], Awaitable[None] | None]


class AssessmentCache(Protocol):
    def get(self, key: str) -> RawAssessment | None: ...

    def put(self, key: str, raw: RawAssessment) -> None: ...


class MemoryCache:
    """Process-lifetime cache. The service uses a SQLite-backed one with the same two methods."""

    def __init__(self) -> None:
        self._items: dict[str, RawAssessment] = {}

    def get(self, key: str) -> RawAssessment | None:
        return self._items.get(key)

    def put(self, key: str, raw: RawAssessment) -> None:
        self._items[key] = raw


@dataclass
class EngineResult:
    findings: list[Finding]  # catalog order
    usage: Usage = field(default_factory=Usage)
    injection_chunks: dict[str, list[str]] = field(default_factory=dict)  # chunk id -> pattern labels


def cache_key(backend_name: str, control: Control, excerpts: list[Chunk]) -> str:
    """Everything that can change the answer: prompt wording, model, the control's definition and the exact excerpt text."""
    h = hashlib.sha256()
    for part in (PROMPT_VERSION, backend_name, control.model_dump_json()):
        h.update(part.encode("utf-8"))
        h.update(b"\x00")
    for chunk in excerpts:
        h.update(f"{chunk.id}\x1f{chunk.page}\x1f{chunk.section}\x1f{chunk.text}\x00".encode())
    return h.hexdigest()


class AssessmentEngine:
    def __init__(
        self,
        backend: LLMBackend,
        index: HybridIndex,
        *,
        top_k: int = 6,
        concurrency: int = 4,
        cache: AssessmentCache | None = None,
    ) -> None:
        self.backend = backend
        self.index = index
        self.top_k = top_k
        self.concurrency = max(1, concurrency)
        self.cache = cache

    async def run(
        self,
        controls: list[Control],
        *,
        on_finding: FindingCallback | None = None,
        cancel: asyncio.Event | None = None,
    ) -> EngineResult:
        injections = scan_chunks(self.index.chunks)
        semaphore = asyncio.Semaphore(self.concurrency)
        usage = Usage()
        abort = asyncio.Event()
        fatal: list[LLMAuthError] = []
        results: dict[str, Finding] = {}

        async def emit(finding: Finding) -> None:
            results[finding.control_id] = finding
            if on_finding is not None:
                outcome = on_finding(finding)
                if inspect.isawaitable(outcome):
                    await outcome

        async def one(control: Control) -> None:
            nonlocal usage
            async with semaphore:
                if abort.is_set() or (cancel is not None and cancel.is_set()):
                    return
                hits = self.index.search(control.queries, k=self.top_k)
                excerpts = sorted((h.chunk for h in hits), key=lambda c: c.ord)  # document order reads naturally
                if not excerpts:
                    await emit(_no_excerpts(control, self.backend.name))
                    return
                key = cache_key(self.backend.name, control, excerpts)
                raw = self.cache.get(key) if self.cache else None
                from_cache = raw is not None
                if raw is None:
                    try:
                        raw, used = await self.backend.assess(control, excerpts)
                    except LLMAuthError as exc:
                        fatal.append(exc)
                        abort.set()
                        return
                    except LLMError as exc:
                        log.warning("assessment of %s failed: %s", control.id, exc)
                        await emit(_failed(control, self.backend.name, str(exc), excerpts))
                        return
                    usage = usage + used
                    if self.cache:
                        self.cache.put(key, raw)
                finding = finalize(control.id, raw, excerpts, model=self.backend.name, from_cache=from_cache)
                flagged = sorted({label for c in excerpts for label in injections.get(c.id, [])})
                if flagged:
                    finding.flags = sorted({*finding.flags, "injection_suspected"})
                await emit(finding)

        await asyncio.gather(*(one(c) for c in controls))
        if fatal:
            raise fatal[0]
        ordered = [results[c.id] for c in controls if c.id in results]
        return EngineResult(findings=ordered, usage=usage, injection_chunks=injections)


def _no_excerpts(control: Control, model: str) -> Finding:
    return Finding(
        control_id=control.id,
        status="gap",
        rationale="The document has no text that could be matched to this control.",
        missing_elements=[c.text for c in control.criteria],
        flags=["no_excerpts"],
        model=model,
    )


def _failed(control: Control, model: str, reason: str, excerpts: list[Chunk]) -> Finding:
    return Finding(
        control_id=control.id,
        status="error",
        rationale=f"This control could not be assessed ({reason}). Run the audit again to retry it.",
        flags=["assessment_failed"],
        retrieved_chunk_ids=[c.id for c in excerpts],
        model=model,
    )
