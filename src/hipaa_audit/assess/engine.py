"""Runs the assessment of many controls against one indexed document.

For each control: retrieve excerpts (hybrid search over the control's queries), look the answer up in the cache, otherwise ask
the backend, then verify the quotes and apply the downgrade rules. Controls run concurrently up to a limit.

Failure handling, in order of severity:

* a rejected API key (``LLMAuthError``) or a failing progress callback (for example a full disk) stops the whole run;
* any other failure while assessing a control, expected or not, becomes an ``error`` finding for that control only;
* cancellation stops new controls from starting and lets the ones in flight finish.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Protocol

from hipaa_audit.assess.grounding import control_reference
from hipaa_audit.assess.injection import scan_chunks
from hipaa_audit.assess.llm import HeuristicBackend, LLMAuthError, LLMBackend, LLMError
from hipaa_audit.assess.prompts import PROMPT_VERSION
from hipaa_audit.assess.schema import RawAssessment
from hipaa_audit.assess.verify import finalize, verify_evidence
from hipaa_audit.catalog import Control
from hipaa_audit.models import Chunk, Finding, Usage
from hipaa_audit.retrieval import HybridIndex

log = logging.getLogger(__name__)

FindingCallback = Callable[[Finding], Awaitable[None] | None]
MAX_MISSED_PASSAGES = 2  # how many unseen passages a gap may add to its list of closest passages


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
    errors: dict[str, str] = field(default_factory=dict)  # control id -> why it could not be assessed


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

    async def _assess(self, control: Control, injections: dict[str, list[str]]) -> tuple[Finding, Usage]:
        hits = self.index.search(control.queries, k=self.top_k)
        excerpts = sorted((h.chunk for h in hits), key=lambda c: c.ord)  # document order reads naturally
        if not excerpts:
            return _no_excerpts(control, self.backend.name), Usage()
        key = cache_key(self.backend.name, control, excerpts)
        raw = self.cache.get(key) if self.cache else None
        from_cache = raw is not None
        used = Usage()
        if raw is None:
            raw, used = await self.backend.assess(control, excerpts)
            if self.cache:
                self.cache.put(key, raw)
        finding = finalize(
            control.id,
            raw,
            excerpts,
            model=self.backend.name,
            from_cache=from_cache,
            reference=control_reference(control),
        )
        if finding.status == "gap" and not isinstance(self.backend, HeuristicBackend):
            finding = await self._second_look(control, finding, excerpts)
        if any(injections.get(c.id) for c in excerpts):
            finding.flags = sorted({*finding.flags, "injection_suspected"})
        return finding, used

    async def _second_look(self, control: Control, finding: Finding, shown: list[Chunk]) -> Finding:
        """A gap says that the passages the reviewer was shown do not address the control. Search only shows it a few, so the rest of
        the document gets a keyword look, and a strong match there is listed under the closest passages and flagged for a person.
        The status stays the reviewer's. (The offline matcher is this same look, so it does not get a second one.)"""
        shown_ids = {c.id for c in shown}
        unseen = [c for c in self.index.chunks if c.id not in shown_ids]
        if not unseen:
            return finding
        raw, _ = await HeuristicBackend().assess(control, unseen)
        if raw.status == "gap":
            return finding
        found, _ = verify_evidence(raw, unseen)
        if not found:
            return finding
        known = {(e.chunk_id, e.quote) for e in finding.evidence}
        extra = [e for e in found if (e.chunk_id, e.quote) not in known][:MAX_MISSED_PASSAGES]
        if not extra:
            return finding
        finding.evidence = [*finding.evidence, *extra]
        finding.flags = sorted({*finding.flags, "possible_missed_passage"})
        return finding

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
        stop = asyncio.Event()  # set by a fatal error: nothing new starts
        fatal: list[BaseException] = []
        results: dict[str, Finding] = {}
        errors: dict[str, str] = {}

        async def one(control: Control) -> None:
            nonlocal usage
            async with semaphore:
                if stop.is_set() or (cancel is not None and cancel.is_set()):
                    return
                try:
                    finding, used = await self._assess(control, injections)
                except LLMAuthError as exc:
                    fatal.append(exc)
                    stop.set()
                    return
                except LLMError as exc:
                    log.warning("assessment of %s failed: %s", control.id, exc)
                    finding, used = _failed(control, self.backend.name, str(exc)), Usage()
                    errors[control.id] = str(exc)
                except Exception:  # noqa: BLE001 - one control must not take the audit down; the traceback goes to the log
                    log.exception("unexpected error while assessing %s", control.id)
                    finding, used = _failed(control, self.backend.name, "unexpected internal error"), Usage()
                    errors[control.id] = "unexpected internal error"
                usage = usage + used
                results[control.id] = finding
                if on_finding is not None:
                    try:
                        outcome = on_finding(finding)
                        if inspect.isawaitable(outcome):
                            await outcome
                    except Exception as exc:  # noqa: BLE001 - the progress callback failing is an infrastructure problem
                        log.exception("progress callback failed")
                        fatal.append(exc)
                        stop.set()

        await asyncio.gather(*(one(c) for c in controls))
        if fatal:
            raise fatal[0]
        ordered = [results[c.id] for c in controls if c.id in results]
        return EngineResult(findings=ordered, usage=usage, injection_chunks=injections, errors=errors)


def _no_excerpts(control: Control, model: str) -> Finding:
    return Finding(
        control_id=control.id,
        status="gap",
        rationale="The document has no text that could be matched to this control.",
        missing_elements=[c.text for c in control.criteria],
        flags=["no_excerpts"],
        model=model,
    )


def _failed(control: Control, model: str, reason: str) -> Finding:
    return Finding(
        control_id=control.id,
        status="error",
        rationale=f"This control could not be assessed ({reason}). Run the audit again to retry it.",
        flags=["assessment_failed"],
        model=model,
    )
