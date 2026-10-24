"""Run a backend over synthetic policies and score what comes back."""

from __future__ import annotations

import asyncio
import time
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from hipaa_audit.assess.engine import AssessmentEngine
from hipaa_audit.assess.llm import LLMBackend
from hipaa_audit.assess.verify import normalize
from hipaa_audit.catalog import load_catalog
from hipaa_audit.evaluation.scoring import LABELS, Matrix, confusion
from hipaa_audit.evaluation.synthetic import ControlTruth, Mix, SyntheticPolicy, generate_policy
from hipaa_audit.ingest import ingest_document
from hipaa_audit.models import Finding, Usage
from hipaa_audit.retrieval import Embedder, HashingEmbedder, HybridIndex

BackendFactory = Callable[[SyntheticPolicy], LLMBackend]


@dataclass
class DocumentScore:
    seed: int
    matrix: Matrix
    # When the backend claims support (met or partial) for a control that truly has some: did it quote that control's own text?
    claims: int = 0
    claims_quoting_own_text: int = 0
    quotes: int = 0
    quotes_in_own_text: int = 0
    # Could the backend have seen the answer? Controls with support in the document, and whether retrieval found it.
    retrieval_controls: int = 0
    retrieval_any: int = 0  # at least one of the control's sentences is in the passages sent to the backend
    retrieval_all: int = 0  # all of them are
    # Truth gaps by whether the document had a vague decoy line for them: predicted status counts.
    gaps_with_decoy: Counter = field(default_factory=Counter)
    gaps_without_decoy: Counter = field(default_factory=Counter)
    flags: Counter = field(default_factory=Counter)
    usage: Usage = field(default_factory=Usage)
    seconds: float = 0.0


@dataclass
class EvaluationResult:
    backend: str
    difficulty: str
    seeds: list[int]
    controls: int
    top_k: int
    embedder: str
    catalog_version: str
    documents: list[DocumentScore] = field(default_factory=list)


def _quoted_from(finding: Finding, truth: ControlTruth) -> tuple[int, int]:
    own = [normalize(text) for text in truth.own_texts]
    quotes = [normalize(e.quote) for e in finding.evidence]
    return len(quotes), sum(1 for q in quotes if q and any(q in text for text in own))


def _retrieval(index: HybridIndex, controls, truth: dict[str, ControlTruth], top_k: int) -> tuple[int, int, int]:
    total = any_hit = all_hit = 0
    for control in controls:
        entry = truth[control.id]
        if entry.status == "gap":
            continue
        total += 1
        seen = [normalize(hit.chunk.text) for hit in index.search(control.queries, k=top_k)]
        found = [any(normalize(sentence) in text for text in seen) for sentence in entry.sentences]
        any_hit += any(found)
        all_hit += all(found)
    return total, any_hit, all_hit


async def score_document(
    policy: SyntheticPolicy,
    backend: LLMBackend,
    *,
    control_ids: Sequence[str] | None,
    embedder: Embedder,
    top_k: int,
    concurrency: int,
    cancel: asyncio.Event | None = None,
) -> DocumentScore:
    controls = load_catalog().select(list(control_ids) if control_ids else None)
    chunks, _pages = ingest_document(policy.filename(), policy.text.encode("utf-8"))
    index = HybridIndex(chunks, embedder)
    started = time.perf_counter()
    result = await AssessmentEngine(backend, index, top_k=top_k, concurrency=concurrency).run(controls, cancel=cancel)
    seconds = time.perf_counter() - started

    predicted = {f.control_id: f.status for f in result.findings}
    pairs = [(policy.truth[c.id].status, predicted[c.id]) for c in controls if c.id in predicted]
    score = DocumentScore(seed=policy.seed, matrix=confusion(pairs), usage=result.usage, seconds=seconds)
    for finding in result.findings:
        truth = policy.truth[finding.control_id]
        score.flags.update(finding.flags)
        if truth.status == "gap":
            (score.gaps_with_decoy if truth.decoy else score.gaps_without_decoy)[finding.status] += 1
        elif finding.status in ("met", "partial"):
            quotes, in_own = _quoted_from(finding, truth)
            score.claims += 1
            score.claims_quoting_own_text += in_own > 0
            score.quotes += quotes
            score.quotes_in_own_text += in_own
    score.retrieval_controls, score.retrieval_any, score.retrieval_all = _retrieval(
        index, controls, policy.truth, top_k
    )
    return score


async def evaluate(
    make_backend: BackendFactory,
    *,
    seeds: Sequence[int],
    difficulty: str = "hard",
    control_ids: Sequence[str] | None = None,
    mix: Mix | None = None,
    embedder: Embedder | None = None,
    top_k: int = 6,
    concurrency: int = 4,
    progress: Callable[[int, int], None] | None = None,
    cancel: asyncio.Event | None = None,
) -> EvaluationResult:
    """One synthetic document per seed. ``make_backend`` receives the policy so a test can build an oracle that knows the answers."""
    embedder = embedder or HashingEmbedder()
    catalog = load_catalog()
    controls = catalog.select(list(control_ids) if control_ids else None)
    result = EvaluationResult(
        backend="",
        difficulty=difficulty,
        seeds=list(seeds),
        controls=len(controls),
        top_k=top_k,
        embedder=embedder.name,
        catalog_version=catalog.meta.version,
    )
    for done, seed in enumerate(seeds):
        if cancel is not None and cancel.is_set():
            break
        policy = generate_policy(seed, difficulty=difficulty, mix=mix, catalog=catalog, control_ids=control_ids)
        backend = make_backend(policy)
        result.backend = backend.name
        result.documents.append(
            await score_document(
                policy,
                backend,
                control_ids=control_ids,
                embedder=embedder,
                top_k=top_k,
                concurrency=concurrency,
                cancel=cancel,
            )
        )
        if progress is not None:
            progress(done + 1, len(seeds))
    return result


__all__ = ["DocumentScore", "EvaluationResult", "LABELS", "evaluate", "score_document"]
