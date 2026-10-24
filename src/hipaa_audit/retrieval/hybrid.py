"""Hybrid retrieval: BM25 and dense similarity, fused with reciprocal rank fusion across several queries per control."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

import numpy as np

from hipaa_audit.models import Chunk
from hipaa_audit.retrieval.bm25 import BM25Index
from hipaa_audit.retrieval.embeddings import Embedder
from hipaa_audit.retrieval.text import tokenize

RRF_K = 60


@dataclass(frozen=True)
class Hit:
    chunk: Chunk
    score: float  # fused reciprocal-rank score; only meaningful for ordering
    bm25_rank: int | None  # best rank over the queries (1 = best), None if never retrieved by BM25
    dense_rank: int | None
    matched_queries: int  # how many of the queries retrieved this chunk


class HybridIndex:
    def __init__(self, chunks: list[Chunk], embedder: Embedder) -> None:
        self.chunks = chunks
        self.embedder = embedder
        self._bm25 = BM25Index([tokenize(c.text) for c in chunks])
        self._vectors = embedder.embed_documents([c.text for c in chunks])

    def search(self, queries: list[str], k: int = 6, depth: int = 20) -> list[Hit]:
        """Top ``k`` chunks for a set of queries. Every query contributes a BM25 ranking and a dense ranking."""
        if not self.chunks:
            return []
        fused: dict[int, float] = defaultdict(float)
        bm25_best: dict[int, int] = {}
        dense_best: dict[int, int] = {}
        seen_by: dict[int, set[int]] = defaultdict(set)
        for q_idx, query in enumerate(queries):
            for rank, (idx, _score) in enumerate(self._bm25.top(tokenize(query), depth), start=1):
                fused[idx] += 1.0 / (RRF_K + rank)
                bm25_best[idx] = min(rank, bm25_best.get(idx, rank))
                seen_by[idx].add(q_idx)
            sims = self._vectors @ self.embedder.embed_query(query)
            for rank, idx in enumerate(np.argsort(-sims, kind="stable")[:depth], start=1):
                idx = int(idx)
                if sims[idx] <= 0:
                    break
                fused[idx] += 1.0 / (RRF_K + rank)
                dense_best[idx] = min(rank, dense_best.get(idx, rank))
                seen_by[idx].add(q_idx)
        ranked = sorted(fused.items(), key=lambda kv: (-kv[1], kv[0]))[:k]
        return [
            Hit(
                chunk=self.chunks[idx],
                score=score,
                bm25_rank=bm25_best.get(idx),
                dense_rank=dense_best.get(idx),
                matched_queries=len(seen_by[idx]),
            )
            for idx, score in ranked
        ]
