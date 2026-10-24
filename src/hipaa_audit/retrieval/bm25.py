"""A small BM25 (Okapi) index. In-process and dependency free; a policy document has hundreds of chunks, not millions."""

from __future__ import annotations

import math
from collections import Counter, defaultdict


class BM25Index:
    def __init__(self, docs: list[list[str]], k1: float = 1.5, b: float = 0.75) -> None:
        self.k1 = k1
        self.b = b
        self.n_docs = len(docs)
        self.doc_len = [len(d) for d in docs]
        self.avg_len = sum(self.doc_len) / self.n_docs if self.n_docs else 0.0
        self.postings: dict[str, list[tuple[int, int]]] = defaultdict(list)
        for idx, tokens in enumerate(docs):
            for term, tf in Counter(tokens).items():
                self.postings[term].append((idx, tf))
        self.idf = {
            term: math.log(1.0 + (self.n_docs - len(posts) + 0.5) / (len(posts) + 0.5))
            for term, posts in self.postings.items()
        }

    def top(self, query_tokens: list[str], k: int) -> list[tuple[int, float]]:
        """Best ``k`` documents with a positive score as (index, score), best first. Ties break on document order."""
        scores: dict[int, float] = defaultdict(float)
        for term in set(query_tokens):
            idf = self.idf.get(term)
            if idf is None:
                continue
            for idx, tf in self.postings[term]:
                norm = self.k1 * (1.0 - self.b + self.b * self.doc_len[idx] / self.avg_len) if self.avg_len else self.k1
                scores[idx] += idf * tf * (self.k1 + 1.0) / (tf + norm)
        ranked = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))
        return ranked[:k]
