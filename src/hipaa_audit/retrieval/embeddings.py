"""Embedders for the dense half of hybrid retrieval.

* ``FastEmbedEmbedder`` uses BAAI/bge-small-en-v1.5 through the optional ``fastembed`` package (ONNX, CPU, no API call).
* ``HashingEmbedder`` is the dependency-free fallback: signed hashed word and character n-gram features. It captures fuzzy
  lexical overlap (plurals, typos, shared word pieces) but not meaning, so results are best with the real model installed.
"""

from __future__ import annotations

import logging
import zlib
from typing import Protocol

import numpy as np

from hipaa_audit.retrieval.text import tokenize

log = logging.getLogger(__name__)


class Embedder(Protocol):
    name: str

    def embed_documents(self, texts: list[str]) -> np.ndarray: ...

    def embed_query(self, text: str) -> np.ndarray: ...


def _normalize(matrix: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(matrix, axis=-1, keepdims=True)
    norms[norms == 0] = 1.0
    return matrix / norms


class HashingEmbedder:
    name = "hashing"

    def __init__(self, dim: int = 768) -> None:
        self.dim = dim

    def _vector(self, text: str) -> np.ndarray:
        vec = np.zeros(self.dim, dtype=np.float32)
        tokens = tokenize(text)
        features: list[str] = list(tokens)
        features += [f"{a} {b}" for a, b in zip(tokens, tokens[1:], strict=False)]
        for tok in tokens:
            padded = f"<{tok}>"
            features += [padded[i : i + 4] for i in range(max(len(padded) - 3, 0))]
        for feature in features:
            h = zlib.crc32(feature.encode("utf-8"))
            vec[h % self.dim] += 1.0 if (h >> 16) & 1 else -1.0
        return vec

    def embed_documents(self, texts: list[str]) -> np.ndarray:
        if not texts:
            return np.zeros((0, self.dim), dtype=np.float32)
        return _normalize(np.vstack([self._vector(t) for t in texts]))

    def embed_query(self, text: str) -> np.ndarray:
        return _normalize(self._vector(text)[None, :])[0]


class FastEmbedEmbedder:
    def __init__(self, model_name: str = "BAAI/bge-small-en-v1.5") -> None:
        try:
            from fastembed import TextEmbedding
        except ImportError as exc:  # pragma: no cover - depends on the optional extra
            raise RuntimeError("fastembed is not installed; install the extra: pip install 'hipaa-audit-assistant[embeddings]'") from exc
        self.name = f"fastembed:{model_name}"
        self._model = TextEmbedding(model_name=model_name)

    def embed_documents(self, texts: list[str]) -> np.ndarray:  # pragma: no cover - needs the model
        if not texts:
            return np.zeros((0, 384), dtype=np.float32)
        return _normalize(np.array(list(self._model.embed(texts)), dtype=np.float32))

    def embed_query(self, text: str) -> np.ndarray:  # pragma: no cover - needs the model
        embed = getattr(self._model, "query_embed", None) or self._model.embed
        vec = np.array(next(iter(embed([text]))), dtype=np.float32)
        return _normalize(vec[None, :])[0]


def make_embedder(kind: str = "auto") -> Embedder:
    """``hashing``, ``fastembed`` or ``auto`` (fastembed when it loads, otherwise hashing with a warning)."""
    if kind == "hashing":
        return HashingEmbedder()
    if kind == "fastembed":
        return FastEmbedEmbedder()
    if kind != "auto":
        raise ValueError(f"unknown embedder '{kind}' (use auto, fastembed or hashing)")
    try:
        return FastEmbedEmbedder()
    except Exception as exc:
        log.warning("dense embeddings unavailable (%s); falling back to the hashing embedder", exc)
        return HashingEmbedder()
