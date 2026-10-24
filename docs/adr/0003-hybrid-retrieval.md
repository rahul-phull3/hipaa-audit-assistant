# 0003. Retrieve with BM25 and embeddings fused by rank, with a dependency-free fallback

## Situation

Each control must be assessed against the few passages of the document that bear on it. Policies word things in their own way,
so keyword search alone misses paraphrases ("access is withdrawn when someone leaves" for a termination procedure), while
embeddings alone are weak on the exact terms that matter in this domain (a citation, "ePHI", "every 12 months").

## Decision

`retrieval/hybrid.py` ranks passages with **BM25** and with **dense similarity**, for each of several queries written for the
control, and fuses the rankings with **reciprocal rank fusion** (`1 / (60 + rank)`, top 20 of each). The top six passages go to
the reviewer in document order. Passages are about 200 words with 40 words of overlap, split on sentences, and carry their
page and section.

The dense half uses `BAAI/bge-small-en-v1.5` through the optional `fastembed` package. Without it, a built-in **hashing
embedder** (hashed word and character n-grams) is used so the tool works with no machine-learning dependency. The embedder's
name is stored on each review and printed in the report.

## Why

- Rank fusion needs no calibration between BM25 scores and cosine similarities, and it is hard to get badly wrong. A weighted
  sum would need tuning against data this project does not have.
- Several queries per control cover the different ways a requirement is phrased and its different elements, and they encode
  domain knowledge in a place where a compliance person can read and edit it (the catalog).
- The fallback keeps installation, CI and the offline demo free of a model download.

## Consequences

- With the hashing fallback, the dense half is lexical, not semantic. Retrieval is better with `fastembed`, and that path has
  not been exercised end to end here. If retrieval misses the answer, no prompt can recover it, so the evaluation reports how
  often the answer was in front of the reviewer.
- Six passages is a trade between cost and recall. It is a setting (`HIPAA_AUDIT_TOP_K`), not a constant.
- There is no reranker. Adding a cross-encoder over the fused top 20 is the obvious next step if retrieval proves to be the
  weak link.

## Considered

- Sending the whole document for every control. It removes the retrieval failure, but multiplies tokens by the number of
  controls, and loses the record of what the reviewer was shown for each finding.
- Dense retrieval only, or BM25 only. Each fails in the way described above.
- A vector database. The documents are tens of passages. A matrix product in memory is simpler and has nothing to operate.
