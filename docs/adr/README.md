# Decision records

Short notes on the decisions that shape this tool, why they were made, and what they cost. Each one says what was decided in
October 2026 and can be revisited: if you change one, add a new record that supersedes it instead of rewriting history.

| Record | Decision |
| --- | --- |
| [0001](0001-no-compliance-score.md) | Report counts, never a single compliance score |
| [0002](0002-verify-quotes.md) | Verify every quote against the document and downgrade what cannot be supported |
| [0003](0003-hybrid-retrieval.md) | Retrieve with BM25 and embeddings fused by rank, with a dependency-free fallback |
| [0004](0004-keep-the-text-not-the-file.md) | Store the extracted text and the file's hash, not the uploaded file |
| [0005](0005-heuristic-backend.md) | The offline reviewer is a keyword locator, and is labelled as one everywhere |
| [0006](0006-strict-tool-use.md) | Ask Claude for a strict tool call with `tool_choice: auto` |
| [0007](0007-sqlite-single-process.md) | One process and SQLite, with the way out written down |

Each record has the same parts: the situation, the decision, what follows from it, and what else was considered.
