# HTTP API

The same server that serves the interface serves a small JSON API under `/api`. Everything the interface does goes through it,
so anything the interface can do a script can do.

- **Base URL:** `http://127.0.0.1:8000` by default (`hipaa-audit serve`).
- **Authentication:** if `HIPAA_AUDIT_API_KEY` is set, send it as `X-API-Key` on every request except `GET /api/health`.
- **Content:** responses are JSON unless noted. A review is asynchronous: you upload, get `202 Accepted`, and poll.
- **Errors:** every error has the same shape, and the `code` is stable where the message is not.

```json
{ "error": { "code": "invalid_request", "message": "Unsupported file type. Upload one of: .pdf, .docx, .txt, .md, .markdown." } }
```

| Status | `code` | When |
| --- | --- | --- |
| 400 | `bad_request`, `invalid_host`, `error` | A malformed header, or a `Host` this server does not answer to |
| 401 | `unauthorized` | The API key is missing or wrong |
| 403 | `forbidden_origin` | A browser request that changes something came from another site |
| 404 | `not_found` | No such review, passage or path |
| 405 | `method_not_allowed` | |
| 409 | `conflict` | The review is still waiting or running (delete, run again) |
| 413 | `too_large` | The upload is over `HIPAA_AUDIT_MAX_UPLOAD_MB` |
| 422 | `invalid_request` | No file, an unsupported or unreadable file, an unknown control id, a bad number |
| 429 | `busy` | Too many reviews are waiting or running. Honour `Retry-After` (30 seconds) |
| 500 | `internal_error` | Unexpected. Details are in the server log, never in the response |
| 503 | `unavailable` | No reviewer is configured, for example the API key for the model is missing |

## Endpoints

| Method and path | What it does |
| --- | --- |
| `GET /api/health` | Liveness: `{"status": "ok", "version": "0.1.0"}`. Needs no key |
| `GET /api/status` | Readiness and configuration: reviewer, embedder, catalog, limits |
| `GET /api/controls` | The control catalog |
| `POST /api/audits` | Upload a policy and start a review |
| `GET /api/audits` | List reviews, newest first, with their counts |
| `GET /api/audits/{id}` | One review and its summary |
| `GET /api/audits/{id}/findings` | The findings so far, in catalog order |
| `GET /api/audits/{id}/chunks/{chunk_id}` | A passage of the document with its neighbours |
| `GET /api/audits/{id}/report?format=md\|json` | The report, as a download |
| `POST /api/audits/{id}/cancel` | Stop a review |
| `POST /api/audits/{id}/rerun` | Review the same stored text again |
| `DELETE /api/audits/{id}` | Delete a review and its stored text |

### Start a review

```
POST /api/audits
Content-Type: multipart/form-data
```

| Field | |
| --- | --- |
| `file` | Required. A `.pdf`, `.docx`, `.txt`, `.md` or `.markdown` file |
| `controls` | Optional. Control ids to assess, comma-separated or repeated. Default: all 48 |

```sh
curl -sS -H "X-API-Key: $KEY" -F file=@policy.pdf http://127.0.0.1:8000/api/audits
```

The answer is `202 Accepted` with a `Location: /api/audits/{id}` header and the review as it stands: `status` is `queued` and
`done_controls` is 0. The file is validated and parsed before the answer, so a bad file fails here with a `4xx` and nothing is
queued.

### Follow a review

`GET /api/audits/{id}` returns the review and a `summary`. Poll it until `status` is `completed`, `failed` or `cancelled`
(a second or two apart is plenty). `done_controls` out of `total_controls` is the progress, and findings can be read while
the review runs.

```json
{
  "id": "d5c40906b0d09cdd",
  "filename": "policy.pdf",
  "sha256": "1ea1c240a717…",
  "size_bytes": 184320,
  "pages": 12,
  "status": "running",
  "created_at": "2026-10-24T19:57:11+00:00",
  "started_at": "2026-10-24T19:57:11+00:00",
  "finished_at": null,
  "backend": "anthropic:claude-sonnet-5-5",
  "embedder": "hashing",
  "catalog_version": "2026.10-r1",
  "prompt_version": "v2",
  "control_ids": ["risk-analysis", "…"],
  "total_controls": 48,
  "done_controls": 17,
  "chunk_count": 61,
  "usage": { "input_tokens": 41200, "output_tokens": 5300, "cache_read_tokens": 0, "cache_creation_tokens": 0 },
  "error": null,
  "summary": {
    "assessed": 17, "met": 4, "partial": 6, "gap": 7, "error": 0, "needs_review": 1,
    "by_safeguard": { "administrative": { "met": 4, "partial": 6, "gap": 7, "error": 0, "total": 17 } }
  }
}
```

- `status`: `queued`, `running`, `completed`, `failed` (see `error`) or `cancelled`.
- `summary` holds **counts only**. There is deliberately no overall score.
- `needs_review` counts findings that carry a flag meaning a person should look at them first.
- `pages` is `null` for formats without pages.

`GET /api/audits?limit=50&offset=0` returns `{"audits": [...], "total": n}`. Each audit has the fields above and a `counts`
object by status instead of a `summary`. `limit` is clamped to 1 to 200.

### Findings

`GET /api/audits/{id}/findings` returns `{"findings": [...]}`:

```json
{
  "control": {
    "id": "risk-analysis",
    "citation": "45 CFR 164.308(a)(1)(ii)(A)",
    "title": "Risk analysis",
    "safeguard": "administrative",
    "standard": "Security management process",
    "requirement": "required"
  },
  "status": "partial",
  "rationale": "The policy requires an annual risk analysis but does not say what triggers an earlier update.",
  "evidence": [
    {
      "chunk_id": "c0002",
      "quote": "We perform a risk analysis of every system that holds ePHI once a year and whenever a major change is made.",
      "page": 3,
      "section": "Risk management"
    }
  ],
  "missing_elements": ["Says which events trigger an update of the risk analysis."],
  "confidence": 0.8,
  "flags": [],
  "needs_review": false,
  "retrieved_chunk_ids": ["c0001", "c0002", "c0003", "c0004", "c0007", "c0009"],
  "model": "anthropic:claude-sonnet-5-5",
  "from_cache": false
}
```

The values above are illustrative.

- `status` is `met`, `partial`, `gap`, or `error` (the control could not be assessed; run the review again).
- Every `evidence[].quote` was checked against the document text. `page` and `section` say where the quote really is.
- **On a `gap`, `evidence` is not support.** It lists the closest passages the reviewer found, for context.
- `flags` explain what the server did or noticed: `quote_not_found`, `quote_too_short`, `evidence_id_corrected`,
  `unsupported_downgraded`, `met_with_missing_downgraded`, `quote_drops_negation`, `quote_joins_sentences`,
  `ungrounded_quantity`, `possible_missed_passage`, `injection_suspected`, `no_excerpts`, `assessment_failed`.
  `GET /api/controls` returns a plain-language label for each.
- `needs_review` is true when a flag is one of `injection_suspected`, `unsupported_downgraded`,
  `met_with_missing_downgraded`, `assessment_failed`, `quote_drops_negation`, `quote_joins_sentences`,
  `ungrounded_quantity` or `possible_missed_passage`. The last four are raised when the server cannot call something wrong
  but a person should look: a quote that leaves out a nearby "not" or "except", a quote joined from two sentences, a number
  in the rationale or the missing elements that is not in the passages the reviewer was shown (it is named in the
  rationale), and, on a gap from a language model, a strong keyword match in a passage the reviewer was not shown (it is
  added to the closest passages; the status stays as the reviewer gave it).
- `confidence` is the model's own estimate between 0 and 1. For the offline keyword reviewer it is a fixed number (0.5, or 0.3
  for a gap) and should be ignored.
- `retrieved_chunk_ids` are the passages the reviewer was shown, in document order. A `gap` means those passages did not
  address the control, not that the whole document is silent; reports say how many passages the reviewer saw
  (`passages_seen` in the report JSON). `from_cache` is true when the answer was reused from an earlier review of identical
  text.

### A passage in context

`GET /api/audits/{id}/chunks/{chunk_id}` returns a passage with the one before it and the one after it, which is how the
interface shows a quote in context.

```json
{
  "id": "c0002", "page": 3, "section": "Risk management", "text": "…",
  "previous": { "id": "c0001", "page": 2, "section": "Security responsibility", "text": "…" },
  "next": null
}
```

### Reports

`GET /api/audits/{id}/report?format=md` (the default) or `?format=json` returns the report as an attachment
(`Content-Disposition`), named `hipaa-review-<file name>.md` or `.json`.

The JSON report has `"schema_version": 1`, and changes to the shape that could break a reader will bump it.

| Key | Holds |
| --- | --- |
| `schema_version`, `generated_at`, `tool` | The report format, when it was made and by which version |
| `disclaimer` | What the report is and is not. It says a language model helped only when one did; a report from the offline keyword matcher says it is not an AI model |
| `document` | `filename`, `sha256`, `size_bytes`, `pages`, `chunks` |
| `run` | `audit_id`, `status`, `backend`, `embedder`, `catalog_version`, `current_catalog_version`, `prompt_version`, `controls_requested`, timestamps, `usage`, `error` |
| `summary` | The same counts as the review's `summary` |
| `findings` | Each finding as above without the retrieval details, in catalog order |
| `catalog` | The catalog `version`, `regulation`, `rule_status` and `notes` |

The Markdown report carries the same content for reading, with gaps and partials listed first under "Needs attention".

### Run again, cancel, delete

- `POST /api/audits/{id}/rerun` starts a **new** review over the text already stored, with the same controls, and returns
  `202` with it. It needs no upload. Controls whose answers are cached cost no model call. `409` if the review is still going.
- `POST /api/audits/{id}/cancel` stops new controls from starting. A queued review is cancelled at once; a running one finishes
  the controls in flight and becomes `cancelled`. It returns the review as it stands.
- `DELETE /api/audits/{id}` returns `204` and removes the review, its stored text, findings and cached answers. `409` while the
  review is waiting or running; cancel it first.

### The catalog and the server's state

`GET /api/controls` returns the catalog `version`, `regulation`, `rule_status`, `notes`, a `flag_labels` object, and `controls`:
each with `id`, `citation`, `title`, `safeguard`, `standard`, `requirement` (`required` or `addressable`), `expectation` and
`elements`.

`GET /api/status` returns whether the server can review documents right now:

```json
{
  "status": "ok",
  "version": "0.1.0",
  "backend": { "ready": true, "name": "anthropic:claude-sonnet-5-5", "is_ai_model": true, "error": null },
  "embedder": "hashing",
  "catalog": { "version": "2026.10-r1", "controls": 48 },
  "limits": { "max_upload_mb": 10, "max_pages": 200 },
  "active_audits": 0
}
```

`backend.ready` is false when no reviewer could be set up (the message is in `backend.error`), and uploads then fail with
`503`. `is_ai_model` is false for the offline keyword reviewer. `status` is `degraded` if the database does not answer.

## A complete example

```sh
KEY=…                                  # only if the server has HIPAA_AUDIT_API_KEY set
BASE=http://127.0.0.1:8000

field() { python3 -c "import sys, json; print(json.load(sys.stdin)['$1'])"; }

ID=$(curl -sS -H "X-API-Key: $KEY" -F file=@policy.pdf $BASE/api/audits | field id)

while :; do
  STATUS=$(curl -sS -H "X-API-Key: $KEY" $BASE/api/audits/$ID | field status)
  case $STATUS in queued|running) sleep 2 ;; *) break ;; esac
done
echo "review $STATUS"

curl -sS -H "X-API-Key: $KEY" "$BASE/api/audits/$ID/report?format=json" -o review.json
```

The same flow without a server is `hipaa-audit audit policy.pdf --format json -o review.json`.
