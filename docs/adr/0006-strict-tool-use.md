# 0006. Ask Claude for a strict tool call with `tool_choice: auto`

## Situation

Each assessment must come back as structured data: a status, a rationale, quotes, missing elements and a confidence. The usual
way is to define a tool and force the model to call it with `tool_choice: {"type": "tool", "name": ...}`.

The model this was written for, Claude Sonnet 5.5, changes several things an adapter written for earlier models would rely on.
Anthropic's migration guide and "what's new" page for the model (read in October 2026) say that:

- forced tool use (`tool_choice` of type `any` or `tool`) is rejected with a 400 error. `auto` is supported, and the guide
  recommends `strict: true` on the tool together with it;
- `temperature`, `top_p` and `top_k` are rejected;
- an assistant message prefill is rejected;
- adaptive thinking is on by default, and `max_tokens` covers the thinking as well as the answer;
- `output_config.effort` takes `low`, `medium`, `high`, `xhigh` or `max`.

## Decision

`AnthropicBackend` sends, per control:

- one tool, `record_assessment`, declared `strict: true`, with every object closed (`additionalProperties: false`) and no
  numeric bounds, which strict mode does not accept. The 0 to 1 range of `confidence` is stated in its description and enforced
  again when the answer is parsed;
- `tool_choice: {"type": "auto"}`, with a system prompt that says to answer only by calling the tool once;
- no sampling parameters and no prefill;
- `max_tokens` of 4096, doubled on the one retry that follows a truncated or malformed answer;
- `output_config.effort` from `HIPAA_AUDIT_EFFORT` (default `medium`; `default` omits it). It is passed through `extra_body`
  so an SDK release that predates the field still sends it;
- the system prompt marked for prompt caching.

## Why

- Strict tool use makes the API validate the shape of the answer, so most format failures never reach the parser.
- Not sending what the model rejects avoids a class of 400 errors that would otherwise fail every control.

## Consequences

- With `auto`, the model may reply in text without calling the tool. That is treated as an unusable answer: one more attempt,
  then an `error` finding for that control ("Not assessed", with a note to run it again), never a silent gap.
- A model change can break this adapter in ways the stub in the tests cannot show. **The adapter has so far been exercised only
  against a stand-in for the SDK, never the live API.** The first real run, a few controls with
  `hipaa-audit eval --backend anthropic --documents 1 --controls ...`, is the real test.
- The effort default is lower than the API's own default. It is a setting because the right value has to be measured, and the
  evaluation harness is there to measure it.

## Considered

- Asking for JSON in plain text and parsing it. It works on any model and fails more often, with no schema check.
- Structured outputs as a separate feature instead of a tool. The migration guide offers it as an alternative. A tool call was
  chosen first because the adapter's retry and error handling were already built around one, and it could be swapped later.
