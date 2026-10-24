# 0005. The offline reviewer is a keyword locator, and is labelled as one everywhere

## Situation

Several things need a reviewer that costs nothing and needs no key: trying the tool, the browser test and CI, developing
without spending credits, and a free baseline for the evaluation harness. The risk is that its output looks like the real thing.
A keyword matcher that prints "met" next to a control invites the reading that something understood the policy.

## Decision

`HeuristicBackend` is built as a **keyword locator**. For each element a control expects, it finds the paragraph that shares
the most of that element's keywords. A strong match (at least half of the keywords, never fewer than two) counts as support.
A weaker match of two keywords is shown only as one of the **closest passages** on a gap and never raises a status.

It says what it is, in every place its output appears:

- the backend is named `heuristic:keywords`, and `GET /api/status` has `is_ai_model: false` for it;
- every rationale begins "Keyword heuristic (not an AI model)";
- the interface calls it "Offline keyword matching" and shows a notice that no AI model read the document;
- its confidence is a constant, so the interface and the Markdown report leave it out;
- the README describes it as a locator and gives no accuracy for it.

## Why

- It lets the whole stack, from upload to downloadable report, run in CI with no secrets and no network.
- Conservative matching means it under-reports. On the bundled sample policy it finds no control fully met and eleven partly
  met, although a person would call several met. A tool that misses things fails safe. One that over-claimed would mislead.

## Consequences

- Its results are modest and are not meant to look good. They should never be quoted as the tool's accuracy.
- Copy anywhere in the product must never call it a model, an AI, or "AI-assisted". Tests cover the `is_ai_model` flag, the
  rationale wording and the interface's label and notice.
- The evaluation harness scores it well on synthetic documents, which are written from the keywords it looks for. That is the
  circularity [evaluation.md](../evaluation.md) warns about.

## Considered

- No offline mode. Then CI cannot run the browser test, and nobody can try the tool without a key.
- Canned results. Misleading, and it would not exercise retrieval or verification.
- A small local model. A heavy dependency whose answers would also need the same caveats, for a gain nobody has measured.
