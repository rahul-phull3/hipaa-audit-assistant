# 0002. Verify every quote against the document and downgrade what cannot be supported

## Situation

A language model asked to assess a control against a document will sometimes quote text that is not there, merge two
sentences, or paraphrase while presenting the result as a quotation. In an audit tool that is the worst failure there is: a
fabricated quotation is evidence that does not exist, and a reader who trusts the quote stops reading the document.

## Decision

The model is asked for a status, a rationale, the elements it found missing and **verbatim quotes with the passage each came
from**. The server then checks them, for every backend, before anything is stored or shown (`assess/verify.py`):

1. A quote must appear in the passages the model was shown, after normalising Unicode, curly quotes and dashes, whitespace and
   case. `...` inside a quote may skip words, and each part must appear in order. Quotes under 12 characters are dropped.
2. A quote attributed to the wrong passage is re-attached to the passage that contains it. A quote found nowhere is dropped.
3. A status of `met` or `partial` with no verified quote becomes `gap`, with confidence capped at 0.4.
4. A `met` that still lists missing elements becomes `partial`.
5. Each of these leaves a flag on the finding, and the flags that mean a person should look first mark it "needs review".

Page and section are taken from the passage the quote was found in, not from the model.

## Why

- Verification is cheap, deterministic and independent of which model produced the answer.
- It turns "the model said so" into "this text is in your document", which is the claim a reader needs to rely on.
- Downgrading errs on the safe side. A true `met` that the model could only paraphrase shows up as a gap that a person
  checks. The opposite error, a `met` resting on nothing, is the one that would go unnoticed.

## Consequences

- Every quote in a report is real text from the document. That does **not** mean the model read it correctly. A true quote
  can be misinterpreted, so the report still says findings need a person's review.
- A model that paraphrases a lot will have findings downgraded. The rate of `unsupported_downgraded` is therefore a quality
  signal, and the evaluation harness counts it.
- The check is on the passages the model was shown, so a quote from elsewhere in the document is rejected even if it is real.
  That is intended: the finding records what the reviewer had in front of it (`retrieved_chunk_ids`).

## Considered

- Trusting the model. Rejected for the reason above.
- A provider's built-in citation feature. It would tie the check to one provider, and the offline backend and the tests
  would need a separate path. The server-side check works for all of them.
- Fuzzy matching, to forgive small paraphrases. Rejected: a quotation that is almost right is the failure being guarded
  against. Case, spacing and typographic quotes are the only differences forgiven.
