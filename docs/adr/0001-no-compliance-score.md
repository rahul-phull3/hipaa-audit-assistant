# 0001. Report counts, never a single compliance score

## Situation

The natural thing to put at the top of an audit is a percentage: "78% compliant". The three statuses make it easy to compute
one (met counts as 1, partial as a half, gap as 0), and a number is what a busy reader looks for first.

## Decision

Reports and the interface show **counts** of met, partial, gap and not assessed, by safeguard and overall, with a sentence
saying that they describe what the document says and do not show that a control is carried out. There is no overall score, no
score per safeguard, and no traffic light derived from one. A test asserts that the summary has no score.

To help a reader decide where to look first without a score, the Markdown report lists gaps before partials, and required
controls before addressable ones, under "Needs attention", and findings that carry a review flag are marked.

## Why

- **The controls are not equal.** A gap in the risk analysis, which the rest of the Security Rule depends on, is not the same
  size as a gap in an addressable control about reminders. Any weighting would be an opinion presented as arithmetic.
- **The denominator is not "the rule".** The catalog is 48 paraphrased controls. It leaves out entity-specific requirements,
  and some controls do not apply to every organisation. "37 of 48" sounds like a measure of the regulation and is not.
- **A number travels without its caveats.** It ends up in a slide, an email subject or a board paper, stripped of "this is what
  the document says, read by a model, and not whether anything is implemented". A percentage reads as a certification.
- **The precision is not there.** Each status is a judgement made by a language model about a paraphrased control. Averaging
  forty-eight of them gives a number with more decimal places than the process supports.

## Consequences

- People who want a number have to make one from the JSON report, and then own what it means.
- The interface's strip and counts carry the overview instead. They are honest, and a little less convenient.
- Comparing two reviews of the same policy over time is done by looking at which controls changed, not a score moving.

## Considered

- A weighted score with required controls counting more. Rejected: the weights would be invented.
- A score shown only per safeguard. Rejected: it has the same problems with smaller denominators.
- A score hidden behind a click. Rejected: it would be the number people quote.
