# Evaluating a reviewer

A reviewer here is whatever turns a control and some passages into a status: the Claude backend with a given model, effort and
prompt, or the offline keyword locator. Without a way to compare them, every change to the prompt, the model or the retrieval
is a guess. `hipaa-audit eval` is that way: it runs a reviewer over policies whose answers are known, scores what comes back,
and reports the kinds of mistake that matter most for this tool.

**Read the last section before quoting any number from it.** The documents are synthetic, so the scores are good for
comparing reviewers and catching regressions and say little about accuracy on real policies.

## How the policies are made

`evaluation/synthetic.py` writes policy documents from the catalog's own example sentences (the `synth` field of every
criterion). The truth for each control is therefore known by construction:

| True status | What is in the document |
| --- | --- |
| **met** | Every one of the control's sentences |
| **partial** | Some of them, but not all |
| **gap** | None of them. Some gaps get a vague line that names the topic and commits to nothing (a "decoy"), such as "Management is committed to backups and expects everyone to take it seriously" |

By default about 35% of the controls are met, 30% partial and 35% gaps, and 40% of the gaps get a decoy. Each document has
an organisation name, five part headings, a heading over each control's paragraph, and filler sentences that answer no control.
A seed gives the same document on every run and Python version.

`--difficulty hard` (the default) makes the documents harder to match by keyword: it swaps common words for synonyms, replaces
each control's descriptive heading with a bare "Section N", and moves a control's last sentence to an appendix about 40% of the
time. `--difficulty easy` leaves the wording and the headings as the catalog has them.

## Running it

```sh
# Free and offline: the keyword locator on five documents
hipaa-audit eval --backend heuristic

# A smoke test of the Claude backend: one document, two controls, two model calls
hipaa-audit eval --backend anthropic --documents 1 --controls risk-analysis,data-backup-plan

# A fuller run, saved
hipaa-audit eval --backend anthropic --documents 3 -o eval.md
hipaa-audit eval --backend anthropic --documents 3 --format json -o eval.json
```

| Option | |
| --- | --- |
| `--backend` | `anthropic` or `heuristic`. Default: `HIPAA_AUDIT_LLM_BACKEND` |
| `--documents N` | How many policies to generate (default 5) |
| `--seed N` | The seed of the first policy; the others follow in sequence. Use the same seeds to compare two runs |
| `--difficulty` | `easy` or `hard` (default) |
| `--controls` | Comma-separated control ids (default: all 48) |
| `--format`, `-o` | `md` or `json`, and where to write it |
| `-q` | No progress on stderr |

**Cost.** A run makes `documents x controls` model calls with the Claude backend: the default is 5 x 48 = 240. The command
prints that number before it starts, and Ctrl+C stops it. Start with the smoke test.

The evaluation uses the same retrieval and the same verification as a real review; only the documents differ.

## Reading the report

| Section | What it tells you |
| --- | --- |
| **Scores** | Precision, recall and F1 for each status, the macro F1 over the three, accuracy, and the mean distance between true and predicted status (0 is exact, 2 is a gap called met or the reverse) |
| **Confusion matrix** | True status down the side, what the reviewer said across the top, with a column for controls it could not assess |
| **Mistakes that matter** | A gap reported as met; a gap reported as met or partial; support missed (met reported as gap); and the gap rates split by whether the document had a decoy line |
| **Evidence and retrieval** | Whether quotes came from the control's own text, and whether retrieval put the answer in front of the reviewer at all |

Look at **Mistakes that matter** first. The mistakes are not equally costly: telling someone a control is covered when the
document is silent is worse than flagging a control that is covered, because the first one is the mistake a person stops
checking for. A change that raises F1 and also raises the gap-called-met rate is not an improvement for this tool.

The decoy split shows whether a reviewer is fooled by a line that mentions the topic and says nothing.

The evidence figures say whether support was quoted from the right place. The retrieval figures separate two kinds of failure:
if retrieval did not put the answer in front of the reviewer, no prompt can fix the result. An `error` count above zero means
calls failed. The command still writes the report, prints the reasons on stderr (the most common three, with how many
controls each affected) and exits with status 1, so a smoke test cannot pass after the API rejected every request.

The JSON report has `schema_version`, `run`, `scores`, `confusion`, `spread` (per-document macro F1), `decoys`, `evidence`,
`retrieval` and `flags` (how often each review flag was raised).

## Changing something and checking it

1. Run the evaluation on the current code with a few fixed seeds and keep the JSON.
2. Make the change. If it touches the prompt, bump `PROMPT_VERSION` in `assess/prompts.py` so cached answers are not reused.
3. Run again with the same seeds, `--difficulty` and `--controls`, and compare **Mistakes that matter** before the scores.
4. Check the spread across documents. With five documents, a difference smaller than the spread between them is noise.

`make eval-offline` runs the offline locator on three documents as a quick check that the harness and the retrieval still work.

## What these numbers do not mean

- **They are circular.** The documents are written from the same sentences the catalog describes the controls with, and the
  offline locator looks for the same keywords. A reviewer that does well here has shown it can find those sentences, not that
  it can judge a policy written by someone else, in other words, with the gaps and half-measures real policies have.
- **They are not an accuracy estimate.** Do not quote an F1 from this harness as how accurate the tool is on real documents.
  Real policies are longer, vaguer, contradict themselves, bury requirements in tables and arrive as PDFs whose text extraction is
  imperfect. None of that is modelled.
- **The offline locator shows the gap.** It scores respectably on the synthetic documents and finds far less in the hand-written
  sample policy in `examples/`, where a person reads several controls as covered. That difference is the measure of how much
  the synthetic documents flatter a keyword matcher, and a model's score on them is flattered in a way nobody has measured.
- **Nothing here has been run with the Claude backend yet.** The harness is built and tested against stand-in backends. The
  first real run is the first measurement.

## What a real evaluation would need

This is the part that has not been done:

- A set of real or realistic policies written independently of the catalog, in the formats people actually have.
- Labels for each control from people who know the Security Rule, ideally two per document so their disagreement is known. A
  reviewer cannot be expected to agree with a label that two experts would not agree on.
- The same report run on that set, with errors read one by one: which controls, which wording, which formats.
- A look at whether `confidence` means anything: do the answers the model is sure about turn out right more often?
- A threshold on the "gap reported as met" rate that fails the build when it is crossed.

The harness takes any backend that implements `assess(control, excerpts)`, so a labelled corpus is a new loader for
`evaluation/` and not a new harness.
