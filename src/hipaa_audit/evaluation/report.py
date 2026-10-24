"""The evaluation report: a dictionary (also served as JSON) and its Markdown rendering."""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from hipaa_audit import __version__
from hipaa_audit.assess.prompts import PROMPT_VERSION
from hipaa_audit.evaluation.runner import EvaluationResult
from hipaa_audit.evaluation.scoring import COLUMNS, LABELS, merge, summarize
from hipaa_audit.models import Usage

REPORT_SCHEMA_VERSION = 1

DISCLAIMER = (
    "The documents are written from the catalog's own example sentences, so these scores compare backends and versions and "
    "catch regressions. They are not an estimate of accuracy on real policies, which word things in their own way."
)


def _rate(count: int, total: int) -> float | None:
    return count / total if total else None


def build_report(result: EvaluationResult, *, generated_at: str | None = None) -> dict[str, Any]:
    matrix = merge(d.matrix for d in result.documents)
    usage = Usage()
    flags: Counter = Counter()
    with_decoy: Counter = Counter()
    without_decoy: Counter = Counter()
    for d in result.documents:
        usage = usage + d.usage
        flags.update(d.flags)
        with_decoy.update(d.gaps_with_decoy)
        without_decoy.update(d.gaps_without_decoy)
    claims = sum(d.claims for d in result.documents)
    quoting = sum(d.claims_quoting_own_text for d in result.documents)
    quotes = sum(d.quotes for d in result.documents)
    in_own = sum(d.quotes_in_own_text for d in result.documents)
    controls = sum(d.retrieval_controls for d in result.documents)
    found_any = sum(d.retrieval_any for d in result.documents)
    found_all = sum(d.retrieval_all for d in result.documents)
    per_document = [
        {"seed": d.seed, "macro_f1": s["macro_f1"], "accuracy": s["accuracy"], "seconds": round(d.seconds, 2)}
        for d in result.documents
        for s in [summarize(d.matrix)]
    ]
    f1s = [p["macro_f1"] for p in per_document if p["macro_f1"] is not None]
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generated_at": generated_at or datetime.now(UTC).isoformat(timespec="seconds"),
        "tool": {"name": "hipaa-audit-assistant", "version": __version__},
        "disclaimer": DISCLAIMER,
        "run": {
            "backend": result.backend,
            "difficulty": result.difficulty,
            "seeds": result.seeds,
            "documents": len(result.documents),
            "controls_per_document": result.controls,
            "model_calls": len(result.documents) * result.controls,
            "top_k": result.top_k,
            "embedder": result.embedder,
            "catalog_version": result.catalog_version,
            "prompt_version": PROMPT_VERSION,
            "usage": usage.model_dump(),
        },
        "scores": summarize(matrix),
        "confusion": matrix,
        "spread": {
            "macro_f1_mean": sum(f1s) / len(f1s) if f1s else None,
            "macro_f1_min": min(f1s) if f1s else None,
            "macro_f1_max": max(f1s) if f1s else None,
            "per_document": per_document,
        },
        "decoys": {
            "with_decoy": {s: with_decoy.get(s, 0) for s in COLUMNS},
            "without_decoy": {s: without_decoy.get(s, 0) for s in COLUMNS},
        },
        "evidence": {
            "claims": claims,
            "claims_quoting_own_text": quoting,
            "claims_quoting_own_text_rate": _rate(quoting, claims),
            "quotes": quotes,
            "quotes_in_own_text": in_own,
            "quotes_in_own_text_rate": _rate(in_own, quotes),
        },
        "retrieval": {
            "controls": controls,
            "any_sentence_retrieved": found_any,
            "any_sentence_retrieved_rate": _rate(found_any, controls),
            "all_sentences_retrieved": found_all,
            "all_sentences_retrieved_rate": _rate(found_all, controls),
        },
        "flags": dict(sorted(flags.items())),
    }


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.0%}"


def _num(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2f}"


def _count(item: dict[str, Any]) -> str:
    return f"{item['count']} of {item['of']} ({_pct(item['rate'])})"


def render_markdown(report: dict[str, Any]) -> str:
    run, scores = report["run"], report["scores"]
    lines = ["# Evaluation on synthetic policies", "", f"> {report['disclaimer']}", ""]
    lines += [
        f"- Backend: {run['backend']}",
        f"- Documents: {run['documents']} at {run['difficulty']} difficulty (seeds {', '.join(map(str, run['seeds']))}), "
        f"{run['controls_per_document']} controls each, {run['model_calls']} assessments",
        f"- Passage retrieval: {run['embedder']}, top {run['top_k']} per control",
        f"- Control catalog {run['catalog_version']}, prompt {run['prompt_version']}",
    ]
    usage = run["usage"]
    if usage["input_tokens"] or usage["output_tokens"]:
        lines.append(f"- Model tokens: {usage['input_tokens']:,} in, {usage['output_tokens']:,} out")
    lines += [
        "",
        "## Scores",
        "",
        "| Status | Precision | Recall | F1 | Controls |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for label in LABELS:
        m = scores["classes"][label]
        lines.append(f"| {label} | {_pct(m['precision'])} | {_pct(m['recall'])} | {_num(m['f1'])} | {m['support']} |")
    lines += [
        "",
        f"Macro F1 {_num(scores['macro_f1'])}, accuracy {_pct(scores['accuracy'])}, "
        f"mean distance between true and predicted status {_num(scores['mean_ordinal_error'])} "
        "(0 = exact, 2 = a gap called met or the reverse).",
    ]
    if scores["errors"]:
        lines.append(f"{scores['errors']} controls could not be assessed and count as misses.")
    spread = report["spread"]
    if len(spread["per_document"]) > 1:
        lines.append(
            f"Macro F1 across documents: mean {_num(spread['macro_f1_mean'])}, "
            f"lowest {_num(spread['macro_f1_min'])}, highest {_num(spread['macro_f1_max'])}."
        )

    lines += ["", "## Confusion matrix", "", "Rows are the true status, columns what the backend said.", ""]
    lines += ["| True \\ said | " + " | ".join(COLUMNS) + " |", "| --- | " + " | ".join(["---:"] * len(COLUMNS)) + " |"]
    for label in LABELS:
        lines.append(f"| {label} | " + " | ".join(str(report["confusion"][label][c]) for c in COLUMNS) + " |")

    lines += [
        "",
        "## Mistakes that matter",
        "",
        f"- A gap reported as met: {_count(scores['gap_called_met'])}",
        f"- A gap reported as met or partial: {_count(scores['gap_called_met_or_partial'])}",
        f"- Support missed (met reported as gap): {_count(scores['met_called_gap'])}",
    ]
    decoys = report["decoys"]
    with_total, without_total = sum(decoys["with_decoy"].values()), sum(decoys["without_decoy"].values())
    if with_total:
        wrong = decoys["with_decoy"]["met"] + decoys["with_decoy"]["partial"]
        lines.append(
            f"- A gap whose only mention was a vague line that commits to nothing, reported as met or partial: "
            f"{wrong} of {with_total} ({_pct(_rate(wrong, with_total))})"
        )
    if without_total:
        wrong = decoys["without_decoy"]["met"] + decoys["without_decoy"]["partial"]
        lines.append(
            f"- A gap with no mention at all, reported as met or partial: {wrong} of {without_total} ({_pct(_rate(wrong, without_total))})"
        )

    ev, rt = report["evidence"], report["retrieval"]
    lines += [
        "",
        "## Evidence and retrieval",
        "",
        f"- When the backend found support for a control that has it, it quoted that control's own text in "
        f"{ev['claims_quoting_own_text']} of {ev['claims']} cases ({_pct(ev['claims_quoting_own_text_rate'])}); "
        f"{ev['quotes_in_own_text']} of {ev['quotes']} quotes came from the right place ({_pct(ev['quotes_in_own_text_rate'])}).",
        f"- Retrieval put at least one of a control's sentences in front of the backend in {rt['any_sentence_retrieved']} of "
        f"{rt['controls']} cases ({_pct(rt['any_sentence_retrieved_rate'])}) and all of them in {rt['all_sentences_retrieved']} "
        f"({_pct(rt['all_sentences_retrieved_rate'])}).",
    ]
    if report["flags"]:
        lines += ["", "## Review flags raised", ""]
        lines += [f"- {name}: {count}" for name, count in report["flags"].items()]
    return "\n".join(lines) + "\n"
