"""The audit report: a structured document (also served as JSON) and its Markdown rendering.

Everything that comes from the uploaded document or from the model (quotes, rationales, missing elements) is escaped before it
is placed in Markdown, so a hostile policy cannot inject headings, links or HTML into a report someone else opens later.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from hipaa_audit import __version__
from hipaa_audit.catalog import Catalog, Control
from hipaa_audit.models import Finding
from hipaa_audit.storage import AuditRecord

REPORT_SCHEMA_VERSION = 1

DISCLAIMER = (
    "This report describes what the uploaded policy document says about each control. It was produced with the help of a "
    "language model, every quoted passage was checked against the document, and findings should still be reviewed by a person. "
    "It is not legal advice and does not certify HIPAA compliance: a policy that addresses a control does not show that the "
    "control is implemented or effective."
)

STATUS_LABELS = {"met": "Met", "partial": "Partial", "gap": "Gap", "error": "Not assessed"}
STATUS_ORDER = ("met", "partial", "gap", "error")
SAFEGUARD_LABELS = {
    "administrative": "Administrative safeguards",
    "physical": "Physical safeguards",
    "technical": "Technical safeguards",
    "organizational": "Organizational requirements",
    "documentation": "Policies, procedures and documentation",
}
FLAG_LABELS = {
    "quote_not_found": "A quote the model gave was not found in the document and was dropped.",
    "quote_too_short": "A quote the model gave was too short to verify and was dropped.",
    "evidence_id_corrected": "A quote was attributed to the wrong excerpt and was re-attached to the right one.",
    "unsupported_downgraded": "The model claimed support that could not be verified, so the status was lowered to gap.",
    "met_with_missing_downgraded": "The model marked this met while listing missing elements, so it was lowered to partial.",
    "injection_suspected": "A retrieved passage contains text that looks like an instruction to an AI system. Review it.",
    "no_excerpts": "No part of the document could be matched to this control.",
    "assessment_failed": "The model could not assess this control. Run the audit again to retry it.",
}
_TO_REVIEW_FLAGS = frozenset(
    {"injection_suspected", "unsupported_downgraded", "met_with_missing_downgraded", "assessment_failed"}
)


def needs_review(flags: Iterable[str]) -> bool:
    """True when a finding carries a flag that means a person should look at it before relying on it."""
    return bool(_TO_REVIEW_FLAGS.intersection(flags))


def control_summary(control: Control | None, control_id: str) -> dict[str, Any]:
    if control is None:  # the catalog edition changed since this audit ran
        return {
            "id": control_id,
            "citation": "",
            "title": control_id,
            "safeguard": "",
            "standard": "",
            "requirement": "",
        }
    return {
        "id": control.id,
        "citation": control.citation,
        "title": control.title,
        "safeguard": control.safeguard,
        "standard": control.standard,
        "requirement": control.requirement,
    }


def summarize(findings: list[Finding], catalog: Catalog) -> dict[str, Any]:
    """Counts only. There is deliberately no single compliance score: a number would suggest a conclusion this tool cannot reach."""
    controls = {c.id: c for c in catalog.controls}
    totals = Counter(f.status for f in findings)
    by_safeguard: dict[str, Counter] = defaultdict(Counter)
    for f in findings:
        control = controls.get(f.control_id)
        by_safeguard[control.safeguard if control else "unknown"][f.status] += 1
    return {
        "assessed": len(findings),
        **{status: totals.get(status, 0) for status in STATUS_ORDER},
        "needs_review": sum(1 for f in findings if needs_review(f.flags)),
        "by_safeguard": {
            sg: {**{s: counts.get(s, 0) for s in STATUS_ORDER}, "total": sum(counts.values())}
            for sg, counts in sorted(
                by_safeguard.items(),
                key=lambda kv: list(SAFEGUARD_LABELS).index(kv[0]) if kv[0] in SAFEGUARD_LABELS else 99,
            )
        },
    }


def build_report(
    audit: AuditRecord, findings: list[Finding], catalog: Catalog, *, generated_at: str | None = None
) -> dict[str, Any]:
    controls = {c.id: c for c in catalog.controls}
    position = {c.id: i for i, c in enumerate(catalog.controls)}
    ordered = sorted(findings, key=lambda f: position.get(f.control_id, len(position)))
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generated_at": generated_at or datetime.now(UTC).isoformat(timespec="seconds"),
        "tool": {"name": "hipaa-audit-assistant", "version": __version__},
        "disclaimer": DISCLAIMER,
        "document": {
            "filename": audit.filename,
            "sha256": audit.sha256,
            "size_bytes": audit.size_bytes,
            "pages": audit.pages,
            "chunks": audit.chunk_count,
        },
        "run": {
            "audit_id": audit.id,
            "status": audit.status,
            "backend": audit.backend,
            "embedder": audit.embedder,
            "catalog_version": audit.catalog_version,
            "current_catalog_version": catalog.meta.version,
            "prompt_version": audit.prompt_version,
            "controls_requested": audit.total_controls,
            "created_at": audit.created_at,
            "started_at": audit.started_at,
            "finished_at": audit.finished_at,
            "usage": audit.usage.model_dump(),
            "error": audit.error,
        },
        "summary": summarize(ordered, catalog),
        "findings": [
            {
                "control": control_summary(controls.get(f.control_id), f.control_id),
                "status": f.status,
                "rationale": f.rationale,
                "evidence": [
                    {"quote": e.quote, "page": e.page, "section": e.section, "chunk_id": e.chunk_id} for e in f.evidence
                ],
                "missing_elements": f.missing_elements,
                "confidence": f.confidence,
                "flags": f.flags,
            }
            for f in ordered
        ],
        "catalog": {
            "version": catalog.meta.version,
            "regulation": catalog.meta.regulation,
            "rule_status": catalog.meta.rule_status,
            "notes": catalog.meta.notes,
        },
    }


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


_MD_ESCAPE = re.compile(r"([\\`*_{}\[\]<>|~#])")


def _md(text: str) -> str:
    """One line of untrusted text, safe to place in Markdown: control characters and newlines flattened, markup escaped."""
    flat = re.sub(r"\s+", " ", re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", " ", text or "")).strip()
    return _MD_ESCAPE.sub(r"\\\1", flat).replace("&", "&amp;")


def _where(page: int | None, section: str) -> str:
    parts = []
    if page is not None:
        parts.append(f"page {page}")
    if section:
        parts.append(f"section: {_md(section)}")
    return f" ({', '.join(parts)})" if parts else ""


def render_markdown(report: dict[str, Any]) -> str:
    doc, run, summary = report["document"], report["run"], report["summary"]
    lines: list[str] = ["# HIPAA Security Rule policy review", "", f"> {report['disclaimer']}", ""]

    lines += ["## Document", ""]
    lines += [f"- File: {_md(doc['filename'])}", f"- SHA-256: `{doc['sha256']}`"]
    if doc.get("pages"):
        lines.append(f"- Pages: {doc['pages']}")
    lines += [f"- Text passages analysed: {doc['chunks']}", ""]

    lines += ["## Run", ""]
    lines += [
        f"- Audit: `{run['audit_id']}` ({run['status']})",
        f"- Reviewer: {_md(run['backend'])}",
        f"- Passage retrieval: {_md(run['embedder'] or 'not recorded')}",
        f"- Control catalog: {_md(run['catalog_version'])}",
        f"- Report generated: {report['generated_at']}",
    ]
    if run["catalog_version"] != run["current_catalog_version"]:
        lines.append(f"- Note: the catalog has since been updated to {_md(run['current_catalog_version'])}.")
    usage = run["usage"]
    if usage["input_tokens"] or usage["output_tokens"]:
        lines.append(f"- Model tokens: {usage['input_tokens']:,} in, {usage['output_tokens']:,} out")
    if run.get("error"):
        lines.append(f"- Error: {_md(run['error'])}")
    lines.append("")

    lines += ["## Summary", "", "| Status | Controls |", "| --- | ---: |"]
    for status in STATUS_ORDER:
        if summary[status] or status != "error":
            lines.append(f"| {STATUS_LABELS[status]} | {summary[status]} |")
    lines += ["", f"Controls assessed: {summary['assessed']} of {run['controls_requested']}."]
    if summary["needs_review"]:
        lines.append(f"Findings that need a person's attention before they are relied on: {summary['needs_review']}.")
    lines += ["", "| Safeguard | Met | Partial | Gap | Not assessed |", "| --- | ---: | ---: | ---: | ---: |"]
    for sg, counts in summary["by_safeguard"].items():
        lines.append(
            f"| {SAFEGUARD_LABELS.get(sg, sg)} | {counts['met']} | {counts['partial']} | {counts['gap']} | {counts['error']} |"
        )
    lines.append("")

    findings = report["findings"]
    attention = [f for f in findings if f["status"] in ("gap", "partial")]
    attention.sort(key=lambda f: (f["status"] != "gap", f["control"]["requirement"] != "required"))
    if attention:
        lines += ["## Needs attention", "", "Gaps first, required items before addressable ones.", ""]
        for f in attention:
            c = f["control"]
            lines.append(
                f"- **{STATUS_LABELS[f['status']]}**: {_md(c['title'])} ({_md(c['citation'])}, {c['requirement']})"
            )
        lines.append("")

    lines += ["## Findings", ""]
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for f in findings:
        grouped[f["control"]["safeguard"]].append(f)
    for sg in [*SAFEGUARD_LABELS, *[k for k in grouped if k not in SAFEGUARD_LABELS]]:
        if sg not in grouped:
            continue
        lines += [f"### {SAFEGUARD_LABELS.get(sg, _md(sg or 'Other'))}", ""]
        for f in grouped[sg]:
            c = f["control"]
            lines += [f"#### {_md(c['title'])}: {STATUS_LABELS[f['status']]}", ""]
            meta = [x for x in (_md(c["citation"]), c["requirement"], _md(c["standard"])) if x]
            lines += [" · ".join(meta), ""]
            if f["rationale"]:
                lines += [_md(f["rationale"]), ""]
            if f["status"] == "gap" and f["evidence"]:
                lines += ["Closest passages in the document (these do not count as support):", ""]
            for e in f["evidence"]:
                lines.append(f"> “{_md(e['quote'])}”{_where(e['page'], e['section'])}")
                lines.append("")
            if f["missing_elements"]:
                lines += ["Not shown in the document:", ""]
                lines += [f"- {_md(m)}" for m in f["missing_elements"]]
                lines.append("")
            if f["status"] != "error":
                lines += [f"Model confidence: {f['confidence']:.0%}", ""]
            for flag in f["flags"]:
                lines += [f"Review note: {FLAG_LABELS.get(flag, _md(flag))}", ""]

    cat = report["catalog"]
    lines += [
        "## About this review",
        "",
        f"Controls come from catalog {_md(cat['version'])} ({_md(cat['regulation'])}).",
        "",
        _md(cat["rule_status"]),
        "",
    ]
    lines += [f"- {_md(n)}" for n in cat["notes"]]
    lines.append("")
    return "\n".join(lines)
