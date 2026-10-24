"""A heuristic scan for text in the uploaded document that reads like instructions to an AI model.

This is a warning signal, not a defence. The defences are structural: excerpts are XML-escaped and delimited, the system prompt
tells the model to treat them as data, an answer counts only as one strict tool call whose input is validated, and every quote is verified
against the document. A flagged passage is reported so a reviewer can look at it.
"""

from __future__ import annotations

import re

from hipaa_audit.models import Chunk

_FLAGS = re.IGNORECASE
PATTERNS: dict[str, re.Pattern[str]] = {
    "ignore_instructions": re.compile(
        r"\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all)\b[^.\n]{0,40}\b(instructions?|prompts?|rules?)\b",
        _FLAGS,
    ),
    "role_override": re.compile(r"\byou are (now|no longer)\b|\bnew instructions?\s*:", _FLAGS),
    "prompt_reference": re.compile(r"\b(system prompt|developer message|record_assessment)\b", _FLAGS),
    "force_status": re.compile(
        r"\b(mark|rate|record|set|report)\b[^.\n]{0,30}\b(all|every|each)\b[^.\n]{0,30}\b(met|compliant|passed)\b",
        _FLAGS,
    ),
    "fake_markup": re.compile(r"</?\s*(excerpts?|control|system|assistant|human|user)\b", _FLAGS),
    "suppress_findings": re.compile(
        r"\bdo not (report|mention|flag)\b[^.\n]{0,30}\b(findings?|gaps?|issues?|violations?)\b", _FLAGS
    ),
}


def scan_text(text: str) -> list[str]:
    return [label for label, pattern in PATTERNS.items() if pattern.search(text)]


def scan_chunks(chunks: list[Chunk]) -> dict[str, list[str]]:
    """Chunk id -> labels, for the chunks that matched at least one pattern."""
    found = {c.id: scan_text(c.text) for c in chunks}
    return {cid: labels for cid, labels in found.items() if labels}
