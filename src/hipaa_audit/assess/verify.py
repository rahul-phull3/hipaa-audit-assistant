"""Server-side checks on the model's answer.

The model is asked to quote the document. This module does not take its word for it: every quote must appear in the excerpt
text it was shown (after normalising whitespace, case, quotes and dashes), and a status that rests on no verified quote is
downgraded to a gap. A "met" that still lists missing elements is downgraded to "partial".
"""

from __future__ import annotations

import html
import re
import unicodedata

from hipaa_audit.assess.schema import RawAssessment
from hipaa_audit.models import Chunk, Evidence, Finding

MIN_QUOTE_CHARS = 12
_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍﻿­"), None)
_PUNCT = str.maketrans(
    {"‘": "'", "’": "'", "“": '"', "”": '"', "–": "-", "—": "-", "−": "-"}
)
_ELLIPSIS = re.compile(r"\s*\.{3}\s*")


def normalize(text: str) -> str:
    """Comparison form of a text: unescaped, NFKC, curly quotes and dashes flattened, whitespace collapsed, lower case."""
    t = unicodedata.normalize("NFKC", html.unescape(text)).translate(_ZERO_WIDTH).translate(_PUNCT)
    return re.sub(r"\s+", " ", t).strip().lower()


def _segments(quote: str) -> list[str]:
    """A quote may use an ellipsis to skip words; each part must then appear, in order."""
    cleaned = normalize(quote).strip(" \"'")
    return [s for s in _ELLIPSIS.split(cleaned) if s]


def _contains(haystack: str, segments: list[str]) -> bool:
    pos = 0
    for segment in segments:
        found = haystack.find(segment, pos)
        if found < 0:
            return False
        pos = found + len(segment)
    return True


def _locate(chunk: Chunk, segments: list[str]) -> tuple[int | None, str]:
    """Page and section of the paragraph a verified quote sits in (a chunk can merge several short sections)."""
    texts = [normalize(chunk.text[span.start : span.end]) for span in chunk.spans]
    for span, text in zip(chunk.spans, texts, strict=True):
        if _contains(text, segments):
            return span.page, span.section
    for span, text in zip(chunk.spans, texts, strict=True):  # the quote runs across paragraphs: use where it starts
        if segments and segments[0] in text:
            return span.page, span.section
    return chunk.page, chunk.section


def verify_evidence(raw: RawAssessment, chunks: list[Chunk]) -> tuple[list[Evidence], list[str]]:
    """Keep only quotes found verbatim in the excerpts. Returns (verified evidence, flags)."""
    by_id = {c.id: c for c in chunks}
    normalised = {c.id: normalize(c.text) for c in chunks}
    accepted: list[Evidence] = []
    flags: set[str] = set()
    seen: set[tuple[str, str]] = set()
    for item in raw.evidence:
        segments = _segments(item.quote)
        if sum(len(s) for s in segments) < MIN_QUOTE_CHARS:
            flags.add("quote_too_short")
            continue
        chunk_id = item.excerpt_id if item.excerpt_id in by_id else None
        if chunk_id is None or not _contains(normalised[chunk_id], segments):
            chunk_id = next((cid for cid, text in normalised.items() if _contains(text, segments)), None)
            if chunk_id is None:
                flags.add("quote_not_found")
                continue
            flags.add("evidence_id_corrected")
        key = (chunk_id, " ".join(segments))
        if key in seen:
            continue
        seen.add(key)
        chunk = by_id[chunk_id]
        page, section = _locate(chunk, segments)
        accepted.append(Evidence(chunk_id=chunk_id, quote=html.unescape(item.quote).strip(), page=page, section=section))
    return accepted, sorted(flags)


def finalize(
    control_id: str, raw: RawAssessment, chunks: list[Chunk], *, model: str, from_cache: bool = False
) -> Finding:
    """Turn a raw assessment into a finding: verify the quotes, then apply the downgrade rules."""
    evidence, flags = verify_evidence(raw, chunks)
    flag_set = set(flags)
    status = raw.status
    rationale = raw.rationale.strip()
    confidence = raw.confidence
    missing = [m.strip() for m in raw.missing_elements if m.strip()]
    if status in ("met", "partial") and not evidence:
        status = "gap"
        confidence = min(confidence, 0.4)
        flag_set.add("unsupported_downgraded")
        rationale = (rationale + " ").lstrip() + "(No quoted support could be verified in the document, so this is recorded as a gap.)"
    if status == "met" and missing:
        status = "partial"
        flag_set.add("met_with_missing_downgraded")
    return Finding(
        control_id=control_id,
        status=status,
        rationale=rationale,
        evidence=evidence,
        missing_elements=missing,
        confidence=confidence,
        flags=sorted(flag_set),
        retrieved_chunk_ids=[c.id for c in chunks],
        model=model,
        from_cache=from_cache,
    )
