"""Server-side checks on the model's answer.

The model is asked to quote the document. This module does not take its word for it: every quote must appear in the excerpt
text it was shown (after normalising whitespace, case, quotes and dashes), and a status that rests on no verified quote is
downgraded to a gap. A "met" that still lists missing elements is downgraded to "partial".

Further checks only raise a flag, because they cannot tell a mistake from an unusual way of writing: a quote that leaves out a
"not" or an "except" sitting next to it, a quote that an ellipsis stitches together from two sentences, and a number in the model's
own sentences (see ``grounding``) that the document does not contain.
"""

from __future__ import annotations

import html
import re
import unicodedata

from hipaa_audit.assess.grounding import allowed_quantities, ungrounded_quantities
from hipaa_audit.assess.schema import RawAssessment
from hipaa_audit.models import Chunk, Evidence, Finding

MIN_QUOTE_CHARS = 12
_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍﻿­"), None)
_PUNCT = str.maketrans({"‘": "'", "’": "'", "“": '"', "”": '"', "–": "-", "—": "-", "−": "-"})
_ELLIPSIS = re.compile(r"\s*\.{3}\s*")
_NEGATORS = re.compile(r"\b(?:not|no|never|cannot|without|neither|nor|prohibited|forbidden)\b|n't\b")
_EXCEPTIONS = re.compile(r"\b(?:except|unless|excluding|exempt|other than|apart from|but not)\b")
_BOUNDARY = re.compile(r"[.!?;]\s")
_CLAUSE = re.compile(r"[.!?;:,]\s|\s(?:and|but|while|which|where|although)\s")
NEAR_WORDS = 5  # how far from a quote a "not" or an "except" still changes what the quote says


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


def _paragraphs(chunk: Chunk) -> list[str]:
    if chunk.spans:
        return [normalize(chunk.text[span.start : span.end]) for span in chunk.spans]
    return [normalize(line) for line in chunk.text.split("\n") if line.strip()]


def quote_problems(chunk: Chunk, segments: list[str]) -> set[str]:
    """Ways a quote that is really in the document can still say something the document does not.

    ``quote_drops_negation``: a word that reverses or limits the quote sits right next to it, outside the words that were quoted.
    Before a quote (or before the part that follows an ellipsis), a "not", "no", "never" or "without" in the same clause turns
    what it says around: "must not send ePHI by email" quoted as "send ePHI by email". After it, an "except" or "unless" takes
    something back. Only the few words next to the quote count, a comma or "and" ends a clause, and a quote that ends its sentence
    is not judged by the sentence after it.

    ``quote_joins_sentences``: an ellipsis skips over the end of a sentence, or the quote runs from one paragraph into the next, so it
    reads as one statement the document never made."""
    problems: set[str] = set()
    for text in _paragraphs(chunk):
        if not _contains(text, segments):
            continue
        spans, position = [], 0
        for segment in segments:
            start = text.find(segment, position)
            spans.append((start, start + len(segment)))
            position = start + len(segment)
        for i, (start, end) in enumerate(spans):
            outside = text[(spans[i - 1][1] if i else 0) : start]
            if i and _BOUNDARY.search(outside):
                problems.add("quote_joins_sentences")
            cut = max((m.end() for m in _CLAUSE.finditer(outside)), default=0)
            if _NEGATORS.search(" ".join(outside[cut:].split()[-NEAR_WORDS:])):
                problems.add("quote_drops_negation")
            if not segments[i].endswith((".", "!", "?", ";")):
                rest = text[end : (spans[i + 1][0] if i + 1 < len(spans) else len(text))]
                stop = _BOUNDARY.search(rest)
                if _EXCEPTIONS.search(" ".join((rest[: stop.start()] if stop else rest).split()[:NEAR_WORDS])):
                    problems.add("quote_drops_negation")
        return problems
    return {"quote_joins_sentences"}  # no single paragraph holds the whole quote


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
        if raw.status in ("met", "partial"):  # a gap's quotes are not support, so they are not judged
            flags |= quote_problems(chunk, segments)
        page, section = _locate(chunk, segments)
        accepted.append(
            Evidence(chunk_id=chunk_id, quote=html.unescape(item.quote).strip(), page=page, section=section)
        )
    return accepted, sorted(flags)


def finalize(
    control_id: str,
    raw: RawAssessment,
    chunks: list[Chunk],
    *,
    model: str,
    from_cache: bool = False,
    reference: str = "",
) -> Finding:
    """Turn a raw assessment into a finding: verify the quotes, then apply the downgrade rules.

    ``reference`` is what the control itself says. A number in the model's own sentences must be in the passages it was shown or in
    that text; one that is in neither is flagged and named in the rationale, and the status is left as the model gave it."""
    evidence, flags = verify_evidence(raw, chunks)
    flag_set = set(flags)
    status = raw.status
    rationale = raw.rationale.strip()
    confidence = raw.confidence
    missing = [m.strip() for m in raw.missing_elements if m.strip()]
    allowed = allowed_quantities([c.text for c in chunks] + [reference])
    invented: list[str] = []
    for own_words in (raw.rationale, *missing):
        invented += [q for q in ungrounded_quantities(own_words, allowed) if q not in invented]
    if status in ("met", "partial") and not evidence:
        status = "gap"
        confidence = min(confidence, 0.4)
        flag_set.add("unsupported_downgraded")
        rationale = (
            rationale + " "
        ).lstrip() + "(No quoted support could be verified in the document, so this is recorded as a gap.)"
    if status == "met" and missing:
        status = "partial"
        flag_set.add("met_with_missing_downgraded")
    if invented:
        flag_set.add("ungrounded_quantity")
        rationale = (rationale + " ").lstrip() + (
            f"(Check: this explanation mentions {', '.join(invented)}, which the passages the reviewer was shown do not contain.)"
        )
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
