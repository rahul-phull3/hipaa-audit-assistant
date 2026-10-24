"""Split parsed blocks into overlapping passages that can be retrieved and cited."""

from __future__ import annotations

import re

from hipaa_audit.models import Block, Chunk

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9(\"'])")


def _words(text: str) -> int:
    return len(text.split())


def split_long(text: str, target: int) -> list[str]:
    """Split a paragraph into pieces of at most ``target`` words, on sentence boundaries where possible."""
    if _words(text) <= target:
        return [text]
    pieces: list[str] = []
    current: list[str] = []
    count = 0
    for sentence in _SENTENCE_SPLIT.split(text):
        sentence = sentence.strip()
        n = _words(sentence)
        if n > target:  # a very long sentence: split on words
            if current:
                pieces.append(" ".join(current))
                current, count = [], 0
            words = sentence.split()
            pieces.extend(" ".join(words[i : i + target]) for i in range(0, len(words), target))
            continue
        if current and count + n > target:
            pieces.append(" ".join(current))
            current, count = [], 0
        current.append(sentence)
        count += n
    if current:
        pieces.append(" ".join(current))
    return pieces


def _tail(text: str, max_words: int) -> str:
    """The last sentences of ``text`` that fit in ``max_words`` (empty if even the last sentence is too long)."""
    if max_words <= 0:
        return ""
    picked: list[str] = []
    count = 0
    for sentence in reversed(_SENTENCE_SPLIT.split(text)):
        n = _words(sentence)
        if count + n > max_words:
            break
        picked.append(sentence.strip())
        count += n
    return " ".join(reversed(picked))


def chunk_blocks(
    blocks: list[Block], *, target_words: int = 200, overlap_words: int = 40, min_words: int = 40
) -> list[Chunk]:
    """Greedy chunking in reading order.

    A chunk holds whole paragraphs up to ``target_words``. A long paragraph is split on sentence boundaries. When a chunk
    closes because it is full, the next one starts with the last sentences of the previous one (up to ``overlap_words``) so a
    requirement that straddles a boundary is still retrievable. A new heading closes the open chunk once it has at least
    ``min_words``; shorter sections are merged into the next chunk rather than left as fragments.
    """
    chunks: list[Chunk] = []
    parts: list[str] = []
    body_words = 0  # words that are not overlap
    total_words = 0
    page: int | None = None
    section = ""
    pending_tail = ""

    def flush(*, with_overlap: bool) -> None:
        nonlocal parts, body_words, total_words, pending_tail
        if parts and body_words > 0:
            text = "\n".join(parts)
            chunks.append(
                Chunk(
                    id=f"c{len(chunks) + 1:04d}",
                    ord=len(chunks),
                    text=text,
                    page=page,
                    section=section,
                    n_words=_words(text),
                )
            )
            pending_tail = _tail(text, overlap_words) if with_overlap else ""
        parts, body_words, total_words = [], 0, 0

    for block in blocks:
        if block.is_heading and body_words >= min_words:
            flush(with_overlap=False)
        pieces = [block.text] if block.is_heading else split_long(block.text, target_words)
        for piece in pieces:
            n = _words(piece)
            if body_words > 0 and total_words + n > target_words:
                flush(with_overlap=True)
            if not parts:
                page, section = block.page, block.section
                if pending_tail:
                    parts.append(pending_tail)
                    total_words += _words(pending_tail)
                    pending_tail = ""
            parts.append(piece)
            body_words += n
            total_words += n
    flush(with_overlap=False)
    return chunks
