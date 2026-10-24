"""Shared data models for the document pipeline (parsing, chunking, retrieval)."""

from __future__ import annotations

from pydantic import BaseModel


class Block(BaseModel):
    """A paragraph, table row or heading read from a document, in reading order."""

    text: str
    page: int | None = None  # None for formats without pages (DOCX, TXT, Markdown)
    section: str = ""  # heading path at this point, e.g. "Access Control > Password Management"
    is_heading: bool = False


class Chunk(BaseModel):
    """A passage of the document that can be retrieved and cited."""

    id: str  # "c0001"
    ord: int
    text: str
    page: int | None = None
    section: str = ""
    n_words: int
