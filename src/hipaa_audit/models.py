"""Shared data models for the document pipeline (parsing, chunking, retrieval)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Status = Literal["met", "partial", "gap"]  # what a model may answer
FindingStatus = Literal["met", "partial", "gap", "error"]  # "error": the control could not be assessed


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


class Evidence(BaseModel):
    """A quote the server has checked against the source document."""

    chunk_id: str
    quote: str
    page: int | None = None
    section: str = ""


class Usage(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_creation_tokens: int = 0

    def __add__(self, other: Usage) -> Usage:
        return Usage(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
            cache_read_tokens=self.cache_read_tokens + other.cache_read_tokens,
            cache_creation_tokens=self.cache_creation_tokens + other.cache_creation_tokens,
        )


class Finding(BaseModel):
    control_id: str
    status: FindingStatus
    rationale: str
    evidence: list[Evidence] = Field(default_factory=list)
    missing_elements: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    flags: list[str] = Field(default_factory=list)  # e.g. "unsupported_downgraded", "injection_suspected"
    retrieved_chunk_ids: list[str] = Field(default_factory=list)
    model: str = ""
    from_cache: bool = False
