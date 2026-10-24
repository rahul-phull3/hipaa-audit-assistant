"""Document ingestion: parsing and chunking."""

from hipaa_audit.ingest.chunking import chunk_blocks
from hipaa_audit.ingest.parsers import ALLOWED_EXTENSIONS, UnsupportedDocument, parse_document
from hipaa_audit.models import Chunk


def ingest_document(filename: str, data: bytes, *, max_pages: int = 200) -> tuple[list[Chunk], int | None]:
    """Parse an upload and cut it into citable chunks. Returns (chunks, page count or None for formats without pages)."""
    blocks = parse_document(filename, data, max_pages=max_pages)
    pages = [b.page for b in blocks if b.page is not None]
    return chunk_blocks(blocks), (max(pages) if pages else None)


__all__ = ["ALLOWED_EXTENSIONS", "UnsupportedDocument", "chunk_blocks", "ingest_document", "parse_document"]
