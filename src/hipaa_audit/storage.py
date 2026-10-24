"""SQLite persistence: audits, the chunks they were run against, findings, and cached model answers.

One connection guarded by a lock is plenty for this service (small writes, WAL mode so readers do not block the writer). The
schema is versioned with ``PRAGMA user_version`` so a later release can migrate it. The uploaded file itself is never stored,
only its hash and the extracted text chunks needed to show evidence in context.
"""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from hipaa_audit.assess.schema import RawAssessment
from hipaa_audit.models import Chunk, Finding, Span, Usage

SCHEMA_VERSION = 1
AuditStatus = Literal["queued", "running", "completed", "failed", "cancelled"]
ACTIVE_STATUSES = ("queued", "running")

_SCHEMA = """
CREATE TABLE audits (
    id              TEXT PRIMARY KEY,
    filename        TEXT NOT NULL,
    sha256          TEXT NOT NULL,
    size_bytes      INTEGER NOT NULL,
    pages           INTEGER,
    status          TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    started_at      TEXT,
    finished_at     TEXT,
    backend         TEXT NOT NULL,
    embedder        TEXT NOT NULL DEFAULT '',
    catalog_version TEXT NOT NULL,
    prompt_version  TEXT NOT NULL,
    control_ids     TEXT NOT NULL,
    total_controls  INTEGER NOT NULL,
    done_controls   INTEGER NOT NULL DEFAULT 0,
    chunk_count     INTEGER NOT NULL,
    usage           TEXT NOT NULL DEFAULT '{}',
    error           TEXT
);
CREATE INDEX audits_created ON audits(created_at DESC);

CREATE TABLE chunks (
    audit_id TEXT NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    chunk_id TEXT NOT NULL,
    ord      INTEGER NOT NULL,
    page     INTEGER,
    section  TEXT NOT NULL,
    text     TEXT NOT NULL,
    n_words  INTEGER NOT NULL,
    spans    TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (audit_id, chunk_id)
);

CREATE TABLE findings (
    audit_id   TEXT NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    control_id TEXT NOT NULL,
    position   INTEGER NOT NULL,
    status     TEXT NOT NULL,
    data       TEXT NOT NULL,
    PRIMARY KEY (audit_id, control_id)
);

CREATE TABLE assessment_cache (
    key        TEXT PRIMARY KEY,
    audit_id   TEXT NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    data       TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX cache_audit ON assessment_cache(audit_id);
"""


def utcnow() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def new_id() -> str:
    return secrets.token_hex(8)


class StorageError(RuntimeError):
    """The database cannot be used (for example, it was written by a newer version)."""


class AuditRecord(BaseModel):
    id: str
    filename: str
    sha256: str
    size_bytes: int
    pages: int | None = None
    status: AuditStatus = "queued"
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    backend: str
    embedder: str = ""
    catalog_version: str
    prompt_version: str
    control_ids: list[str]
    total_controls: int
    done_controls: int = 0
    chunk_count: int
    usage: Usage = Field(default_factory=Usage)
    error: str | None = None


_AUDIT_COLUMNS = (
    "id, filename, sha256, size_bytes, pages, status, created_at, started_at, finished_at, backend, embedder, catalog_version, "
    "prompt_version, control_ids, total_controls, done_controls, chunk_count, usage, error"
)


_CHUNK_COLUMNS = "chunk_id, ord, page, section, text, n_words, spans"


def _chunk_from_row(r: sqlite3.Row) -> Chunk:
    return Chunk(
        id=r["chunk_id"],
        ord=r["ord"],
        page=r["page"],
        section=r["section"],
        text=r["text"],
        n_words=r["n_words"],
        spans=[Span(**s) for s in json.loads(r["spans"] or "[]")],
    )


def _audit_from_row(row: sqlite3.Row) -> AuditRecord:
    data = dict(row)
    data["control_ids"] = json.loads(data["control_ids"])
    data["usage"] = Usage.model_validate_json(data["usage"] or "{}")
    return AuditRecord(**data)


class Repository:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            parent = Path(self.path).expanduser().resolve().parent
            parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys = ON")
        self._db.execute("PRAGMA busy_timeout = 5000")
        if self.path != ":memory:":
            self._db.execute("PRAGMA journal_mode = WAL")
            self._db.execute("PRAGMA synchronous = NORMAL")
        try:
            self._migrate()
        except BaseException:
            self._db.close()  # do not leak the connection when the database is unusable
            raise
        if self.path != ":memory:":
            try:
                os.chmod(self.path, 0o600)  # the file holds excerpts of policy documents
            except OSError:  # pragma: no cover - e.g. a filesystem without permissions
                pass

    # -- plumbing ---------------------------------------------------------------------------------------------------

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield self._db
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            else:
                self._db.execute("COMMIT")

    def _migrate(self) -> None:
        with self._lock:
            version = self._db.execute("PRAGMA user_version").fetchone()[0]
            if version > SCHEMA_VERSION:
                raise StorageError(
                    f"{self.path} was written by a newer version of this application (schema {version}, this one supports {SCHEMA_VERSION})"
                )
            if version == 0:
                self._db.execute("BEGIN IMMEDIATE")
                try:
                    for statement in filter(None, (s.strip() for s in _SCHEMA.split(";"))):
                        self._db.execute(statement)
                    self._db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                except BaseException:
                    self._db.execute("ROLLBACK")
                    raise
                self._db.execute("COMMIT")

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def ping(self) -> bool:
        with self._lock:
            return self._db.execute("SELECT 1").fetchone()[0] == 1

    # -- audits -----------------------------------------------------------------------------------------------------

    def create_audit(self, record: AuditRecord, chunks: list[Chunk]) -> None:
        with self._tx() as db:
            db.execute(
                f"INSERT INTO audits ({_AUDIT_COLUMNS}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    record.id,
                    record.filename,
                    record.sha256,
                    record.size_bytes,
                    record.pages,
                    record.status,
                    record.created_at,
                    record.started_at,
                    record.finished_at,
                    record.backend,
                    record.embedder,
                    record.catalog_version,
                    record.prompt_version,
                    json.dumps(record.control_ids),
                    record.total_controls,
                    record.done_controls,
                    record.chunk_count,
                    record.usage.model_dump_json(),
                    record.error,
                ),
            )
            db.executemany(
                "INSERT INTO chunks (audit_id, chunk_id, ord, page, section, text, n_words, spans) VALUES (?,?,?,?,?,?,?,?)",
                [
                    (
                        record.id,
                        c.id,
                        c.ord,
                        c.page,
                        c.section,
                        c.text,
                        c.n_words,
                        json.dumps([s.model_dump() for s in c.spans]),
                    )
                    for c in chunks
                ],
            )

    def get_audit(self, audit_id: str) -> AuditRecord | None:
        with self._lock:
            row = self._db.execute(f"SELECT {_AUDIT_COLUMNS} FROM audits WHERE id = ?", (audit_id,)).fetchone()
        return _audit_from_row(row) if row else None

    def list_audits(self, limit: int = 50, offset: int = 0) -> list[AuditRecord]:
        with self._lock:
            rows = self._db.execute(
                f"SELECT {_AUDIT_COLUMNS} FROM audits ORDER BY created_at DESC, id LIMIT ? OFFSET ?", (limit, offset)
            ).fetchall()
        return [_audit_from_row(r) for r in rows]

    def count_audits(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM audits").fetchone()[0]

    def count_active(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM audits WHERE status IN ('queued', 'running')").fetchone()[0]

    def claim_for_run(self, audit_id: str) -> bool:
        """queued -> running, atomically. False when the audit was cancelled or deleted while it waited."""
        with self._tx() as db:
            cur = db.execute(
                "UPDATE audits SET status = 'running', started_at = ? WHERE id = ? AND status = 'queued'",
                (utcnow(), audit_id),
            )
            return cur.rowcount == 1

    def finish(
        self, audit_id: str, status: AuditStatus, *, usage: Usage | None = None, error: str | None = None
    ) -> None:
        with self._tx() as db:
            db.execute(
                "UPDATE audits SET status = ?, finished_at = ?, usage = COALESCE(?, usage), error = ? WHERE id = ?",
                (status, utcnow(), usage.model_dump_json() if usage else None, error, audit_id),
            )

    def cancel_if_queued(self, audit_id: str) -> bool:
        with self._tx() as db:
            cur = db.execute(
                "UPDATE audits SET status = 'cancelled', finished_at = ? WHERE id = ? AND status = 'queued'",
                (utcnow(), audit_id),
            )
            return cur.rowcount == 1

    def fail_interrupted(self, reason: str) -> int:
        """Called at start-up: audits left queued or running by a previous process can never finish."""
        with self._tx() as db:
            cur = db.execute(
                "UPDATE audits SET status = 'failed', finished_at = ?, error = ? WHERE status IN ('queued', 'running')",
                (utcnow(), reason),
            )
            return cur.rowcount

    def delete_audit(self, audit_id: str) -> bool:
        with self._tx() as db:
            return db.execute("DELETE FROM audits WHERE id = ?", (audit_id,)).rowcount == 1

    def delete_finished_before(self, cutoff_iso: str) -> int:
        """Retention: remove finished audits created before the cutoff (children go with them)."""
        with self._tx() as db:
            return db.execute(
                "DELETE FROM audits WHERE created_at < ? AND status NOT IN ('queued', 'running')", (cutoff_iso,)
            ).rowcount

    # -- findings and chunks ----------------------------------------------------------------------------------------

    def save_finding(self, audit_id: str, position: int, finding: Finding) -> int:
        """Store one finding and return how many the audit has now."""
        with self._tx() as db:
            db.execute(
                "INSERT OR REPLACE INTO findings (audit_id, control_id, position, status, data) VALUES (?,?,?,?,?)",
                (audit_id, finding.control_id, position, finding.status, finding.model_dump_json()),
            )
            done = db.execute("SELECT COUNT(*) FROM findings WHERE audit_id = ?", (audit_id,)).fetchone()[0]
            db.execute("UPDATE audits SET done_controls = ? WHERE id = ?", (done, audit_id))
            return done

    def finding_counts(self, audit_ids: list[str]) -> dict[str, dict[str, int]]:
        """Findings per status for several audits in one query (for list views)."""
        if not audit_ids:
            return {}
        marks = ",".join("?" * len(audit_ids))
        with self._lock:
            rows = self._db.execute(
                f"SELECT audit_id, status, COUNT(*) AS n FROM findings WHERE audit_id IN ({marks}) GROUP BY audit_id, status",
                audit_ids,
            ).fetchall()
        counts: dict[str, dict[str, int]] = {a: {} for a in audit_ids}
        for r in rows:
            counts[r["audit_id"]][r["status"]] = r["n"]
        return counts

    def get_findings(self, audit_id: str) -> list[Finding]:
        with self._lock:
            rows = self._db.execute(
                "SELECT data FROM findings WHERE audit_id = ? ORDER BY position", (audit_id,)
            ).fetchall()
        return [Finding.model_validate_json(r["data"]) for r in rows]

    def get_chunks(self, audit_id: str) -> list[Chunk]:
        with self._lock:
            rows = self._db.execute(
                f"SELECT {_CHUNK_COLUMNS} FROM chunks WHERE audit_id = ? ORDER BY ord", (audit_id,)
            ).fetchall()
        return [_chunk_from_row(r) for r in rows]

    def get_chunk(self, audit_id: str, chunk_id: str) -> Chunk | None:
        with self._lock:
            r = self._db.execute(
                f"SELECT {_CHUNK_COLUMNS} FROM chunks WHERE audit_id = ? AND chunk_id = ?", (audit_id, chunk_id)
            ).fetchone()
        return None if r is None else _chunk_from_row(r)

    # -- assessment cache -------------------------------------------------------------------------------------------

    def cache_get(self, key: str) -> RawAssessment | None:
        with self._lock:
            row = self._db.execute("SELECT data FROM assessment_cache WHERE key = ?", (key,)).fetchone()
        return RawAssessment.model_validate_json(row["data"]) if row else None

    def cache_put(self, key: str, audit_id: str, raw: RawAssessment) -> None:
        with self._tx() as db:
            db.execute(
                "INSERT OR REPLACE INTO assessment_cache (key, audit_id, data, created_at) VALUES (?,?,?,?)",
                (key, audit_id, raw.model_dump_json(), utcnow()),
            )

    def cache_size(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM assessment_cache").fetchone()[0]


class SqliteCache:
    """The engine's cache protocol on top of the repository. Entries belong to the audit that created them, so deleting an
    audit also removes the quotes it caused to be cached."""

    def __init__(self, repo: Repository, audit_id: str) -> None:
        self._repo = repo
        self._audit_id = audit_id

    def get(self, key: str) -> RawAssessment | None:
        return self._repo.cache_get(key)

    def put(self, key: str, raw: RawAssessment) -> None:
        self._repo.cache_put(key, self._audit_id, raw)
