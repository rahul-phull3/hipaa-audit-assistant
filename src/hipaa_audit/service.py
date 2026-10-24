"""The application service: everything the HTTP API and the CLI do, with no web framework involved.

Uploading is synchronous and cheap to reason about (validate, parse, chunk, store). Running is a background coroutine that
indexes the chunks, assesses the selected controls and records each finding as it arrives, so a client can poll progress.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from hipaa_audit import __version__
from hipaa_audit.assess.engine import AssessmentEngine
from hipaa_audit.assess.factory import make_backend
from hipaa_audit.assess.llm import LLMAuthError, LLMBackend
from hipaa_audit.assess.prompts import PROMPT_VERSION
from hipaa_audit.catalog import Catalog, load_catalog
from hipaa_audit.config import Settings
from hipaa_audit.ingest import ALLOWED_EXTENSIONS, UnsupportedDocument, ingest_document
from hipaa_audit.report import FLAG_LABELS, build_report, control_summary, render_json, render_markdown, summarize
from hipaa_audit.retrieval import Embedder, HybridIndex, make_embedder
from hipaa_audit.storage import ACTIVE_STATUSES, AuditRecord, Repository, SqliteCache, new_id, utcnow

log = logging.getLogger(__name__)

MAX_PENDING_AUDITS = 20
MAX_FILENAME_CHARS = 150


class ServiceError(Exception):
    """Base class. The API maps each subclass to an HTTP status."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class NotFound(ServiceError):
    pass


class InvalidRequest(ServiceError):
    pass


class TooLarge(ServiceError):
    pass


class Conflict(ServiceError):
    pass


class Busy(ServiceError):
    pass


class Unavailable(ServiceError):
    pass


def safe_filename(name: str | None) -> str:
    """The base name only, without control characters, at a sensible length."""
    base = re.split(r"[\\/]", name or "")[-1]
    base = re.sub(r"[\x00-\x1f\x7f]", "", base).strip().strip(".")
    return (base[:MAX_FILENAME_CHARS] or "document")


class AuditService:
    def __init__(
        self,
        settings: Settings,
        repo: Repository,
        *,
        backend: LLMBackend | None,
        backend_error: str | None = None,
        embedder: Embedder,
        catalog: Catalog | None = None,
    ) -> None:
        self.settings = settings
        self.repo = repo
        self.backend = backend
        self.backend_error = backend_error
        self.embedder = embedder
        self.catalog = catalog or load_catalog()
        self._slots = asyncio.Semaphore(settings.max_active_audits)
        self._tasks: set[asyncio.Task[None]] = set()
        self._cancel: dict[str, asyncio.Event] = {}

    @classmethod
    def from_settings(cls, settings: Settings) -> AuditService:
        repo = Repository(settings.db_path)
        backend: LLMBackend | None = None
        backend_error: str | None = None
        try:
            backend = make_backend(settings)
        except RuntimeError as exc:
            backend_error = str(exc)
            log.warning("model backend not ready: %s", exc)
        service = cls(settings, repo, backend=backend, backend_error=backend_error, embedder=make_embedder(settings.embedder))
        service.startup()
        return service

    # -- lifecycle --------------------------------------------------------------------------------------------------

    def startup(self) -> None:
        interrupted = self.repo.fail_interrupted("The server restarted while this audit was waiting or running.")
        if interrupted:
            log.warning("marked %d interrupted audit(s) as failed", interrupted)
        if self.settings.retention_days:
            cutoff = (datetime.now(UTC) - timedelta(days=self.settings.retention_days)).isoformat(timespec="seconds")
            removed = self.repo.delete_finished_before(cutoff)
            if removed:
                log.info("retention: removed %d audit(s) older than %d days", removed, self.settings.retention_days)

    async def shutdown(self) -> None:
        for event in self._cancel.values():
            event.set()
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self.repo.close()

    def health(self) -> dict[str, Any]:
        return {
            "status": "ok" if self.repo.ping() else "degraded",
            "version": __version__,
            "backend": {
                "ready": self.backend is not None,
                "name": self.backend.name if self.backend else None,
                "is_ai_model": bool(self.backend and not self.backend.name.startswith("heuristic")),
                "error": self.backend_error,
            },
            "embedder": self.embedder.name,
            "catalog": {"version": self.catalog.meta.version, "controls": len(self.catalog.controls)},
            "limits": {"max_upload_mb": self.settings.max_upload_mb, "max_pages": self.settings.max_pages},
            "active_audits": self.repo.count_active(),
        }

    # -- creating audits --------------------------------------------------------------------------------------------

    def _new_record(self, filename: str, sha256: str, size: int, pages: int | None, control_ids: list[str], chunk_count: int) -> AuditRecord:
        assert self.backend is not None
        return AuditRecord(
            id=new_id(),
            filename=filename,
            sha256=sha256,
            size_bytes=size,
            pages=pages,
            created_at=utcnow(),
            backend=self.backend.name,
            embedder=self.embedder.name,
            catalog_version=self.catalog.meta.version,
            prompt_version=PROMPT_VERSION,
            control_ids=control_ids,
            total_controls=len(control_ids),
            chunk_count=chunk_count,
        )

    def _require_capacity(self) -> None:
        if self.backend is None:
            raise Unavailable(self.backend_error or "No model backend is configured.")
        if self.repo.count_active() >= MAX_PENDING_AUDITS:
            raise Busy("Too many audits are waiting or running. Try again in a few minutes.")

    def _resolve_controls(self, control_ids: list[str] | None) -> list[str]:
        try:
            return [c.id for c in self.catalog.select(control_ids)]
        except KeyError as exc:
            raise InvalidRequest(str(exc.args[0])) from None

    def submit(self, filename: str | None, data: bytes, control_ids: list[str] | None = None) -> AuditRecord:
        """Validate, parse and store an upload. The audit is queued; call ``start`` to run it."""
        self._require_capacity()
        name = safe_filename(filename)
        if not name.lower().endswith(ALLOWED_EXTENSIONS):
            raise InvalidRequest(f"Unsupported file type. Upload one of: {', '.join(ALLOWED_EXTENSIONS)}.")
        if not data:
            raise InvalidRequest("The file is empty.")
        if len(data) > self.settings.max_upload_bytes:
            raise TooLarge(f"The file is larger than the {self.settings.max_upload_mb} MB limit.")
        selected = self._resolve_controls(control_ids)
        try:
            chunks, pages = ingest_document(name, data, max_pages=self.settings.max_pages)
        except UnsupportedDocument as exc:
            raise InvalidRequest(str(exc)) from exc
        if not chunks:
            raise InvalidRequest("No readable text was found in the file.")
        record = self._new_record(name, hashlib.sha256(data).hexdigest(), len(data), pages, selected, len(chunks))
        self.repo.create_audit(record, chunks)
        return record

    def rerun(self, audit_id: str) -> AuditRecord:
        """A new audit over the same stored text. Controls whose answers are cached cost nothing the second time."""
        self._require_capacity()
        old = self.get(audit_id)
        if old.status in ACTIVE_STATUSES:
            raise Conflict("This audit is still running.")
        chunks = self.repo.get_chunks(audit_id)
        record = self._new_record(old.filename, old.sha256, old.size_bytes, old.pages, list(old.control_ids), len(chunks))
        self.repo.create_audit(record, chunks)
        return record

    # -- running audits ---------------------------------------------------------------------------------------------

    def start(self, audit_id: str) -> asyncio.Task[None]:
        task = asyncio.create_task(self.run(audit_id), name=f"audit-{audit_id}")
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    async def run(self, audit_id: str) -> None:
        """Run one audit to completion. Never raises (except cancellation at shutdown); failures are recorded on the audit."""
        try:
            async with self._slots:
                await self._execute(audit_id)
        except asyncio.CancelledError:
            self.repo.finish(audit_id, "failed", error="The server stopped while this audit was running.")
            raise
        except Exception:  # noqa: BLE001 - the audit records a generic message; the traceback goes to the log
            log.exception("audit %s failed", audit_id)
            self.repo.finish(audit_id, "failed", error="The audit stopped because of an unexpected error. See the server log.")

    async def _execute(self, audit_id: str) -> None:
        record = self.repo.get_audit(audit_id)
        if record is None or not self.repo.claim_for_run(audit_id):
            return  # deleted or cancelled while it waited for a slot
        assert self.backend is not None
        cancel = self._cancel.setdefault(audit_id, asyncio.Event())
        try:
            chunks = self.repo.get_chunks(audit_id)
            index = await asyncio.to_thread(HybridIndex, chunks, self.embedder)
            controls = self.catalog.select(record.control_ids)
            position = {c.id: i for i, c in enumerate(controls)}
            cache = SqliteCache(self.repo, audit_id) if self.settings.cache_enabled else None
            engine = AssessmentEngine(
                self.backend, index, top_k=self.settings.top_k, concurrency=self.settings.concurrency, cache=cache
            )
            result = await engine.run(
                controls, on_finding=lambda f: self.repo.save_finding(audit_id, position[f.control_id], f), cancel=cancel
            )
            if cancel.is_set():
                self.repo.finish(audit_id, "cancelled", usage=result.usage)
            elif result.findings and len(result.errors) == len(result.findings):
                reason = next(iter(result.errors.values()))[:300]
                self.repo.finish(audit_id, "failed", usage=result.usage, error=f"None of the controls could be assessed. {reason}")
            else:
                self.repo.finish(audit_id, "completed", usage=result.usage)
        except LLMAuthError:
            self.repo.finish(
                audit_id,
                "failed",
                error="The Anthropic API rejected the API key or the request. Check ANTHROPIC_API_KEY and the model name.",
            )
        finally:
            self._cancel.pop(audit_id, None)

    def cancel(self, audit_id: str) -> AuditRecord:
        record = self.get(audit_id)
        if record.status == "queued" and self.repo.cancel_if_queued(audit_id):
            return self.get(audit_id)
        if record.status == "running":
            event = self._cancel.get(audit_id)
            if event is not None:
                event.set()  # the run stops starting new controls and marks the audit cancelled
        return self.get(audit_id)

    async def wait(self, audit_id: str) -> AuditRecord:
        """Wait for a started audit to finish (used by the CLI and tests)."""
        for task in list(self._tasks):
            if task.get_name() == f"audit-{audit_id}":
                await task
        return self.get(audit_id)

    # -- reading ----------------------------------------------------------------------------------------------------

    def get(self, audit_id: str) -> AuditRecord:
        record = self.repo.get_audit(audit_id)
        if record is None:
            raise NotFound("No audit with that id.")
        return record

    def list_audits(self, limit: int = 50, offset: int = 0) -> list[AuditRecord]:
        return self.repo.list_audits(limit=max(1, min(limit, 200)), offset=max(0, offset))

    def finding_views(self, audit_id: str) -> list[dict[str, Any]]:
        self.get(audit_id)
        controls = {c.id: c for c in self.catalog.controls}
        views = []
        for f in self.repo.get_findings(audit_id):
            view = f.model_dump(exclude={"control_id"})
            view["control"] = control_summary(controls.get(f.control_id), f.control_id)
            views.append(view)
        return views

    def summary(self, audit_id: str) -> dict[str, Any]:
        self.get(audit_id)
        return summarize(self.repo.get_findings(audit_id), self.catalog)

    def chunk_context(self, audit_id: str, chunk_id: str) -> dict[str, Any]:
        self.get(audit_id)
        chunk = self.repo.get_chunk(audit_id, chunk_id)
        if chunk is None:
            raise NotFound("No such passage in this audit.")
        neighbours = {c.ord: c for c in self.repo.get_chunks(audit_id) if abs(c.ord - chunk.ord) == 1}

        def brief(c):
            return None if c is None else {"id": c.id, "page": c.page, "section": c.section, "text": c.text}

        return {**brief(chunk), "previous": brief(neighbours.get(chunk.ord - 1)), "next": brief(neighbours.get(chunk.ord + 1))}

    def report(self, audit_id: str, fmt: str) -> tuple[str, str, str]:
        """Returns (content, media type, suggested file name)."""
        record = self.get(audit_id)
        if fmt not in ("md", "json"):
            raise InvalidRequest("format must be md or json")
        report = build_report(record, self.repo.get_findings(audit_id), self.catalog)
        stem = re.sub(r"[^A-Za-z0-9._-]+", "_", record.filename.rsplit(".", 1)[0]) or "audit"
        if fmt == "json":
            return render_json(report), "application/json", f"hipaa-review-{stem}.json"
        return render_markdown(report), "text/markdown; charset=utf-8", f"hipaa-review-{stem}.md"

    def delete(self, audit_id: str) -> None:
        record = self.get(audit_id)
        if record.status in ACTIVE_STATUSES:
            raise Conflict("The audit is still waiting or running. Cancel it first.")
        self.repo.delete_audit(audit_id)

    def control_catalog(self) -> dict[str, Any]:
        return {
            "version": self.catalog.meta.version,
            "regulation": self.catalog.meta.regulation,
            "rule_status": self.catalog.meta.rule_status,
            "notes": self.catalog.meta.notes,
            "flag_labels": FLAG_LABELS,
            "controls": [
                {**control_summary(c, c.id), "expectation": c.expectation, "elements": [x.text for x in c.criteria]}
                for c in self.catalog.controls
            ],
        }

