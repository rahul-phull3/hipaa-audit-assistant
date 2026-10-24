import asyncio
import json
import sqlite3
import unittest
from datetime import UTC, datetime, timedelta
from unittest import mock

from hipaa_audit import service as service_module
from hipaa_audit.assess.llm import HeuristicBackend, LLMAuthError, LLMUnavailable
from hipaa_audit.assess.schema import RawAssessment
from hipaa_audit.catalog import load_catalog
from hipaa_audit.config import Settings
from hipaa_audit.models import Usage
from hipaa_audit.retrieval import HashingEmbedder
from hipaa_audit.service import (
    AuditService,
    Busy,
    Conflict,
    InvalidRequest,
    NotFound,
    TooLarge,
    Unavailable,
    safe_filename,
)
from hipaa_audit.storage import Repository
from tests.fixtures import make_docx, make_pdf

CATALOG = load_catalog()
IDS = [
    "data-backup-plan",
    "password-management",
    "automatic-logoff",
    "facility-security-plan",
    "security-awareness-training",
]


def policy_text(control_ids=IDS) -> bytes:
    parts = ["INFORMATION SECURITY POLICY", ""]
    for i, cid in enumerate(control_ids, start=1):
        control = CATALOG.get(cid)
        parts += [f"{i}. {control.title}", " ".join(c.synth[0] for c in control.criteria), ""]
    return "\n".join(parts).encode()


class SlowBackend:
    name = "scripted:slow"

    def __init__(self, delay=0.0, error=None):
        self.delay, self.error, self.calls = delay, error, 0

    async def assess(self, control, excerpts):
        self.calls += 1
        await asyncio.sleep(self.delay)
        if self.error:
            raise self.error
        return RawAssessment(status="gap", rationale="Nothing.", confidence=0.5), Usage(
            input_tokens=10, output_tokens=1
        )


def make_service(backend=None, *, backend_error=None, repo=None, **settings):
    values = {"llm_backend": "heuristic", "concurrency": 2, **settings}
    return AuditService(
        Settings(**values),
        repo or Repository(":memory:"),
        backend=backend if backend is not None or backend_error else HeuristicBackend(),
        backend_error=backend_error,
        embedder=HashingEmbedder(),
    )


class SubmitTests(unittest.TestCase):
    def setUp(self):
        self.svc = make_service()
        self.addCleanup(self.svc.repo.close)

    def test_text_upload_is_parsed_and_stored(self):
        record = self.svc.submit("../../etc/Policy v2.txt", policy_text())
        self.assertEqual((record.filename, record.status), ("Policy v2.txt", "queued"))
        self.assertEqual(record.total_controls, len(CATALOG.controls))
        self.assertGreater(record.chunk_count, 0)
        self.assertEqual(len(record.sha256), 64)
        self.assertEqual(
            (record.backend, record.embedder, record.catalog_version),
            ("heuristic:keywords", "hashing", CATALOG.meta.version),
        )
        self.assertEqual(len(self.svc.repo.get_chunks(record.id)), record.chunk_count)

    def test_pdf_page_count_and_docx_are_supported(self):
        pdf = make_pdf(
            [
                ["Backups are taken daily and stored off site. " * 6],
                ["Passwords must never be shared with anyone. " * 6],
            ]
        )
        self.assertEqual(self.svc.submit("p.pdf", pdf).pages, 2)
        self.assertIsNone(self.svc.submit("p.docx", make_docx()).pages)

    def test_selected_controls_are_kept_in_catalog_order(self):
        record = self.svc.submit("p.txt", policy_text(), ["password-management", "data-backup-plan"])
        self.assertEqual(
            record.control_ids, [c.id for c in CATALOG.controls if c.id in ("password-management", "data-backup-plan")]
        )
        self.assertEqual(record.total_controls, 2)

    def test_validation(self):
        cases = [
            ("policy.exe", b"MZ" + b"x" * 100, InvalidRequest),
            ("policy.txt", b"", InvalidRequest),
            ("policy.txt", b"\x00\x01\x02binary" * 50, InvalidRequest),
            ("policy.pdf", b"this is not a pdf", InvalidRequest),
            ("policy.docx", b"this is not a zip", InvalidRequest),
            ("policy.txt", b"   \n  \n", InvalidRequest),
        ]
        for name, data, error in cases:
            with self.assertRaises(error, msg=name):
                self.svc.submit(name, data)
        with self.assertRaises(InvalidRequest):
            self.svc.submit("p.txt", policy_text(), ["not-a-control"])
        self.assertEqual(self.svc.repo.count_audits(), 0)  # nothing is stored for a rejected upload

    def test_size_limit(self):
        svc = make_service(max_upload_mb=1)
        self.addCleanup(svc.repo.close)
        with self.assertRaises(TooLarge):
            svc.submit("big.txt", b"a " * (1024 * 1024))

    def test_page_limit(self):
        svc = make_service(max_pages=1)
        self.addCleanup(svc.repo.close)
        pdf = make_pdf([["First page text here. " * 5], ["Second page text here. " * 5]])
        with self.assertRaises(InvalidRequest) as ctx:
            svc.submit("p.pdf", pdf)
        self.assertIn("limit", ctx.exception.message)

    def test_no_backend_is_reported_clearly(self):
        svc = make_service(backend_error="ANTHROPIC_API_KEY is not set.")
        self.addCleanup(svc.repo.close)
        with self.assertRaises(Unavailable) as ctx:
            svc.submit("p.txt", policy_text())
        self.assertIn("ANTHROPIC_API_KEY", ctx.exception.message)
        self.assertFalse(svc.health()["backend"]["ready"])

    def test_too_many_waiting_audits(self):
        with mock.patch.object(service_module, "MAX_PENDING_AUDITS", 2):
            self.svc.submit("a.txt", policy_text())
            self.svc.submit("b.txt", policy_text())
            with self.assertRaises(Busy):
                self.svc.submit("c.txt", policy_text())

    def test_safe_filename(self):
        self.assertEqual(safe_filename("C:\\Users\\me\\policy.pdf"), "policy.pdf")
        self.assertEqual(safe_filename("a/b/../c.txt"), "c.txt")
        self.assertEqual(safe_filename("na\x00me\n.md"), "name.md")
        self.assertEqual(safe_filename(None), "document")
        self.assertEqual(safe_filename(".."), "document")
        self.assertEqual(len(safe_filename("x" * 500 + ".txt")), 150)


class RunTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.svc = make_service()
        self.addCleanup(self.svc.repo.close)

    async def test_full_run_with_the_offline_backend(self):
        record = self.svc.submit("policy.txt", policy_text())
        self.svc.start(record.id)
        done = await self.svc.wait(record.id)
        self.assertEqual(done.status, "completed")
        self.assertEqual((done.done_controls, done.total_controls), (48, 48))
        self.assertIsNotNone(done.started_at)
        self.assertIsNotNone(done.finished_at)
        summary = self.svc.summary(record.id)
        self.assertEqual(summary["assessed"], 48)
        self.assertGreaterEqual(summary["met"], 3)  # the controls the sample policy actually covers
        self.assertGreaterEqual(summary["gap"], 30)  # and the ones it does not
        views = self.svc.finding_views(record.id)
        self.assertEqual(len(views), 48)
        self.assertEqual(views[0]["control"]["id"], CATALOG.controls[0].id)
        content, media, name = self.svc.report(record.id, "md")
        self.assertIn("# HIPAA Security Rule policy review", content)
        self.assertEqual((media.split(";")[0], name), ("text/markdown", "hipaa-review-policy.md"))
        as_json = json.loads(self.svc.report(record.id, "json")[0])
        self.assertEqual(as_json["summary"]["assessed"], 48)

    async def test_evidence_can_be_opened_in_context(self):
        record = self.svc.submit("policy.txt", policy_text(), ["data-backup-plan"])
        self.svc.start(record.id)
        await self.svc.wait(record.id)
        finding = self.svc.finding_views(record.id)[0]
        self.assertTrue(finding["evidence"])
        ctx = self.svc.chunk_context(record.id, finding["evidence"][0]["chunk_id"])
        self.assertIn(finding["evidence"][0]["quote"].lower()[:20], ctx["text"].lower())
        with self.assertRaises(NotFound):
            self.svc.chunk_context(record.id, "c9999")
        with self.assertRaises(NotFound):
            self.svc.chunk_context("missing", "c0001")

    async def test_progress_is_visible_while_running(self):
        svc = make_service(SlowBackend(delay=0.02), concurrency=1)
        self.addCleanup(svc.repo.close)
        record = svc.submit("policy.txt", policy_text(), IDS)
        svc.start(record.id)
        seen = set()
        while svc.get(record.id).status in ("queued", "running"):
            seen.add(svc.get(record.id).done_controls)
            await asyncio.sleep(0.01)
        self.assertEqual(svc.get(record.id).status, "completed")
        self.assertGreater(len(seen), 2)  # several distinct progress values were observable
        self.assertEqual(svc.get(record.id).usage.input_tokens, 50)

    async def test_rejected_key_fails_the_audit_with_a_useful_message(self):
        svc = make_service(SlowBackend(error=LLMAuthError("401 invalid x-api-key sk-ant-SECRET")))
        self.addCleanup(svc.repo.close)
        record = svc.submit("policy.txt", policy_text())
        svc.start(record.id)
        done = await svc.wait(record.id)
        self.assertEqual(done.status, "failed")
        self.assertIn("ANTHROPIC_API_KEY", done.error)
        self.assertNotIn("SECRET", done.error)

    async def test_unexpected_errors_never_reach_the_client(self):
        svc = make_service(SlowBackend(error=ValueError("internal detail /srv/app/secret.py")))
        self.addCleanup(svc.repo.close)
        record = svc.submit("policy.txt", policy_text(), IDS)
        svc.start(record.id)
        done = await svc.wait(record.id)
        self.assertEqual(done.status, "failed")  # every control failed, so the audit failed
        self.assertTrue(done.error.startswith("None of the controls could be assessed."))
        self.assertNotIn("secret.py", done.error)
        for view in svc.finding_views(record.id):
            self.assertEqual(view["status"], "error")
            self.assertNotIn("secret.py", view["rationale"])

    async def test_a_service_that_is_down_fails_the_audit_with_the_reason(self):
        svc = make_service(SlowBackend(error=LLMUnavailable("Anthropic API error: overloaded")))
        self.addCleanup(svc.repo.close)
        record = svc.submit("policy.txt", policy_text(), IDS)
        svc.start(record.id)
        done = await svc.wait(record.id)
        self.assertEqual(done.status, "failed")
        self.assertIn("overloaded", done.error)
        self.assertEqual(done.done_controls, len(IDS))  # the error findings are kept so they can be seen

    async def test_some_failures_still_complete_the_audit(self):
        class Flaky(SlowBackend):
            async def assess(self, control, excerpts):
                if control.id == "password-management":
                    raise LLMUnavailable("timeout")
                return await super().assess(control, excerpts)

        svc = make_service(Flaky())
        self.addCleanup(svc.repo.close)
        record = svc.submit("policy.txt", policy_text(), IDS)
        svc.start(record.id)
        done = await svc.wait(record.id)
        self.assertEqual(done.status, "completed")
        summary = svc.summary(record.id)
        self.assertEqual((summary["error"], summary["gap"]), (1, len(IDS) - 1))
        rerun = svc.rerun(record.id)  # the controls that worked are cached; only the failed one is asked again
        svc.start(rerun.id)
        await svc.wait(rerun.id)
        self.assertEqual(svc.summary(rerun.id)["error"], 1)
        self.assertEqual(sum(v["from_cache"] for v in svc.finding_views(rerun.id)), len(IDS) - 1)

    async def test_cancel_a_queued_audit(self):
        svc = make_service(SlowBackend(delay=0.05), max_active_audits=1, concurrency=1)
        self.addCleanup(svc.repo.close)
        first = svc.submit("a.txt", policy_text(), IDS)
        second = svc.submit("b.txt", policy_text(), IDS)
        svc.start(first.id)
        svc.start(second.id)
        await asyncio.sleep(0.02)
        self.assertEqual(svc.get(second.id).status, "queued")
        self.assertEqual(svc.cancel(second.id).status, "cancelled")
        await svc.wait(first.id)
        await svc.wait(second.id)
        self.assertEqual(svc.get(first.id).status, "completed")
        self.assertEqual(svc.get(second.id).status, "cancelled")
        self.assertEqual(svc.get(second.id).done_controls, 0)

    async def test_cancel_a_running_audit_keeps_partial_results(self):
        svc = make_service(SlowBackend(delay=0.03), concurrency=1)
        self.addCleanup(svc.repo.close)
        record = svc.submit("policy.txt", policy_text())
        svc.start(record.id)
        await asyncio.sleep(0.1)
        self.assertEqual(svc.get(record.id).status, "running")
        svc.cancel(record.id)
        done = await svc.wait(record.id)
        self.assertEqual(done.status, "cancelled")
        self.assertTrue(0 < done.done_controls < done.total_controls)
        self.assertEqual(len(svc.finding_views(record.id)), done.done_controls)

    async def test_rerun_reuses_cached_answers(self):
        backend = SlowBackend()
        svc = make_service(backend)
        self.addCleanup(svc.repo.close)
        first = svc.submit("policy.txt", policy_text(), IDS)
        svc.start(first.id)
        await svc.wait(first.id)
        calls_after_first = backend.calls
        self.assertEqual(calls_after_first, len(IDS))
        second = svc.rerun(first.id)
        self.assertNotEqual(second.id, first.id)
        svc.start(second.id)
        done = await svc.wait(second.id)
        self.assertEqual(backend.calls, calls_after_first)  # nothing was sent to the model again
        self.assertTrue(all(v["from_cache"] for v in svc.finding_views(second.id)))
        self.assertEqual(done.usage.input_tokens, 0)

    async def test_cache_can_be_switched_off(self):
        backend = SlowBackend()
        svc = make_service(backend, cache_enabled=False)
        self.addCleanup(svc.repo.close)
        for _ in range(2):
            record = svc.submit("policy.txt", policy_text(), IDS)
            svc.start(record.id)
            await svc.wait(record.id)
        self.assertEqual(backend.calls, 2 * len(IDS))

    async def test_delete_rules(self):
        record = self.svc.submit("policy.txt", policy_text(), IDS)
        with self.assertRaises(Conflict):
            self.svc.delete(record.id)  # still queued
        self.svc.start(record.id)
        await self.svc.wait(record.id)
        self.svc.delete(record.id)
        with self.assertRaises(NotFound):
            self.svc.get(record.id)
        self.assertEqual(self.svc.repo.get_chunks(record.id), [])
        with self.assertRaises(NotFound):
            self.svc.delete(record.id)

    async def test_rerun_of_a_running_audit_is_refused(self):
        record = self.svc.submit("policy.txt", policy_text(), IDS)
        with self.assertRaises(Conflict):
            self.svc.rerun(record.id)

    async def test_shutdown_stops_running_audits(self):
        svc = make_service(SlowBackend(delay=0.2), concurrency=1)
        record = svc.submit("policy.txt", policy_text(), IDS)
        svc.start(record.id)
        await asyncio.sleep(0.05)
        repo = svc.repo
        await svc.shutdown()
        # the repository was closed by shutdown; reopen nothing, just confirm the task ended
        self.assertEqual(len(svc._tasks), 0)
        with self.assertRaises(sqlite3.ProgrammingError):
            repo.get_audit(record.id)  # closed


class LifecycleTests(unittest.TestCase):
    def test_startup_fails_interrupted_audits(self):
        repo = Repository(":memory:")
        svc = make_service(repo=repo)
        self.addCleanup(repo.close)
        record = svc.submit("policy.txt", policy_text())
        svc.startup()  # what happens when the process starts again
        failed = svc.get(record.id)
        self.assertEqual(failed.status, "failed")
        self.assertIn("restarted", failed.error)

    def test_retention_removes_old_finished_audits_only(self):
        repo = Repository(":memory:")
        svc = make_service(repo=repo, retention_days=30)
        self.addCleanup(repo.close)
        old = svc.submit("old.txt", policy_text(), IDS)
        recent = svc.submit("recent.txt", policy_text(), IDS)
        long_ago = (datetime.now(UTC) - timedelta(days=90)).isoformat(timespec="seconds")
        repo._db.execute("UPDATE audits SET created_at = ?, status = 'completed' WHERE id = ?", (long_ago, old.id))
        repo._db.execute("UPDATE audits SET status = 'completed' WHERE id = ?", (recent.id,))
        svc.startup()
        self.assertEqual(repo.count_audits(), 1)
        self.assertIsNotNone(repo.get_audit(recent.id))

    def test_health_and_catalog_listing(self):
        svc = make_service()
        self.addCleanup(svc.repo.close)
        health = svc.health()
        self.assertEqual(health["status"], "ok")
        self.assertEqual(health["backend"]["name"], "heuristic:keywords")
        self.assertFalse(health["backend"]["is_ai_model"])
        self.assertEqual(health["catalog"]["controls"], 48)
        listing = svc.control_catalog()
        self.assertEqual(len(listing["controls"]), 48)
        self.assertIn("injection_suspected", listing["flag_labels"])
        self.assertTrue(listing["controls"][0]["elements"])

    def test_report_format_is_validated(self):
        svc = make_service()
        self.addCleanup(svc.repo.close)
        record = svc.submit("policy.txt", policy_text())
        with self.assertRaises(InvalidRequest):
            svc.report(record.id, "pdf")
        with self.assertRaises(NotFound):
            svc.report("missing", "md")


if __name__ == "__main__":
    unittest.main()
