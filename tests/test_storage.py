import os
import sqlite3
import stat
import tempfile
import unittest

from hipaa_audit.assess.schema import RawAssessment, RawEvidence
from hipaa_audit.models import Chunk, Evidence, Finding, Span, Usage
from hipaa_audit.storage import AuditRecord, Repository, SqliteCache, StorageError, new_id


def make_record(**overrides) -> AuditRecord:
    base = dict(
        id=new_id(),
        filename="policy.pdf",
        sha256="ab" * 32,
        size_bytes=1234,
        pages=3,
        created_at="2026-10-24T10:00:00+00:00",
        backend="heuristic:keywords",
        embedder="hashing",
        catalog_version="2026.10-r1",
        prompt_version="v2",
        control_ids=["data-backup-plan", "password-management"],
        total_controls=2,
        chunk_count=2,
    )
    base.update(overrides)
    return AuditRecord(**base)


def make_chunks():
    return [
        Chunk(
            id="c0001", ord=0, page=1, section="Backups", text="Backups are taken daily.", n_words=4,
            spans=[Span(start=0, end=24, page=1, section="Backups")],
        ),
        Chunk(id="c0002", ord=1, page=2, section="", text="Passwords are never shared.", n_words=4),
    ]


def make_finding(control_id="data-backup-plan", status="met") -> Finding:
    return Finding(
        control_id=control_id,
        status=status,
        rationale="Because.",
        evidence=[Evidence(chunk_id="c0001", quote="Backups are taken daily.", page=1, section="Backups")],
        confidence=0.8,
        model="heuristic:keywords",
    )


class RepositoryTests(unittest.TestCase):
    def setUp(self):
        self.repo = Repository(":memory:")
        self.addCleanup(self.repo.close)

    def test_audit_round_trip(self):
        record = make_record(usage=Usage(input_tokens=5, output_tokens=2))
        self.repo.create_audit(record, make_chunks())
        loaded = self.repo.get_audit(record.id)
        self.assertEqual(loaded, record)
        self.assertEqual(loaded.control_ids, ["data-backup-plan", "password-management"])
        self.assertIsNone(self.repo.get_audit("missing"))

    def test_list_is_newest_first_and_paged(self):
        ids = []
        for day in (1, 2, 3):
            record = make_record(created_at=f"2026-10-0{day}T00:00:00+00:00")
            self.repo.create_audit(record, [])
            ids.append(record.id)
        self.assertEqual([a.id for a in self.repo.list_audits()], ids[::-1])
        self.assertEqual([a.id for a in self.repo.list_audits(limit=1, offset=1)], [ids[1]])
        self.assertEqual(self.repo.count_audits(), 3)

    def test_chunks_come_back_in_order(self):
        record = make_record()
        self.repo.create_audit(record, list(reversed(make_chunks())))
        chunks = self.repo.get_chunks(record.id)
        self.assertEqual([c.id for c in chunks], ["c0001", "c0002"])
        self.assertEqual(chunks[0].spans, [Span(start=0, end=24, page=1, section="Backups")])
        self.assertEqual(chunks[1].spans, [])
        self.assertEqual(self.repo.get_chunk(record.id, "c0002").text, "Passwords are never shared.")
        self.assertIsNone(self.repo.get_chunk(record.id, "c9999"))
        self.assertIsNone(self.repo.get_chunk("other", "c0001"))

    def test_failed_create_leaves_nothing_behind(self):
        record = make_record()
        duplicate = make_chunks() + make_chunks()[:1]
        with self.assertRaises(sqlite3.IntegrityError):
            self.repo.create_audit(record, duplicate)
        self.assertIsNone(self.repo.get_audit(record.id))

    def test_claim_is_atomic_and_only_from_queued(self):
        record = make_record()
        self.repo.create_audit(record, [])
        self.assertTrue(self.repo.claim_for_run(record.id))
        self.assertFalse(self.repo.claim_for_run(record.id))
        running = self.repo.get_audit(record.id)
        self.assertEqual(running.status, "running")
        self.assertIsNotNone(running.started_at)

    def test_cancel_only_while_queued(self):
        queued, running = make_record(), make_record()
        self.repo.create_audit(queued, [])
        self.repo.create_audit(running, [])
        self.repo.claim_for_run(running.id)
        self.assertTrue(self.repo.cancel_if_queued(queued.id))
        self.assertFalse(self.repo.cancel_if_queued(running.id))
        self.assertEqual(self.repo.get_audit(queued.id).status, "cancelled")
        self.assertFalse(self.repo.claim_for_run(queued.id))  # a cancelled audit can no longer start

    def test_finish_records_usage_and_error(self):
        record = make_record()
        self.repo.create_audit(record, [])
        self.repo.claim_for_run(record.id)
        self.repo.finish(record.id, "failed", usage=Usage(input_tokens=9), error="boom")
        done = self.repo.get_audit(record.id)
        self.assertEqual((done.status, done.error, done.usage.input_tokens), ("failed", "boom", 9))
        self.assertIsNotNone(done.finished_at)
        self.repo.finish(record.id, "completed")  # without usage the stored usage is kept
        self.assertEqual(self.repo.get_audit(record.id).usage.input_tokens, 9)

    def test_findings_track_progress_and_keep_catalog_order(self):
        record = make_record()
        self.repo.create_audit(record, make_chunks())
        self.assertEqual(self.repo.save_finding(record.id, 1, make_finding("password-management", "gap")), 1)
        self.assertEqual(self.repo.save_finding(record.id, 0, make_finding("data-backup-plan")), 2)
        self.assertEqual(self.repo.get_audit(record.id).done_controls, 2)
        self.assertEqual([f.control_id for f in self.repo.get_findings(record.id)], ["data-backup-plan", "password-management"])
        # saving a control again replaces it instead of double counting
        self.assertEqual(self.repo.save_finding(record.id, 0, make_finding("data-backup-plan", "partial")), 2)
        self.assertEqual(self.repo.get_findings(record.id)[0].status, "partial")

    def test_delete_removes_everything_that_belongs_to_the_audit(self):
        keep, drop = make_record(), make_record()
        for record in (keep, drop):
            self.repo.create_audit(record, make_chunks())
            self.repo.save_finding(record.id, 0, make_finding())
            SqliteCache(self.repo, record.id).put(f"key-{record.id}", RawAssessment(status="gap"))
        self.assertTrue(self.repo.delete_audit(drop.id))
        self.assertFalse(self.repo.delete_audit(drop.id))
        self.assertIsNone(self.repo.get_audit(drop.id))
        self.assertEqual(self.repo.get_chunks(drop.id), [])
        self.assertEqual(self.repo.get_findings(drop.id), [])
        self.assertIsNone(self.repo.cache_get(f"key-{drop.id}"))
        self.assertIsNotNone(self.repo.cache_get(f"key-{keep.id}"))
        self.assertEqual(len(self.repo.get_chunks(keep.id)), 2)

    def test_interrupted_audits_are_failed_at_startup(self):
        queued, running, done = make_record(), make_record(), make_record()
        for record in (queued, running, done):
            self.repo.create_audit(record, [])
        self.repo.claim_for_run(running.id)
        self.repo.claim_for_run(done.id)
        self.repo.finish(done.id, "completed")
        self.assertEqual(self.repo.fail_interrupted("restarted"), 2)
        self.assertEqual(self.repo.get_audit(queued.id).status, "failed")
        self.assertEqual(self.repo.get_audit(running.id).error, "restarted")
        self.assertEqual(self.repo.get_audit(done.id).status, "completed")


class CacheTests(unittest.TestCase):
    def test_round_trip_keeps_the_whole_answer(self):
        repo = Repository(":memory:")
        self.addCleanup(repo.close)
        record = make_record()
        repo.create_audit(record, [])
        raw = RawAssessment(
            status="partial",
            rationale="Some.",
            evidence=[RawEvidence(excerpt_id="c0001", quote="Backups are taken daily.")],
            missing_elements=["Tested restores"],
            confidence=0.6,
        )
        cache = SqliteCache(repo, record.id)
        self.assertIsNone(cache.get("k"))
        cache.put("k", raw)
        self.assertEqual(cache.get("k"), raw)
        self.assertEqual(repo.cache_size(), 1)
        # another audit can reuse the entry
        self.assertEqual(SqliteCache(repo, "someone-else").get("k"), raw)


class FileDatabaseTests(unittest.TestCase):
    def test_persists_across_reopen_with_wal_and_private_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "nested", "audits.sqlite3")
            repo = Repository(path)
            record = make_record()
            repo.create_audit(record, make_chunks())
            repo.close()
            reopened = Repository(path)
            self.addCleanup(reopened.close)
            self.assertEqual(reopened.get_audit(record.id).filename, "policy.pdf")
            self.assertEqual(reopened._db.execute("PRAGMA journal_mode").fetchone()[0], "wal")
            self.assertEqual(reopened._db.execute("PRAGMA user_version").fetchone()[0], 1)
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(path)).st_mode) & 0o077, 0)

    def test_database_from_a_newer_version_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "future.sqlite3")
            raw = sqlite3.connect(path)
            raw.execute("PRAGMA user_version = 99")
            raw.commit()
            raw.close()
            with self.assertRaises(StorageError):
                Repository(path)


if __name__ == "__main__":
    unittest.main()
