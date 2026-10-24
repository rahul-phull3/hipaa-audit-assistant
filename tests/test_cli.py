import contextlib
import io
import json
import os
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

from hipaa_audit.cli import main
from hipaa_audit.storage import Repository
from tests.test_service import IDS, policy_text


def run_cli(*argv, env=None):
    out, err = io.StringIO(), io.StringIO()
    with (
        mock.patch.dict(os.environ, env or {}, clear=False),
        contextlib.redirect_stdout(out),
        contextlib.redirect_stderr(err),
    ):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.policy = Path(self.dir.name) / "policy.txt"
        self.policy.write_bytes(policy_text())
        cwd = os.getcwd()
        os.chdir(self.dir.name)  # so a stray .env in the repository is never read
        self.addCleanup(os.chdir, cwd)

    def test_audit_prints_a_markdown_report(self):
        code, out, err = run_cli("audit", str(self.policy), "--backend", "heuristic", "--controls", ",".join(IDS))
        self.assertEqual(code, 0, err)
        self.assertIn("# HIPAA Security Rule policy review", out)
        self.assertIn("policy.txt", out)
        self.assertIn("Done:", err)
        self.assertIn("heuristic:keywords", err)

    def test_json_output_to_a_file(self):
        target = Path(self.dir.name) / "report.json"
        code, out, err = run_cli(
            "audit", str(self.policy), "--backend", "heuristic", "--format", "json", "-o", str(target), "-q"
        )
        self.assertEqual((code, out, err.strip()), (0, "", f"Report written to {target}"))
        report = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(report["summary"]["assessed"], 48)
        self.assertEqual(report["document"]["filename"], "policy.txt")

    def test_unknown_control_missing_file_and_bad_type(self):
        code, _out, err = run_cli("audit", str(self.policy), "--backend", "heuristic", "--controls", "nope")
        self.assertEqual(code, 2)
        self.assertIn("unknown control ids", err)
        code, _out, err = run_cli("audit", str(Path(self.dir.name) / "missing.pdf"), "--backend", "heuristic")
        self.assertEqual((code, "is not a file" in err), (2, True))
        exe = Path(self.dir.name) / "x.exe"
        exe.write_bytes(b"MZ")
        code, _out, err = run_cli("audit", str(exe), "--backend", "heuristic")
        self.assertEqual((code, "Unsupported file type" in err), (2, True))

    def test_missing_api_key_is_a_clear_error(self):
        code, _out, err = run_cli(
            "audit", str(self.policy), env={"HIPAA_AUDIT_LLM_BACKEND": "anthropic", "ANTHROPIC_API_KEY": ""}
        )
        self.assertEqual(code, 2)
        self.assertIn("ANTHROPIC_API_KEY", err)

    def test_bad_configuration(self):
        code, _out, err = run_cli("audit", str(self.policy), env={"HIPAA_AUDIT_CONCURRENCY": "many"})
        self.assertEqual(code, 2)
        self.assertIn("HIPAA_AUDIT_CONCURRENCY", err)

    def test_db_option_keeps_the_audit(self):
        db = str(Path(self.dir.name) / "kept.sqlite3")
        code, _out, err = run_cli("audit", str(self.policy), "--backend", "heuristic", "--db", db, "-q")
        self.assertEqual(code, 0, err)
        repo = Repository(db)
        self.addCleanup(repo.close)
        audits = repo.list_audits()
        self.assertEqual((len(audits), audits[0].status), (1, "completed"))

    def test_controls_listing(self):
        code, out, _err = run_cli("controls")
        self.assertEqual(code, 0)
        self.assertIn("48 controls", out)
        self.assertIn("data-backup-plan", out)
        code, out, _err = run_cli("controls", "--json")
        self.assertEqual(len(json.loads(out)), 48)

    def test_purge(self):
        db = str(Path(self.dir.name) / "purge.sqlite3")
        run_cli("audit", str(self.policy), "--backend", "heuristic", "--db", db, "-q", "-o", os.devnull)
        repo = Repository(db)
        long_ago = (datetime.now(UTC) - timedelta(days=60)).isoformat(timespec="seconds")
        repo._db.execute("UPDATE audits SET created_at = ?", (long_ago,))
        repo.close()
        code, out, _err = run_cli("purge", "--days", "30", "--db", db)
        self.assertEqual(code, 0)
        self.assertIn("Removed 1 audit(s)", out)
        repo = Repository(db)
        self.addCleanup(repo.close)
        self.assertEqual(repo.count_audits(), 0)

    def test_serve_starts_uvicorn_with_the_app(self):
        with mock.patch("uvicorn.run") as run:
            code, _out, err = run_cli("serve", "--port", "8123", "--db", ":memory:", "--backend", "heuristic")
        self.assertEqual((code, err), (0, ""))
        (app,), kwargs = run.call_args
        self.assertEqual((kwargs["host"], kwargs["port"]), ("127.0.0.1", 8123))
        self.assertTrue(callable(app))
        app.state.service.repo.close()

    def test_serve_warns_when_exposed_without_an_api_key(self):
        with mock.patch("uvicorn.run") as run:
            code, _out, err = run_cli("serve", "--host", "0.0.0.0", "--db", ":memory:", "--backend", "heuristic")
        self.assertEqual(code, 0)
        self.assertIn("without HIPAA_AUDIT_API_KEY", err)
        run.call_args.args[0].state.service.repo.close()
        with mock.patch("uvicorn.run") as run:
            code, _out, err = run_cli(
                "serve",
                "--host",
                "0.0.0.0",
                "--db",
                ":memory:",
                "--backend",
                "heuristic",
                env={"HIPAA_AUDIT_API_KEY": "k"},
            )
        self.assertEqual((code, err), (0, ""))
        run.call_args.args[0].state.service.repo.close()

    def test_version_and_usage(self):
        with self.assertRaises(SystemExit) as ctx, contextlib.redirect_stdout(io.StringIO()):
            main(["--version"])
        self.assertEqual(ctx.exception.code, 0)
        with self.assertRaises(SystemExit) as ctx, contextlib.redirect_stderr(io.StringIO()):
            main([])
        self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
