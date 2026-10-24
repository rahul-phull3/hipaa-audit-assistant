import contextlib
import io
import json
import os
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

from hipaa_audit.assess.llm import HeuristicBackend, LLMUnavailable
from hipaa_audit.cli import main
from hipaa_audit.storage import Repository
from tests.test_service import IDS, policy_text


class FailingBackend:
    """Stands in for a model API that refuses requests: every control fails, or only ``only`` when it is given."""

    name = "anthropic:test"

    def __init__(self, reason, only=None, inner=None):
        self.reason, self.only, self.inner = reason, only, inner

    async def assess(self, control, excerpts):
        if self.only is None or control.id == self.only:
            raise LLMUnavailable(self.reason)
        return await self.inner.assess(control, excerpts)


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
        self.assertNotIn("Model tokens", err)  # the offline matcher uses no model, so there is nothing to count

    def test_progress_log_ends_at_the_full_count_when_stderr_is_not_a_terminal(self):
        # Piped output (CI logs) prints every tenth control; the offline matcher finishes before the first poll, so
        # without a closing line the log would read "0/48" and then "Done".
        code, _out, err = run_cli("audit", str(self.policy), "--backend", "heuristic")
        self.assertEqual(code, 0, err)
        progress = [line for line in err.splitlines() if line.startswith("Assessed ")]
        self.assertEqual(progress[-1], "Assessed 48/48 controls", err)

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

    def test_eval_prints_a_report_on_synthetic_policies(self):
        code, out, err = run_cli(
            "eval", "--backend", "heuristic", "--documents", "1", "--difficulty", "easy", "--controls", ",".join(IDS)
        )
        self.assertEqual(code, 0, err)
        self.assertIn("# Evaluation on synthetic policies", out)
        self.assertIn("not an estimate of accuracy on real policies", out)
        self.assertIn("Scored document 1/1", err)

    def test_eval_json_to_a_file(self):
        target = Path(self.dir.name) / "eval.json"
        code, out, err = run_cli(
            "eval",
            "--backend",
            "heuristic",
            "--documents",
            "2",
            "--seed",
            "5",
            "--format",
            "json",
            "-o",
            str(target),
            "-q",
        )
        self.assertEqual((code, out, err.strip()), (0, "", f"Report written to {target}"))
        report = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual((report["run"]["seeds"], report["run"]["difficulty"]), ([5, 6], "hard"))
        self.assertEqual(report["scores"]["total"], 96)

    def test_eval_exits_with_an_error_and_says_why_when_every_call_fails(self):
        # The first real run is the first contact with the API. A smoke test that exits 0 after every call was rejected
        # cannot fail, so the reason has to reach the person even though the report is still written.
        target = Path(self.dir.name) / "failed.json"
        reason = (
            'Anthropic API error: Error code: 400 - {"message": "output_config.effort: Extra inputs are not permitted"}'
        )
        with mock.patch("hipaa_audit.cli.make_backend", lambda _settings: FailingBackend(reason)):
            code, out, err = run_cli(
                "eval", "--documents", "1", "--controls", ",".join(IDS[:2]), "--format", "json", "-o", str(target), "-q"
            )
        self.assertEqual((code, out), (1, ""))
        self.assertIn("error: 2 of 2 assessments failed", err)
        self.assertIn(f"2 x {reason}", err)
        report = json.loads(target.read_text(encoding="utf-8"))  # the report is still written
        self.assertEqual((report["scores"]["errors"], report["scores"]["total"]), (2, 2))

    def test_eval_exits_with_an_error_when_only_some_calls_fail(self):
        backend = FailingBackend("Anthropic API error: overloaded", only=IDS[0], inner=HeuristicBackend())
        with mock.patch("hipaa_audit.cli.make_backend", lambda _settings: backend):
            code, out, err = run_cli("eval", "--documents", "1", "--controls", ",".join(IDS[:2]))
        self.assertEqual(code, 1)
        self.assertIn("error: 1 of 2 assessments failed", err)
        self.assertIn("1 x Anthropic API error: overloaded", err)
        self.assertIn("1 controls could not be assessed", out)

    def test_eval_refuses_bad_input_and_a_missing_key(self):
        code, _out, err = run_cli("eval", "--backend", "heuristic", "--controls", "nope")
        self.assertEqual((code, "unknown control ids" in err), (2, True))
        code, _out, err = run_cli("eval", env={"HIPAA_AUDIT_LLM_BACKEND": "anthropic", "ANTHROPIC_API_KEY": ""})
        self.assertEqual((code, "ANTHROPIC_API_KEY" in err), (2, True))
        self.assertNotIn("model calls", err)  # nothing was started, so nothing could have been spent

    def test_serve_starts_uvicorn_with_the_app(self):
        with mock.patch("uvicorn.run") as run:
            code, _out, err = run_cli("serve", "--port", "8123", "--db", ":memory:", "--backend", "heuristic")
        self.assertEqual((code, err), (0, ""))
        (app,), kwargs = run.call_args
        self.assertEqual((kwargs["host"], kwargs["port"]), ("127.0.0.1", 8123))
        self.assertTrue(callable(app))
        app.state.service.repo.close()

    def test_serve_on_loopback_answers_only_to_loopback_host_names(self):
        from starlette.testclient import TestClient

        with mock.patch("uvicorn.run") as run:
            run_cli("serve", "--db", ":memory:", "--backend", "heuristic")
        app = run.call_args.args[0]
        self.addCleanup(app.state.service.repo.close)
        with TestClient(app, base_url="http://localhost:8000") as client:
            self.assertEqual(client.get("/api/health").status_code, 200)
        with TestClient(app, base_url="http://attacker.example:8000") as client:
            self.assertEqual(client.get("/api/health").status_code, 400)

    def test_serve_on_another_address_leaves_host_names_alone_unless_configured(self):
        from starlette.testclient import TestClient

        with mock.patch("uvicorn.run") as run:
            run_cli("serve", "--host", "0.0.0.0", "--db", ":memory:", "--backend", "heuristic")
        app = run.call_args.args[0]
        self.addCleanup(app.state.service.repo.close)
        with TestClient(app, base_url="http://review.example") as client:
            self.assertEqual(client.get("/api/health").status_code, 200)
        with mock.patch("uvicorn.run") as run:
            run_cli(
                "serve",
                "--host",
                "0.0.0.0",
                "--db",
                ":memory:",
                "--backend",
                "heuristic",
                env={"HIPAA_AUDIT_ALLOWED_HOSTS": "review.example"},
            )
        app = run.call_args.args[0]
        self.addCleanup(app.state.service.repo.close)
        with TestClient(app, base_url="http://review.example") as client:
            self.assertEqual(client.get("/api/health").status_code, 200)
        with TestClient(app, base_url="http://other.example") as client:
            self.assertEqual(client.get("/api/health").status_code, 400)

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
