"""Command line: audit a file without a server, start the server, evaluate a backend, list the controls, purge old audits.

Exit codes: 0 success, 1 the audit failed, 2 bad input or configuration, 130 interrupted.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import json
import sys
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

from hipaa_audit import __version__
from hipaa_audit.assess.factory import make_backend
from hipaa_audit.assess.llm import LLMAuthError
from hipaa_audit.catalog import load_catalog
from hipaa_audit.config import ConfigError, Settings, load_env_file
from hipaa_audit.evaluation import DIFFICULTIES, build_report, evaluate, render_json, render_markdown
from hipaa_audit.retrieval import make_embedder
from hipaa_audit.service import AuditService, ServiceError
from hipaa_audit.storage import ACTIVE_STATUSES, Repository, StorageError

LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def _settings(args: argparse.Namespace, *, default_db: str | None = None) -> Settings:
    load_env_file(".env")
    settings = Settings.from_env()
    changes: dict[str, object] = {}
    if getattr(args, "backend", None):
        changes["llm_backend"] = args.backend
    db = getattr(args, "db", None) or default_db
    if db:
        changes["db_path"] = db
    return dataclasses.replace(settings, **changes) if changes else settings


def _say(message: str) -> None:
    print(message, file=sys.stderr)


async def _audit(args: argparse.Namespace) -> int:
    settings = _settings(args, default_db=":memory:")
    path = Path(args.file)
    if not path.is_file():
        _say(f"error: {path} is not a file")
        return 2
    if path.stat().st_size > settings.max_upload_bytes:
        _say(f"error: {path.name} is larger than the {settings.max_upload_mb} MB limit")
        return 2
    controls = [c.strip() for c in args.controls.split(",") if c.strip()] if args.controls else None
    service = AuditService.from_settings(settings)
    try:
        record = service.submit(path.name, path.read_bytes(), controls)
        if not args.quiet:
            _say(
                f"Reviewing {record.filename} ({record.chunk_count} passages) against {record.total_controls} controls with {record.backend}"
            )
        service.start(record.id)
        interactive = sys.stderr.isatty() and not args.quiet
        last = -1
        while True:
            current = service.get(record.id)
            if current.done_controls != last and not args.quiet:
                last = current.done_controls
                if interactive:
                    sys.stderr.write(f"\rAssessed {last}/{current.total_controls} controls")
                    sys.stderr.flush()
                elif last % 10 == 0:
                    _say(f"Assessed {last}/{current.total_controls} controls")
            if current.status not in ACTIVE_STATUSES:
                break
            await asyncio.sleep(0.2)
        if interactive:
            sys.stderr.write("\n")
        final = await service.wait(record.id)
        content, _media, _name = service.report(record.id, args.format)
        if args.output:
            Path(args.output).write_text(content, encoding="utf-8")
            _say(f"Report written to {args.output}")
        else:
            sys.stdout.write(content)
        summary = service.summary(record.id)
        if not args.quiet:
            tokens = ""
            if final.usage.input_tokens or final.usage.output_tokens:  # the offline matcher uses no model
                tokens = f" Model tokens: {final.usage.input_tokens:,} in, {final.usage.output_tokens:,} out."
            _say(
                f"Done: {summary['met']} met, {summary['partial']} partial, {summary['gap']} gap, "
                f"{summary['error']} not assessed.{tokens}"
            )
        if final.status == "failed":
            _say(f"error: the audit failed: {final.error}")
            return 1
        return 0
    except ServiceError as exc:
        _say(f"error: {exc.message}")
        return 2
    finally:
        await service.shutdown()


async def _eval(args: argparse.Namespace) -> int:
    settings = _settings(args)
    catalog = load_catalog()
    control_ids = [c.strip() for c in args.controls.split(",") if c.strip()] if args.controls else None
    try:
        controls = catalog.select(control_ids)
        backend = make_backend(settings)
    except KeyError as exc:
        _say(f"error: {exc.args[0]}")
        return 2
    except RuntimeError as exc:
        _say(f"error: {exc}")
        return 2
    seeds = list(range(args.seed, args.seed + args.documents))
    if not backend.name.startswith("heuristic"):
        _say(
            f"Evaluating {backend.name}: {len(seeds) * len(controls)} model calls "
            f"({len(seeds)} documents x {len(controls)} controls). Press Ctrl+C to stop."
        )
    try:
        result = await evaluate(
            lambda _policy: backend,
            seeds=seeds,
            difficulty=args.difficulty,
            control_ids=control_ids,
            embedder=make_embedder(settings.embedder),
            top_k=settings.top_k,
            concurrency=settings.concurrency,
            progress=None if args.quiet else lambda done, total: _say(f"Scored document {done}/{total}"),
        )
    except LLMAuthError:
        _say(
            "error: the Anthropic API rejected the API key or the request. Check ANTHROPIC_API_KEY and the model name."
        )
        return 1
    report = build_report(result)
    content = render_json(report) if args.format == "json" else render_markdown(report)
    if args.output:
        Path(args.output).write_text(content, encoding="utf-8")
        _say(f"Report written to {args.output}")
    else:
        sys.stdout.write(content)
    return 0


def _serve(args: argparse.Namespace) -> int:
    settings = _settings(args)
    try:
        import uvicorn

        from hipaa_audit.api import create_app
    except ImportError as exc:  # pragma: no cover - depends on the environment
        _say(f"error: the web server dependencies are missing ({exc}). Install the package with pip install .")
        return 2
    if args.host not in LOOPBACK and not settings.api_key:
        _say(
            f"warning: listening on {args.host} without HIPAA_AUDIT_API_KEY. Anyone who can reach this port can upload "
            "documents and read audits. Set an API key or put the server behind an authenticating proxy."
        )
    uvicorn.run(create_app(settings), host=args.host, port=args.port, log_level=args.log_level)
    return 0


def _controls(args: argparse.Namespace) -> int:
    catalog = load_catalog()
    if args.json:
        print(json.dumps([c.model_dump() for c in catalog.controls], indent=2))
        return 0
    print(f"Catalog {catalog.meta.version}: {len(catalog.controls)} controls ({catalog.meta.regulation})")
    for c in catalog.controls:
        print(f"{c.id:38} {c.safeguard:14} {c.requirement:11} {c.citation.replace('45 CFR ', ''):28} {c.title}")
    return 0


def _purge(args: argparse.Namespace) -> int:
    settings = _settings(args)
    cutoff = (datetime.now(UTC) - timedelta(days=args.days)).isoformat(timespec="seconds")
    repo = Repository(settings.db_path)
    try:
        removed = repo.delete_finished_before(cutoff)
    finally:
        repo.close()
    print(f"Removed {removed} audit(s) created before {cutoff} (with their text, findings and cached answers).")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hipaa-audit", description="Review a security policy against HIPAA Security Rule controls."
    )
    parser.add_argument("--version", action="version", version=f"hipaa-audit {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", help="review a PDF, DOCX, TXT or Markdown policy and print the report")
    audit.add_argument("file")
    audit.add_argument("--controls", help="comma-separated control ids (default: all; see the controls command)")
    audit.add_argument("--backend", choices=("anthropic", "heuristic"), help="override HIPAA_AUDIT_LLM_BACKEND")
    audit.add_argument("--format", choices=("md", "json"), default="md")
    audit.add_argument("-o", "--output", help="write the report to this file instead of stdout")
    audit.add_argument("--db", help="keep the audit in this SQLite file (default: nothing is stored)")
    audit.add_argument("-q", "--quiet", action="store_true", help="no progress or summary on stderr")
    audit.set_defaults(run=lambda a: asyncio.run(_audit(a)))

    evaluation = sub.add_parser(
        "eval",
        help="score a backend on synthetic policies with known answers (not an accuracy estimate for real policies)",
    )
    evaluation.add_argument("--backend", choices=("anthropic", "heuristic"), help="override HIPAA_AUDIT_LLM_BACKEND")
    evaluation.add_argument(
        "--documents", type=int, default=5, help="how many synthetic policies to generate (default 5)"
    )
    evaluation.add_argument(
        "--seed", type=int, default=1, help="seed of the first policy; the others follow in sequence"
    )
    evaluation.add_argument("--difficulty", choices=DIFFICULTIES, default="hard")
    evaluation.add_argument("--controls", help="comma-separated control ids (default: all)")
    evaluation.add_argument("--format", choices=("md", "json"), default="md")
    evaluation.add_argument("-o", "--output", help="write the report to this file instead of stdout")
    evaluation.add_argument("-q", "--quiet", action="store_true", help="no progress on stderr")
    evaluation.set_defaults(run=lambda a: asyncio.run(_eval(a)))

    serve = sub.add_parser("serve", help="start the web server")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--db", help="SQLite file (default: HIPAA_AUDIT_DB_PATH)")
    serve.add_argument("--backend", choices=("anthropic", "heuristic"))
    serve.add_argument("--log-level", default="info", choices=("critical", "error", "warning", "info", "debug"))
    serve.set_defaults(run=_serve)

    controls = sub.add_parser("controls", help="list the controls in the catalog")
    controls.add_argument("--json", action="store_true")
    controls.set_defaults(run=_controls)

    purge = sub.add_parser("purge", help="delete finished audits older than N days")
    purge.add_argument("--days", type=int, required=True)
    purge.add_argument("--db", help="SQLite file (default: HIPAA_AUDIT_DB_PATH)")
    purge.set_defaults(run=_purge)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.run(args)
    except (ConfigError, StorageError) as exc:
        _say(f"error: {exc}")
        return 2
    except KeyboardInterrupt:
        _say("interrupted")
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
