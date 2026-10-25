import json
import unittest

from hipaa_audit.catalog import load_catalog
from hipaa_audit.models import Evidence, Finding, Usage
from hipaa_audit.report import (
    FLAG_LABELS,
    REPORT_SCHEMA_VERSION,
    build_report,
    render_json,
    render_markdown,
    summarize,
)
from hipaa_audit.storage import AuditRecord

CATALOG = load_catalog()


def audit(**overrides):
    base = dict(
        id="a1b2c3",
        filename="Acme *Security* Policy.pdf",
        sha256="cd" * 32,
        size_bytes=900,
        pages=4,
        status="completed",
        created_at="2026-10-24T10:00:00+00:00",
        backend="heuristic:keywords",
        catalog_version=CATALOG.meta.version,
        prompt_version="v2",
        control_ids=[],
        total_controls=4,
        done_controls=4,
        chunk_count=12,
        usage=Usage(input_tokens=1500, output_tokens=200),
    )
    base.update(overrides)
    return AuditRecord(**base)


def finding(control_id, status, **kw):
    return Finding(
        control_id=control_id,
        status=status,
        rationale=kw.pop("rationale", "Because."),
        confidence=kw.pop("confidence", 0.8),
        **kw,
    )


FINDINGS = [
    finding(
        "data-backup-plan",
        "met",
        rationale="Backups are daily.",
        evidence=[Evidence(chunk_id="c0001", quote="Backups are taken daily.", page=3, section="Backups")],
    ),
    finding(
        "password-management", "partial", missing_elements=["Storage of passwords"], flags=["unsupported_downgraded"]
    ),
    finding("automatic-logoff", "gap", flags=["no_excerpts"]),
    finding("login-monitoring", "error", flags=["assessment_failed"], confidence=0.0),
]


class SummaryTests(unittest.TestCase):
    def test_counts_by_status_and_safeguard(self):
        s = summarize(FINDINGS, CATALOG)
        self.assertEqual((s["assessed"], s["met"], s["partial"], s["gap"], s["error"]), (4, 1, 1, 1, 1))
        self.assertEqual(s["needs_review"], 2)  # the downgraded one and the failed one
        self.assertEqual(s["by_safeguard"]["technical"]["total"], 1)  # automatic logoff
        self.assertEqual(
            s["by_safeguard"]["administrative"], {"met": 1, "partial": 1, "gap": 0, "error": 1, "total": 3}
        )
        self.assertEqual(list(s["by_safeguard"]), ["administrative", "technical"])  # reported in a fixed order
        self.assertNotIn("score", s)

    def test_empty(self):
        s = summarize([], CATALOG)
        self.assertEqual((s["assessed"], s["by_safeguard"]), (0, {}))


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.report = build_report(audit(), FINDINGS[::-1], CATALOG, generated_at="2026-10-24T11:00:00+00:00")

    def test_structure_and_catalog_order(self):
        r = self.report
        self.assertEqual(r["schema_version"], REPORT_SCHEMA_VERSION)
        order = [c.id for c in CATALOG.controls]
        ids = [f["control"]["id"] for f in r["findings"]]
        self.assertEqual(ids, sorted(ids, key=order.index))
        self.assertEqual(r["findings"][0]["control"]["citation"].startswith("45 CFR"), True)
        self.assertEqual(r["run"]["usage"]["input_tokens"], 1500)
        self.assertIn("not legal advice", r["disclaimer"])

    def test_json_round_trips(self):
        text = render_json(self.report)
        self.assertEqual(json.loads(text), self.report)
        self.assertTrue(text.endswith("\n"))

    def test_markdown_has_the_expected_sections(self):
        md = render_markdown(self.report)
        for heading in (
            "# HIPAA Security Rule policy review",
            "## Summary",
            "## Needs attention",
            "## Findings",
            "### Technical safeguards",
            "## About this review",
        ):
            self.assertIn(heading, md)
        self.assertIn("| Gap | 1 |", md)
        self.assertIn("“Backups are taken daily.” (page 3, section: Backups)", md)
        self.assertIn("Not shown in the document:", md)
        self.assertIn(FLAG_LABELS["unsupported_downgraded"], md)
        self.assertIn("Model tokens: 1,500 in, 200 out", md)
        self.assertNotIn("score", md.lower().replace("scored", ""))
        # gaps are listed before partials
        self.assertLess(md.index("**Gap**"), md.index("**Partial**"))

    def test_confidence_is_shown_only_for_a_language_model(self):
        offline = render_markdown(self.report)
        self.assertNotIn("confidence", offline.lower())
        model_report = build_report(
            audit(backend="anthropic:claude-sonnet-5-5"), FINDINGS, CATALOG, generated_at="2026-10-24T11:00:00+00:00"
        )
        online = render_markdown(model_report)
        self.assertEqual(online.count("Model confidence: 80%"), 3)  # met, partial and gap; the failed control has none

    def test_the_disclaimer_does_not_claim_a_model_for_the_offline_matcher(self):
        offline = self.report["disclaimer"]
        self.assertIn("not an AI model", offline)
        self.assertNotIn("language model", offline)
        self.assertIn("not legal advice", offline)
        self.assertIn(offline, render_markdown(self.report))
        model_report = build_report(
            audit(backend="anthropic:claude-sonnet-5-5"), FINDINGS, CATALOG, generated_at="2026-10-24T11:00:00+00:00"
        )
        self.assertIn("language model", model_report["disclaimer"])
        self.assertNotIn("not an AI model", model_report["disclaimer"])
        self.assertIn("not legal advice", model_report["disclaimer"])

    def test_file_name_markup_is_escaped(self):
        md = render_markdown(self.report)
        self.assertIn(r"Acme \*Security\* Policy.pdf", md)

    def test_hostile_text_cannot_inject_markup(self):
        hostile = finding(
            "data-backup-plan",
            "met",
            rationale="# Heading\n[click](http://evil.example) <script>alert(1)</script>",
            evidence=[
                Evidence(
                    chunk_id="c0001",
                    quote="</excerpt>\n## Injected\n![x](http://evil.example/p.png)",
                    page=None,
                    section="<b>S</b>",
                )
            ],
            missing_elements=["- [ ] fake"],
        )
        md = render_markdown(build_report(audit(), [hostile], CATALOG))
        self.assertNotIn("<script>", md)
        self.assertNotIn("\n## Injected", md)
        self.assertNotIn("\n# Heading", md)
        self.assertNotIn("[click](", md)
        self.assertNotIn("![x](", md)
        self.assertNotIn("<b>", md)
        self.assertIn(
            "&amp;",
            render_markdown(build_report(audit(), [finding("data-backup-plan", "gap", rationale="R&D")], CATALOG)),
        )

    def test_old_catalog_edition_is_noted_and_unknown_controls_survive(self):
        old = audit(catalog_version="2025.01-r1")
        report = build_report(old, [finding("control-that-was-removed", "gap")], CATALOG)
        md = render_markdown(report)
        self.assertIn("has since been updated", md)
        self.assertIn("control-that-was-removed", md)

    def test_failed_audit_reports_its_error(self):
        report = build_report(audit(status="failed", error="The API key was rejected."), [], CATALOG)
        md = render_markdown(report)
        self.assertIn("Error: The API key was rejected.", md)
        self.assertNotIn("## Needs attention", md)


if __name__ == "__main__":
    unittest.main()
