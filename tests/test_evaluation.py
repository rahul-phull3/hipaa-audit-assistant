import asyncio
import json
import re
import unittest

from hipaa_audit.assess.llm import HeuristicBackend, LLMAuthError, LLMUnavailable
from hipaa_audit.assess.schema import RawAssessment, RawEvidence
from hipaa_audit.assess.verify import normalize
from hipaa_audit.catalog import load_catalog
from hipaa_audit.evaluation import Mix, build_report, evaluate, generate_policy, render_json, render_markdown
from hipaa_audit.evaluation.scoring import COLUMNS, LABELS, confusion, merge, summarize
from hipaa_audit.evaluation.synthetic import _Draw, _swapper
from hipaa_audit.models import Usage

CATALOG = load_catalog()
CATALOG_SENTENCES = {c.synth[0] for control in CATALOG.controls for c in control.criteria}


class IdealReader:
    """A test double that reads the passages it is given the way a careful person would: it finds the control's sentences."""

    name = "test:ideal-reader"

    def __init__(self, policy):
        self.policy = policy

    async def assess(self, control, excerpts):
        truth = self.policy.truth[control.id]
        found = []
        for sentence in truth.sentences:
            owner = next((chunk for chunk in excerpts if sentence in chunk.text), None)
            if owner is not None:
                found.append(RawEvidence(excerpt_id=owner.id, quote=sentence))
        if not found:
            return RawAssessment(status="gap", rationale="Nothing relevant.", confidence=0.9), Usage()
        complete = len(found) == len(control.criteria)
        missing = [] if complete else [c.text for c in control.criteria if c.id in truth.absent]
        status = "met" if complete else "partial"
        return RawAssessment(
            status=status, rationale="Found.", evidence=found, missing_elements=missing, confidence=0.9
        ), Usage()


class Fabricator:
    """Always claims the control is met and backs it with a quote that is not in any document."""

    name = "test:fabricator"

    async def assess(self, control, excerpts):
        quote = "The practice has fully implemented every safeguard described in this control without exception."
        raw = RawAssessment(
            status="met",
            rationale="All good.",
            evidence=[RawEvidence(excerpt_id=excerpts[0].id, quote=quote)],
            confidence=1.0,
        )
        return raw, Usage()


class Down:
    name = "test:down"

    async def assess(self, control, excerpts):
        raise LLMUnavailable("the service is down")


class Rejected:
    name = "test:rejected"

    async def assess(self, control, excerpts):
        raise LLMAuthError("bad key")


class GenerationTests(unittest.TestCase):
    def test_same_seed_same_document(self):
        for difficulty in ("easy", "hard"):
            a = generate_policy(7, difficulty=difficulty)
            b = generate_policy(7, difficulty=difficulty)
            self.assertEqual((a.text, a.truth), (b.text, b.truth))
            self.assertNotEqual(a.text, generate_policy(8, difficulty=difficulty).text)
        self.assertNotEqual(generate_policy(7, difficulty="easy").text, generate_policy(7, difficulty="hard").text)

    def test_unknown_difficulty_and_control(self):
        with self.assertRaises(ValueError):
            generate_policy(1, difficulty="impossible")
        with self.assertRaises(KeyError):
            generate_policy(1, control_ids=["nope"])

    def test_labels_match_what_was_written(self):
        for difficulty in ("easy", "hard"):
            policy = generate_policy(3, difficulty=difficulty)
            text = normalize(policy.text)
            self.assertEqual(set(policy.truth), {c.id for c in CATALOG.controls})
            for control in CATALOG.controls:
                truth = policy.truth[control.id]
                criteria = {c.id for c in control.criteria}
                self.assertEqual(set(truth.present) | set(truth.absent), criteria)
                self.assertFalse(set(truth.present) & set(truth.absent))
                if truth.status == "met":
                    self.assertEqual(truth.absent, [])
                elif truth.status == "partial":
                    self.assertTrue(truth.present and truth.absent, control.id)
                else:
                    self.assertEqual((truth.present, truth.sentences, truth.own_texts), ([], [], []))
                self.assertEqual(len(truth.sentences), len(truth.present))
                for sentence in truth.sentences:
                    self.assertIn(normalize(sentence), text)
                    self.assertTrue(any(normalize(sentence) in normalize(p) for p in truth.own_texts))
                if truth.decoy:
                    self.assertEqual(truth.status, "gap")
                    self.assertIn(normalize(truth.decoy), text)
                if difficulty == "easy":  # nothing is reworded, so a missing criterion's sentence must be absent
                    for criterion in control.criteria:
                        if criterion.id in truth.absent:
                            self.assertNotIn(normalize(criterion.synth[0]), text)

    def test_mix_decides_the_shares(self):
        everything = generate_policy(1, mix=Mix(met=1, partial=0, gap=0))
        self.assertEqual({t.status for t in everything.truth.values()}, {"met"})
        nothing = generate_policy(1, mix=Mix(met=0, partial=0, gap=1, decoy_rate=0))
        self.assertEqual({t.status for t in nothing.truth.values()}, {"gap"})
        self.assertFalse(any(t.decoy for t in nothing.truth.values()))
        seen = {t.status for seed in range(1, 6) for t in generate_policy(seed).truth.values()}
        self.assertEqual(seen, set(LABELS))

    def test_subset_of_controls(self):
        policy = generate_policy(
            2, control_ids=["data-backup-plan", "automatic-logoff"], mix=Mix(met=1, partial=0, gap=0)
        )
        self.assertEqual(set(policy.truth), {"data-backup-plan", "automatic-logoff"})
        self.assertIn("backup", policy.text.lower())

    def test_hard_documents_are_reworded_scattered_and_without_descriptive_headings(self):
        easy = generate_policy(4, difficulty="easy")
        self.assertIn("1. ", easy.text)
        self.assertTrue(any(t.title in easy.text for t in CATALOG.controls))
        reworded = scattered = 0
        for seed in range(1, 6):
            hard = generate_policy(seed, difficulty="hard")
            self.assertIn("Section 1", hard.text)
            self.assertFalse(any(f". {c.title}\n" in hard.text for c in CATALOG.controls))
            for truth in hard.truth.values():
                reworded += sum(1 for s in truth.sentences if s not in CATALOG_SENTENCES)
                if len(truth.own_texts) == 2:
                    scattered += 1
                    self.assertGreater(hard.text.index(truth.own_texts[1]), hard.text.index("Appendix"))
        self.assertGreater(reworded, 10)
        self.assertGreater(scattered, 2)

    def test_swaps_keep_articles_and_plurals_right(self):
        swap = _swapper(_Draw(1), probability=1.0)  # every substitution switched on
        self.assertEqual(swap("An organization reviewed an incident."), "A company examined an event.")
        self.assertEqual(swap("Incidents and procedures are reviewed."), "Events and processes are examined.")
        wrong_article = re.compile(r"\b(a [aeiou]|an [^aeiou\W])", re.IGNORECASE)
        before = sum(len(wrong_article.findall(s)) for s in CATALOG_SENTENCES)
        after = sum(len(wrong_article.findall(swap(s))) for s in CATALOG_SENTENCES)
        self.assertLessEqual(after, before)
        for sentence in CATALOG_SENTENCES:
            self.assertNotIn("  ", swap(sentence))
            self.assertEqual(
                swap(sentence)[:1].isupper(), sentence[:1].isupper(), sentence
            )  # a sentence keeps its capital


class ScoringTests(unittest.TestCase):
    def matrix(self):
        pairs = (
            [("met", "met")] * 8 + [("met", "partial")] * 2
            + [("partial", "met")] * 1 + [("partial", "partial")] * 6 + [("partial", "gap")] * 3
            + [("gap", "partial")] * 2 + [("gap", "gap")] * 8 + [("gap", "error")] * 1
        )  # fmt: skip
        return confusion(pairs)

    def test_per_class_numbers(self):
        scores = summarize(self.matrix())
        met, partial, gap = (scores["classes"][c] for c in LABELS)
        self.assertEqual((met["precision"], met["recall"], met["support"]), (8 / 9, 0.8, 10))
        self.assertEqual((partial["precision"], partial["recall"], partial["support"]), (6 / 10, 6 / 10, 10))
        self.assertEqual((gap["precision"], gap["recall"], gap["support"]), (8 / 11, 8 / 11, 11))
        self.assertAlmostEqual(met["f1"], 2 * (8 / 9) * 0.8 / (8 / 9 + 0.8))
        self.assertEqual(scores["total"], 31)
        self.assertEqual(scores["errors"], 1)
        self.assertAlmostEqual(scores["accuracy"], 22 / 31)
        self.assertAlmostEqual(scores["macro_f1"], sum(c["f1"] for c in scores["classes"].values()) / 3)

    def test_the_mistakes_that_matter(self):
        scores = summarize(self.matrix())
        self.assertEqual(scores["gap_called_met"], {"count": 0, "of": 11, "rate": 0.0})
        self.assertEqual(scores["gap_called_met_or_partial"]["count"], 2)
        self.assertEqual(scores["met_called_gap"]["count"], 0)
        # four one-step mistakes among the 30 answered controls; the error is not an answer
        self.assertAlmostEqual(scores["mean_ordinal_error"], (2 * 1 + 1 * 1 + 3 * 1 + 2 * 1) / 30)

    def test_size_of_a_mistake(self):
        scores = summarize(confusion([("gap", "met"), ("met", "gap")]))
        self.assertEqual(scores["mean_ordinal_error"], 2.0)

    def test_an_error_is_a_miss_and_an_absent_label_is_left_out(self):
        scores = summarize(confusion([("met", "error"), ("met", "met")]))
        self.assertEqual(scores["classes"]["met"]["recall"], 0.5)
        self.assertIsNone(scores["classes"]["gap"]["f1"])
        self.assertEqual(scores["macro_f1"], scores["classes"]["met"]["f1"])
        never_right = summarize(confusion([("met", "gap")]))
        self.assertEqual(never_right["classes"]["met"]["f1"], 0.0)
        self.assertIsNone(never_right["classes"]["met"]["precision"])

    def test_unknown_predictions_count_as_errors_and_matrices_add(self):
        m = confusion([("met", "banana")])
        self.assertEqual(m["met"]["error"], 1)
        total = merge([m, confusion([("met", "met")])])
        self.assertEqual((total["met"]["error"], total["met"]["met"]), (1, 1))
        self.assertEqual(set(total), set(LABELS))
        self.assertEqual(set(total["met"]), set(COLUMNS))

    def test_nothing_scored_does_not_divide_by_zero(self):
        scores = summarize(confusion([]))
        self.assertEqual(scores["total"], 0)
        self.assertIsNone(scores["accuracy"])
        self.assertIsNone(scores["macro_f1"])
        self.assertIsNone(scores["mean_ordinal_error"])


class RunnerTests(unittest.IsolatedAsyncioTestCase):
    async def test_a_careful_reader_scores_well_and_cites_the_right_text(self):
        for difficulty in ("easy", "hard"):
            result = await evaluate(IdealReader, seeds=[1, 2], difficulty=difficulty)
            report = build_report(result)
            self.assertEqual(report["run"]["backend"], "test:ideal-reader")
            self.assertEqual((report["run"]["documents"], report["run"]["model_calls"]), (2, 96))
            self.assertGreaterEqual(report["scores"]["accuracy"], 0.95, difficulty)
            self.assertEqual(report["scores"]["gap_called_met"]["count"], 0)
            self.assertEqual(report["evidence"]["claims_quoting_own_text_rate"], 1.0)
            self.assertEqual(report["evidence"]["quotes_in_own_text_rate"], 1.0)
            self.assertGreaterEqual(report["retrieval"]["any_sentence_retrieved_rate"], 0.95)
            self.assertEqual(report["flags"], {})

    async def test_a_backend_that_makes_up_support_cannot_get_a_met(self):
        result = await evaluate(lambda _policy: Fabricator(), seeds=[1], difficulty="easy")
        report = build_report(result)
        matrix = report["confusion"]
        for truth in LABELS:  # whatever the truth, the checked answer is a gap
            self.assertEqual((matrix[truth]["met"], matrix[truth]["partial"], matrix[truth]["error"]), (0, 0, 0), truth)
        self.assertEqual(report["scores"]["classes"]["met"]["recall"], 0.0)
        self.assertEqual(report["scores"]["gap_called_met_or_partial"]["count"], 0)
        self.assertEqual(report["flags"]["unsupported_downgraded"], 48)
        self.assertEqual(report["flags"]["quote_not_found"], 48)

    async def test_a_backend_that_is_down_scores_errors_not_guesses(self):
        result = await evaluate(
            lambda _policy: Down(), seeds=[1], difficulty="easy", control_ids=["data-backup-plan", "automatic-logoff"]
        )
        report = build_report(result)
        self.assertEqual(report["scores"]["errors"], 2)
        self.assertEqual(report["scores"]["macro_f1"], 0.0)
        self.assertEqual(report["flags"]["assessment_failed"], 2)

    async def test_the_reason_each_control_failed_is_kept(self):
        result = await evaluate(
            lambda _policy: Down(), seeds=[1], difficulty="easy", control_ids=["data-backup-plan", "automatic-logoff"]
        )
        self.assertEqual(
            result.documents[0].errors,
            {"data-backup-plan": "the service is down", "automatic-logoff": "the service is down"},
        )
        ideal = await evaluate(IdealReader, seeds=[1], difficulty="easy", control_ids=["data-backup-plan"])
        self.assertEqual(ideal.documents[0].errors, {})

    async def test_a_rejected_key_stops_the_evaluation(self):
        with self.assertRaises(LLMAuthError):
            await evaluate(
                lambda _policy: Rejected(), seeds=[1, 2], difficulty="easy", control_ids=["data-backup-plan"]
            )

    async def test_progress_and_cancel(self):
        calls = []
        await evaluate(
            IdealReader,
            seeds=[1, 2],
            difficulty="easy",
            control_ids=["data-backup-plan"],
            progress=lambda d, t: calls.append((d, t)),
        )
        self.assertEqual(calls, [(1, 2), (2, 2)])
        stop = asyncio.Event()
        stop.set()
        result = await evaluate(
            IdealReader, seeds=[1, 2], difficulty="easy", control_ids=["data-backup-plan"], cancel=stop
        )
        self.assertEqual(result.documents, [])
        report = build_report(result)  # an empty run still renders
        self.assertIn("n/a", render_markdown(report))

    async def test_heuristic_backend_runs_and_never_calls_a_gap_met(self):
        result = await evaluate(lambda _policy: HeuristicBackend(), seeds=[1], difficulty="hard")
        report = build_report(result)
        self.assertEqual(report["run"]["backend"], "heuristic:keywords")
        self.assertEqual(report["scores"]["total"], 48)
        self.assertEqual(report["scores"]["gap_called_met"]["count"], 0)


class ReportTests(unittest.IsolatedAsyncioTestCase):
    async def test_json_and_markdown(self):
        result = await evaluate(
            IdealReader, seeds=[1, 2], difficulty="hard", control_ids=[c.id for c in CATALOG.controls[:12]]
        )
        report = build_report(result, generated_at="2026-10-24T00:00:00+00:00")
        self.assertEqual(build_report(result, generated_at="2026-10-24T00:00:00+00:00"), report)
        parsed = json.loads(render_json(report))
        self.assertEqual(parsed["schema_version"], 1)
        self.assertEqual(parsed["run"]["controls_per_document"], 12)
        self.assertEqual(len(parsed["spread"]["per_document"]), 2)
        self.assertEqual(set(parsed["confusion"]), set(LABELS))
        markdown = render_markdown(report)
        for heading in (
            "# Evaluation on synthetic policies",
            "## Scores",
            "## Confusion matrix",
            "## Mistakes that matter",
            "## Evidence and retrieval",
        ):
            self.assertIn(heading, markdown)
        self.assertIn("not an estimate of accuracy on real policies", markdown)
        self.assertNotIn("nan", markdown.lower().replace("financial", ""))
        self.assertNotIn("None", markdown)


if __name__ == "__main__":
    unittest.main()
