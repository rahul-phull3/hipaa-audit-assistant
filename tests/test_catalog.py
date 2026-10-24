import re
import unittest

from pydantic import ValidationError

from hipaa_audit.catalog import Catalog, load_catalog

SECTION_TO_SAFEGUARD = {
    "308": "administrative",
    "310": "physical",
    "312": "technical",
    "314": "organizational",
    "316": "documentation",
}


class CatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = load_catalog()

    def test_size_and_split(self):
        self.assertEqual(len(self.catalog.controls), 48)
        self.assertEqual(
            self.catalog.counts_by_safeguard(),
            {"administrative": 23, "physical": 10, "technical": 10, "organizational": 1, "documentation": 4},
        )

    def test_citation_matches_safeguard(self):
        for c in self.catalog.controls:
            m = re.match(r"^45 CFR 164\.(308|310|312|314|316)\(", c.citation)
            self.assertIsNotNone(m, c.citation)
            self.assertEqual(SECTION_TO_SAFEGUARD[m.group(1)], c.safeguard, c.id)

    def test_known_requirement_flags(self):
        self.assertEqual(self.catalog.get("risk-analysis").requirement, "required")
        self.assertEqual(self.catalog.get("password-management").requirement, "addressable")
        self.assertEqual(self.catalog.get("audit-controls").requirement, "required")
        self.assertEqual(self.catalog.get("transmission-encryption").requirement, "addressable")

    def test_keywords_are_lowercase_and_criteria_are_usable(self):
        for c in self.catalog.controls:
            self.assertGreaterEqual(len(c.queries), 2, c.id)
            for crit in c.criteria:
                for kw in crit.keywords:
                    self.assertEqual(kw, kw.lower(), f"{c.id}/{crit.id}: keyword not lowercase: {kw}")
                for s in crit.synth:
                    self.assertTrue(s.rstrip().endswith("."), f"{c.id}/{crit.id}: synth sentence has no full stop")
                    self.assertGreaterEqual(len(s.split()), 6, f"{c.id}/{crit.id}: synth sentence too short")

    def test_meta_mentions_the_proposed_revision(self):
        self.assertIn("27 December 2024", self.catalog.meta.rule_status)
        self.assertTrue(self.catalog.meta.version)

    def test_select(self):
        self.assertEqual(len(self.catalog.select(None)), 48)
        self.assertEqual(len(self.catalog.select([])), 48)
        picked = self.catalog.select(["audit-controls", "risk-analysis"])
        self.assertEqual(
            [c.id for c in picked], ["risk-analysis", "audit-controls"]
        )  # catalog order, not request order
        with self.assertRaises(KeyError):
            self.catalog.select(["nope"])

    def test_duplicate_ids_are_rejected(self):
        first = self.catalog.controls[0]
        with self.assertRaises(ValidationError):
            Catalog(meta=self.catalog.meta, controls=[first, first])


if __name__ == "__main__":
    unittest.main()
