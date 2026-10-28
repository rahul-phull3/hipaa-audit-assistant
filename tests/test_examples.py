"""The clinic example policy stays readable, and its PDF stays the same text as its Markdown twin."""

import re
import unittest
from pathlib import Path

from hipaa_audit.ingest import parse_document

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
NAME = "clinic_security_policy"


def words(blocks) -> list[str]:
    return re.findall(r"[a-z0-9]+", " ".join(b.text for b in blocks).lower())


class ClinicPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pdf = parse_document(f"{NAME}.pdf", (EXAMPLES / f"{NAME}.pdf").read_bytes())
        cls.md = parse_document(f"{NAME}.md", (EXAMPLES / f"{NAME}.md").read_bytes())

    def test_the_pdf_is_the_same_text_as_the_markdown(self):
        self.assertEqual(words(self.pdf), words(self.md))

    def test_the_pdf_has_four_pages_and_its_numbered_sections(self):
        self.assertEqual({b.page for b in self.pdf}, {1, 2, 3, 4})
        headings = [b.text for b in self.pdf if b.is_heading]
        for expected in (
            "1. Purpose and scope",
            "8. Technical safeguards",
            "8.3 Audit logging and review",
            "13. Exceptions",
        ):
            self.assertIn(expected, headings)

    def test_an_acronym_in_the_table_is_not_taken_for_a_section(self):
        self.assertNotIn("CISO", [b.text for b in self.pdf if b.is_heading])
        under_a_section = False
        for block in self.pdf:
            if block.is_heading and block.text.startswith("1. "):
                under_a_section = True
            if under_a_section:
                self.assertRegex(block.section, r"^\d+\. ", block.text[:60])


if __name__ == "__main__":
    unittest.main()
