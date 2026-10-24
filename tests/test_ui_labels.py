"""The interface repeats the safeguard names the downloaded report uses. Keep the two lists from drifting apart."""

import re
import unittest
from pathlib import Path

from hipaa_audit.report import SAFEGUARD_LABELS

SOURCE = Path(__file__).resolve().parents[1] / "ui" / "src" / "findings.ts"


@unittest.skipUnless(SOURCE.is_file(), "the interface sources are not in this checkout")
class UiLabelTests(unittest.TestCase):
    def test_safeguard_names_match_the_report(self):
        text = SOURCE.read_text(encoding="utf-8")
        block = re.search(r"export const SAFEGUARD_LABELS[^{]*\{(.*?)\n\};", text, re.S)
        self.assertIsNotNone(block, "SAFEGUARD_LABELS was not found in ui/src/findings.ts")
        shown = dict(re.findall(r'(\w+):\s*"([^"]+)"', block.group(1)))
        self.assertEqual(shown, SAFEGUARD_LABELS)


if __name__ == "__main__":
    unittest.main()
