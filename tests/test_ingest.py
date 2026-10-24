import unittest

from hipaa_audit.ingest import UnsupportedDocument, chunk_blocks, parse_document
from hipaa_audit.ingest.parsers import heading_of
from hipaa_audit.models import Block
from tests.fixtures import SAMPLE_POLICY, make_docx, make_pdf


class HeadingTests(unittest.TestCase):
    def test_detects_headings(self):
        self.assertEqual(heading_of("## Backups"), (2, "Backups"))
        self.assertEqual(heading_of("ACCESS CONTROL POLICY"), (1, "ACCESS CONTROL POLICY"))
        self.assertEqual(heading_of("2.1 Automatic Logoff"), (3, "2.1 Automatic Logoff"))

    def test_rejects_sentences(self):
        self.assertIsNone(heading_of("This policy applies to all staff"))
        self.assertIsNone(heading_of("3. Passwords must be changed"))
        self.assertIsNone(heading_of("Sessions end after 15 minutes."))
        self.assertIsNone(heading_of(""))


class ParseTextTests(unittest.TestCase):
    def test_sections_and_bullets(self):
        blocks = parse_document("policy.txt", SAMPLE_POLICY.encode())
        headings = [b.text for b in blocks if b.is_heading]
        self.assertEqual(headings, ["ACCESS CONTROL POLICY", "1. Purpose", "2. Password Management", "2.1 Automatic Logoff"])
        bullets = [b for b in blocks if b.text.startswith("- Passwords")]
        self.assertEqual(len(bullets), 2)
        self.assertEqual(bullets[0].section, "ACCESS CONTROL POLICY > 2. Password Management")
        logoff = next(b for b in blocks if b.text.startswith("Sessions are logged off"))
        self.assertEqual(logoff.section, "ACCESS CONTROL POLICY > 2. Password Management > 2.1 Automatic Logoff")

    def test_markdown_headings(self):
        md = "# Security Policy\n\n## Backups\nBackups of every system that holds ePHI are taken daily and stored off-site in encrypted form.\nThey are tested every quarter."
        blocks = parse_document("p.md", md.encode())
        body = next(b for b in blocks if not b.is_heading)
        self.assertEqual(body.section, "Security Policy > Backups")
        self.assertIn("tested every quarter", body.text)  # soft-wrapped lines are joined

    def test_binary_and_too_short_text_are_rejected(self):
        with self.assertRaises(UnsupportedDocument):
            parse_document("a.txt", b"abc\x00def" * 10)
        with self.assertRaises(UnsupportedDocument):
            parse_document("a.txt", b"too short")


class ParseDocxTests(unittest.TestCase):
    def test_headings_paragraphs_and_tables(self):
        blocks = parse_document("policy.docx", make_docx())
        self.assertEqual([b.text for b in blocks if b.is_heading], ["Information Security Policy", "Access Control"])
        table_rows = [b.text for b in blocks if " | " in b.text]
        self.assertEqual(table_rows, ["Review | Quarterly", "Owner | Security official"])
        approval = next(b for b in blocks if "approval by the data owner" in b.text)
        self.assertEqual(approval.section, "Information Security Policy > Access Control")

    def test_not_a_docx(self):
        with self.assertRaises(UnsupportedDocument):
            parse_document("policy.docx", b"this is plain text pretending to be a document")


class ParsePdfTests(unittest.TestCase):
    def test_pages_and_text(self):
        pdf = make_pdf(
            [
                ["PASSWORD POLICY", "Passwords must be at least fourteen characters long and may not be shared.", "Users change a password when compromise is suspected."],
                ["BACKUP POLICY", "Backups of systems that hold ePHI are taken every day and are stored off-site in encrypted form."],
            ]
        )
        blocks = parse_document("policy.pdf", pdf)
        self.assertEqual([b.page for b in blocks if b.is_heading], [1, 2])
        backups = next(b for b in blocks if b.text.startswith("Backups of systems"))
        self.assertEqual(backups.page, 2)
        self.assertEqual(backups.section, "BACKUP POLICY")

    def test_rejections(self):
        with self.assertRaises(UnsupportedDocument):
            parse_document("fake.pdf", b"not really a pdf")
        with self.assertRaises(UnsupportedDocument):
            parse_document("empty.pdf", b"")
        long_pdf = make_pdf([["Some sentence about security policy and procedures for the workforce."]] * 3)
        with self.assertRaises(UnsupportedDocument):
            parse_document("long.pdf", long_pdf, max_pages=2)

    def test_unknown_extension(self):
        with self.assertRaises(UnsupportedDocument):
            parse_document("policy.exe", b"MZ....")


def _paragraph(tag: str, n_sentences: int = 5) -> str:
    return " ".join(f"Sentence {i} of {tag} states a requirement for the workforce." for i in range(n_sentences))


class ChunkingTests(unittest.TestCase):
    def setUp(self):
        self.blocks = [Block(text=_paragraph(f"p{i}"), page=1 + i // 5, section="Policy") for i in range(20)]

    def test_ids_order_and_size(self):
        chunks = chunk_blocks(self.blocks, target_words=100, overlap_words=25)
        self.assertGreater(len(chunks), 5)
        self.assertEqual([c.id for c in chunks], [f"c{i + 1:04d}" for i in range(len(chunks))])
        self.assertEqual([c.ord for c in chunks], list(range(len(chunks))))
        for c in chunks:
            self.assertLessEqual(c.n_words, 100 + 25 + 5)
            self.assertTrue(c.text.strip())

    def test_every_sentence_is_covered_and_overlap_is_present(self):
        chunks = chunk_blocks(self.blocks, target_words=100, overlap_words=25)
        joined = "\n".join(c.text for c in chunks)
        for b in self.blocks:
            for sentence in b.text.split(". "):
                self.assertIn(sentence.rstrip("."), joined)
        for a, b in zip(chunks, chunks[1:]):
            first_sentence_of_next = b.text.split(". ")[0]
            self.assertIn(first_sentence_of_next, a.text)  # each chunk opens with text carried over from the previous one

    def test_long_paragraph_is_split_on_sentences(self):
        long_block = Block(text=_paragraph("long", 60), section="Policy")
        chunks = chunk_blocks([long_block], target_words=80, overlap_words=0)
        self.assertGreater(len(chunks), 3)
        for c in chunks:
            self.assertLessEqual(c.n_words, 80)
            self.assertTrue(c.text.rstrip().endswith("workforce."))

    def test_heading_closes_a_full_chunk_and_short_sections_merge(self):
        blocks = [
            Block(text="Backups", section="Backups", is_heading=True),
            Block(text=_paragraph("backup", 12), section="Backups"),
            Block(text="Training", section="Training", is_heading=True),
            Block(text="Short note.", section="Training"),
            Block(text="Retention", section="Retention", is_heading=True),
            Block(text=_paragraph("retention", 8), section="Retention"),
        ]
        chunks = chunk_blocks(blocks, target_words=400, overlap_words=0, min_words=40)
        self.assertEqual(len(chunks), 2)
        self.assertEqual(chunks[0].section, "Backups")
        self.assertIn("Training", chunks[1].text)  # the short section was merged into the next chunk
        self.assertEqual(chunks[1].section, "Training")

    def test_empty_input(self):
        self.assertEqual(chunk_blocks([]), [])


if __name__ == "__main__":
    unittest.main()
