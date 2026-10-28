import io
import logging
import random
import unittest
import zipfile
from collections import Counter

from hipaa_audit.ingest import UnsupportedDocument, chunk_blocks, parse_document
from hipaa_audit.ingest.parsers import heading_of
from hipaa_audit.models import Block
from tests.fixtures import SAMPLE_POLICY, make_docx, make_pdf


class HeadingTests(unittest.TestCase):
    def test_detects_headings(self):
        self.assertEqual(heading_of("## Backups"), (2, "Backups"))
        self.assertEqual(heading_of("ACCESS CONTROL POLICY"), (1, "ACCESS CONTROL POLICY"))
        self.assertEqual(heading_of("2.1 Automatic Logoff"), (3, "2.1 Automatic Logoff"))

    def test_an_acronym_on_its_own_line_inside_running_text_is_not_a_heading(self):
        # A table cell or a wrapped line can leave "CISO" or "HIPAA" alone on a line after a line that does not end a sentence.
        self.assertIsNone(heading_of("CISO", previous="Systems and databases, only when needed to fix a"))
        self.assertIsNone(heading_of("HIPAA", previous="the policies required by"))
        # Headings still count when they start a page or follow the end of a sentence or another heading.
        self.assertEqual(heading_of("PURPOSE"), (1, "PURPOSE"))
        self.assertEqual(heading_of("PURPOSE", previous="That is the end of the paragraph."), (1, "PURPOSE"))
        # More than one word is still taken as a heading, as before.
        self.assertEqual(
            heading_of("ACCESS CONTROL POLICY", previous="no full stop here"), (1, "ACCESS CONTROL POLICY")
        )

    def test_rejects_sentences(self):
        self.assertIsNone(heading_of("This policy applies to all staff"))
        self.assertIsNone(heading_of("3. Passwords must be changed"))
        self.assertIsNone(heading_of("Sessions end after 15 minutes."))
        self.assertIsNone(heading_of(""))


class ParseTextTests(unittest.TestCase):
    def test_sections_and_bullets(self):
        blocks = parse_document("policy.txt", SAMPLE_POLICY.encode())
        headings = [b.text for b in blocks if b.is_heading]
        self.assertEqual(
            headings, ["ACCESS CONTROL POLICY", "1. Purpose", "2. Password Management", "2.1 Automatic Logoff"]
        )
        bullets = [b for b in blocks if b.text.startswith("- Passwords")]
        self.assertEqual(len(bullets), 2)
        self.assertEqual(bullets[0].section, "ACCESS CONTROL POLICY > 2. Password Management")
        logoff = next(b for b in blocks if b.text.startswith("Sessions are logged off"))
        self.assertEqual(logoff.section, "ACCESS CONTROL POLICY > 2. Password Management > 2.1 Automatic Logoff")

    def test_a_table_cell_with_an_acronym_does_not_become_a_section(self):
        text = (
            "4. Workforce security\n"
            "Access to ePHI is granted only after the data owner approves a written request that states the role and the systems needed.\n"
            "Role Access to ePHI Approved by\n"
            "Billing staff Billing and claims data Finance\n"
            "manager\n"
            "IT\n"
            "administrator\n"
            "Systems and databases, clinical content only when needed to fix a\n"
            "fault\n"
            "CISO\n"
            "Volunteer None Not applicable\n"
            "4.2 Leaving the Clinic\n"
            "When a workforce member leaves or an engagement ends, their accounts are disabled on their last working day.\n"
        )
        blocks = parse_document("policy.txt", text.encode())
        self.assertNotIn("CISO", [b.text for b in blocks if b.is_heading])
        leaving = next(b for b in blocks if b.text.startswith("When a workforce member leaves"))
        self.assertEqual(leaving.section, "4. Workforce security > 4.2 Leaving the Clinic")
        self.assertTrue(any("CISO Volunteer None" in b.text for b in blocks))  # the cell stays in the text

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
                [
                    "PASSWORD POLICY",
                    "Passwords must be at least fourteen characters long and may not be shared.",
                    "Users change a password when compromise is suspected.",
                ],
                [
                    "BACKUP POLICY",
                    "Backups of systems that hold ePHI are taken every day and are stored off-site in encrypted form.",
                ],
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


class DamagedFileTests(unittest.TestCase):
    """A damaged upload is the client's mistake. Whatever is wrong with it, the outcome is blocks or ``UnsupportedDocument``;
    any other exception would reach the API as a 500."""

    def setUp(self):
        logging.disable(logging.CRITICAL)  # pypdf reports every repair it attempts, and so do we
        self.addCleanup(logging.disable, logging.NOTSET)

    def assert_only_clean_outcomes(self, name, payloads):
        unexpected: Counter = Counter()
        for payload in payloads:
            try:
                parse_document(name, payload)
            except UnsupportedDocument:
                pass
            except Exception as exc:  # noqa: BLE001 - the point of the test
                unexpected[type(exc).__name__] += 1
        self.assertEqual(dict(unexpected), {})

    @staticmethod
    def byte_damage(base: bytes, count: int, seed: int):
        rnd = random.Random(seed)
        for _ in range(count):
            data = bytearray(base)
            kind = rnd.random()
            if kind < 0.4:
                for _ in range(rnd.randint(1, 12)):
                    data[rnd.randrange(len(data))] = rnd.randrange(256)
            elif kind < 0.7:
                del data[rnd.randrange(20, len(data)) :]
            else:
                start = rnd.randrange(len(data))
                del data[start : start + rnd.randint(1, 80)]
            yield bytes(data)

    def test_damaged_pdfs(self):
        base = make_pdf([["Passwords must be at least fourteen characters long and may not be shared."] * 4])
        self.assert_only_clean_outcomes("a.pdf", self.byte_damage(base, 400, seed=11))

    def test_pdfs_with_a_missing_page_tree(self):
        base = make_pdf([["Passwords must be at least fourteen characters long and may not be shared."] * 4])
        for old, new in (
            (b"/Pages 2 0 R", b"/Pagez 2 0 R"),  # the catalog has no page tree
            (b"/Kids [", b"/Kidz ["),  # the page tree has no children
            (b"/Root 1 0 R", b"/Rooot 1 0 R"),  # the trailer has no catalog
        ):
            self.assertIn(old, base)
            with self.subTest(change=old):
                self.assert_only_clean_outcomes("a.pdf", [base.replace(old, new)])

    def test_damaged_docx_archives_and_documents(self):
        base = make_docx()
        rnd = random.Random(5)
        with zipfile.ZipFile(io.BytesIO(base)) as archive:
            parts = {name: archive.read(name) for name in archive.namelist()}

        def inside(xml: bytes) -> bytes:
            out = io.BytesIO()
            with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
                for name, content in parts.items():
                    archive.writestr(name, xml if name == "word/document.xml" else content)
            return out.getvalue()

        def damaged_xml():
            for _ in range(200):
                xml = bytearray(parts["word/document.xml"])
                if rnd.random() < 0.5:
                    for _ in range(rnd.randint(1, 6)):
                        xml[rnd.randrange(len(xml))] = rnd.randrange(32, 127)
                else:
                    start = rnd.randrange(len(xml))
                    del xml[start : start + rnd.randint(1, 120)]
                yield inside(bytes(xml))

        self.assert_only_clean_outcomes("a.docx", self.byte_damage(base, 150, seed=3))
        self.assert_only_clean_outcomes("a.docx", damaged_xml())
        # a document whose body is missing and a style reference without its value, which the fuzzing above first turned up
        self.assert_only_clean_outcomes(
            "a.docx", [inside(b'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>')]
        )
        styled = parts["word/document.xml"].replace(b"<w:p>", b"<w:p><w:pPr><w:pStyle/></w:pPr>", 1)
        self.assertNotEqual(styled, parts["word/document.xml"])
        self.assert_only_clean_outcomes("a.docx", [inside(styled)])


def _paragraph(tag: str, n_sentences: int = 5) -> str:
    return " ".join(f"Sentence {i} of {tag} states a requirement for the workforce." for i in range(n_sentences))


class ChunkSpanTests(unittest.TestCase):
    def test_every_paragraph_keeps_its_own_page_and_section(self):
        blocks = [
            Block(text="Backups", page=1, section="Policy > Backups", is_heading=True),
            Block(
                text="Backups are taken daily and stored off site, and restores are tested twice a year.",
                page=1,
                section="Policy > Backups",
            ),
            Block(text="Passwords", page=2, section="Policy > Passwords", is_heading=True),
            Block(
                text="Passwords must be at least twelve characters long and must never be shared with anyone.",
                page=2,
                section="Policy > Passwords",
            ),
        ]
        (chunk,) = chunk_blocks(blocks, min_words=100)  # short sections are merged into one chunk
        self.assertEqual((chunk.page, chunk.section), (1, "Policy > Backups"))
        located = [(s.page, s.section, chunk.text[s.start : s.end]) for s in chunk.spans]
        self.assertEqual(
            [(p, sec) for p, sec, _ in located], [(1, "Policy > Backups")] * 2 + [(2, "Policy > Passwords")] * 2
        )
        self.assertEqual(located[1][2], blocks[1].text)
        self.assertEqual(located[3][2], blocks[3].text)

    def test_overlap_text_is_attributed_to_where_it_came_from(self):
        sentence = "The security official reviews access rights every quarter and records the result."
        long_paragraph = " ".join([sentence] * 30)
        blocks = [
            Block(text=long_paragraph, page=3, section="Policy > Access"),
            Block(
                text="Visitors sign in and are escorted at all times in secure areas of the building.",
                page=4,
                section="Policy > Visitors",
            ),
        ]
        chunks = chunk_blocks(blocks, target_words=60, overlap_words=20)
        self.assertGreater(len(chunks), 2)
        for chunk in chunks:
            self.assertEqual(chunk.spans[0].start, 0)
            self.assertEqual(chunk.spans[-1].end, len(chunk.text))
            for span in chunk.spans:
                self.assertTrue(chunk.text[span.start : span.end].strip())
        # the second chunk starts with overlap taken from page 3 and is still on page 3
        self.assertEqual(chunks[1].spans[0].page, 3)
        self.assertEqual(chunks[-1].spans[-1].page, 4)


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
        for a, b in zip(chunks, chunks[1:], strict=False):
            first_sentence_of_next = b.text.split(". ")[0]
            self.assertIn(
                first_sentence_of_next, a.text
            )  # each chunk opens with text carried over from the previous one

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
