import importlib.util
import random
import unittest

import numpy as np

from hipaa_audit.catalog import load_catalog
from hipaa_audit.ingest.chunking import chunk_blocks
from hipaa_audit.models import Block, Chunk
from hipaa_audit.retrieval import HashingEmbedder, HybridIndex, make_embedder
from hipaa_audit.retrieval.bm25 import BM25Index
from hipaa_audit.retrieval.text import stem, tokenize

FASTEMBED_INSTALLED = importlib.util.find_spec("fastembed") is not None


class TextTests(unittest.TestCase):
    def test_stem_is_consistent_for_common_forms(self):
        self.assertEqual(stem("logging"), "log")
        self.assertEqual(stem("encrypted"), stem("encrypt"))
        self.assertEqual(stem("policies"), "policy")
        self.assertEqual(stem("devices"), "device")
        self.assertEqual(stem("processes"), "process")
        self.assertEqual(stem("access"), "access")
        self.assertEqual(stem("backups"), "backup")

    def test_tokenize_expands_hyphens_and_drops_stopwords(self):
        tokens = tokenize("Log-in attempts and the multi-factor authentication")
        self.assertIn("login", tokens)
        self.assertIn("multifactor", tokens)
        self.assertNotIn("the", tokens)
        self.assertNotIn("and", tokens)


class BM25Tests(unittest.TestCase):
    def setUp(self):
        docs = [
            "passwords must be changed and never shared",
            "backups are taken daily and stored off site",
            "visitors sign in and are escorted at all times",
            "backups of backups are encrypted",
        ]
        self.index = BM25Index([tokenize(d) for d in docs])

    def test_ranks_the_matching_document_first(self):
        top = self.index.top(tokenize("password sharing"), 3)
        self.assertEqual(top[0][0], 0)

    def test_term_frequency_and_order(self):
        top = self.index.top(tokenize("backups"), 3)
        self.assertEqual([i for i, _ in top], [3, 1])  # more occurrences first, only matching documents returned

    def test_no_match_gives_nothing(self):
        self.assertEqual(self.index.top(tokenize("quantum"), 5), [])

    def test_empty_index(self):
        self.assertEqual(BM25Index([]).top(["a"], 3), [])


class EmbedderTests(unittest.TestCase):
    def test_deterministic_and_normalised(self):
        e = HashingEmbedder()
        a = e.embed_documents(["encrypt data at rest", "visitors are escorted"])
        b = e.embed_documents(["encrypt data at rest", "visitors are escorted"])
        np.testing.assert_array_equal(a, b)
        np.testing.assert_allclose(np.linalg.norm(a, axis=1), 1.0, rtol=1e-5)
        self.assertEqual(e.embed_documents([]).shape, (0, e.dim))

    def test_similar_text_is_closer_than_unrelated_text(self):
        e = HashingEmbedder()
        docs = e.embed_documents(["encryption of data at rest with AES", "visitors sign in at the front desk"])
        query = e.embed_query("data is encrypted at rest")
        sims = docs @ query
        self.assertGreater(sims[0], sims[1])

    def test_make_embedder(self):
        self.assertIsInstance(make_embedder("hashing"), HashingEmbedder)
        with self.assertRaises(ValueError):
            make_embedder("nope")

    @unittest.skipIf(FASTEMBED_INSTALLED, "fastembed is installed here")
    def test_missing_fastembed_falls_back_in_auto_mode_and_raises_when_forced(self):
        self.assertIsInstance(make_embedder("auto"), HashingEmbedder)
        with self.assertRaises(RuntimeError):
            make_embedder("fastembed")


def _document_from_catalog():
    """One section per control built from its synthetic sentences, with filler paragraphs between sections."""
    catalog = load_catalog()
    rnd = random.Random(3)
    filler = [
        "The company was founded to provide care to patients across several regions and employs staff in many offices.",
        "This document is reviewed by the leadership team and distributed to departments for information purposes.",
        "Our mission is to deliver reliable service and to treat every customer with respect and professionalism.",
    ]
    blocks, owner = [], {}
    for control in catalog.controls:
        blocks.append(Block(text=control.title, section=control.title, is_heading=True))
        text = " ".join(c.synth[0] for c in control.criteria)
        blocks.append(Block(text=text, section=control.title))
        owner[control.id] = text.split(". ")[0][:60]
        blocks.extend(Block(text=rnd.choice(filler), section=control.title) for _ in range(2))
    return catalog, blocks, owner


class HybridTests(unittest.TestCase):
    def test_recall_on_a_synthetic_policy(self):
        catalog, blocks, owner = _document_from_catalog()
        chunks = chunk_blocks(blocks, target_words=160, overlap_words=30)
        index = HybridIndex(chunks, HashingEmbedder())
        found = 0
        for control in catalog.controls:
            hits = index.search(control.queries, k=6)
            if any(owner[control.id] in h.chunk.text for h in hits):
                found += 1
        # An easy benchmark (the document is written from the same catalog), so this is a regression guard, not a claim of accuracy.
        self.assertGreaterEqual(found / len(catalog.controls), 0.9, f"recall@6 = {found}/{len(catalog.controls)}")

    def test_hit_metadata_and_ordering(self):
        chunks = [
            Chunk(id="c0001", ord=0, text="Backups are taken daily and stored off site.", n_words=8),
            Chunk(id="c0002", ord=1, text="Visitors sign in and are escorted.", n_words=6),
        ]
        index = HybridIndex(chunks, HashingEmbedder())
        hits = index.search(["daily backups", "off-site storage of backups"], k=2)
        self.assertEqual(hits[0].chunk.id, "c0001")
        self.assertEqual(hits[0].matched_queries, 2)
        self.assertEqual(hits[0].bm25_rank, 1)
        scores = [h.score for h in hits]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_empty_index_and_k_larger_than_corpus(self):
        self.assertEqual(HybridIndex([], HashingEmbedder()).search(["anything"]), [])
        chunks = [Chunk(id="c0001", ord=0, text="Only one chunk about encryption.", n_words=5)]
        self.assertEqual(len(HybridIndex(chunks, HashingEmbedder()).search(["encryption"], k=10)), 1)


if __name__ == "__main__":
    unittest.main()
