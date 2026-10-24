"""Synthetic policy documents whose answers are known.

Each document is written from the catalog's own example sentences (the ``synth`` field of every criterion). A control is

* **met** when every one of its sentences is in the document,
* **partial** when some but not all are, and
* a **gap** when none are. Some gaps get a vague line that names the topic and commits to nothing (a decoy).

The label of every control is therefore known by construction, and so is the paragraph that carries each answer. That makes the
documents useful for comparing backends and versions and for catching regressions. They are easier than real policies, which
word things in their own way, so scores on them say nothing reliable about accuracy on real documents.

The ``hard`` difficulty swaps common words for synonyms, drops the descriptive headings and sometimes moves a control's last
sentence to an appendix. Generation uses only ``random.Random.random()`` so a seed gives the same document on every Python version.
"""

from __future__ import annotations

import random
import re
from collections.abc import Sequence
from dataclasses import dataclass, field

from hipaa_audit.catalog import Catalog, Control, load_catalog

DIFFICULTIES = ("easy", "hard")

ORGANIZATIONS = (
    "Northwind Clinic Group",
    "Harborview Health Partners",
    "Cedar Ridge Medical Associates",
    "Summit Valley Pediatrics",
    "Lakeside Diagnostics",
)

SAFEGUARD_TITLES = {
    "administrative": "Part A. Administrative safeguards",
    "physical": "Part B. Physical safeguards",
    "technical": "Part C. Technical safeguards",
    "organizational": "Part D. Business associates",
    "documentation": "Part E. Policies and documentation",
}

# Text that belongs in any policy and answers none of the controls.
FILLER = (
    "This policy sets out how the practice protects the information that patients and partners entrust to it.",
    "It applies to employees, contractors, volunteers and students, wherever they work.",
    "Questions about this policy are directed to the compliance office.",
    "Exceptions are requested in writing, approved for a limited time and listed in the exceptions register.",
    "Terms such as ePHI have the meaning given in the HIPAA regulations.",
    "Where this policy and a law differ, the stricter requirement applies.",
    "Each section is reviewed by its owner before the policy is reissued.",
    "Examples in this document are illustrative and do not limit the requirements.",
)

# Vague lines that name a topic and commit to nothing. A reviewer should still call the control a gap.
DECOYS = (
    "Management is committed to {topic} as part of protecting patient information and expects everyone to take it seriously.",
    "{Topic} is an important part of the overall security program and is handled through ordinary good practice.",
    "More detail on {topic} may be provided in separate guidance when it is needed.",
)

# Whole-word substitutions for the hard difficulty. They are common synonyms chosen so the sentence stays grammatical in every
# place the catalog uses the word; plurals are listed on their own.
SWAPS: tuple[tuple[str, str], ...] = (
    (r"workforce members", "staff members"),
    (r"organization", "company"),
    (r"performs", "carries out"),
    (r"annually", "once a year"),
    (r"whenever", "each time"),
    (r"regularly", "on a routine basis"),
    (r"reviewed", "examined"),
    (r"recorded", "logged"),
    (r"retained", "kept"),
    (r"authorized", "approved"),
    (r"incidents", "events"),
    (r"incident", "event"),
    (r"restored", "recovered"),
    (r"tampering", "unauthorized alteration"),
    (r"suspected", "possible"),
    (r"equipment", "hardware"),
    (r"official", "officer"),
    (r"analysis", "assessment"),
    (r"procedures", "processes"),
    (r"procedure", "process"),
)
SWAP_PROBABILITY = (
    0.75  # each substitution is used for a whole document with this probability, like one author's habits
)
SCATTER_PROBABILITY = 0.4  # chance that a control's last sentence is moved to the appendix (hard difficulty)


@dataclass(frozen=True)
class Mix:
    """Target shares of controls by truth, and the share of gaps that get a vague decoy line."""

    met: float = 0.35
    partial: float = 0.30
    gap: float = 0.35
    decoy_rate: float = 0.4

    def pick(self, draw: float) -> str:
        total = self.met + self.partial + self.gap
        if draw * total < self.met:
            return "met"
        return "partial" if draw * total < self.met + self.partial else "gap"


@dataclass
class ControlTruth:
    control_id: str
    status: str  # met, partial or gap
    present: list[str] = field(default_factory=list)  # criterion ids written into the document
    absent: list[str] = field(default_factory=list)
    own_texts: list[str] = field(default_factory=list)  # the paragraphs that carry the answer, exactly as written
    sentences: list[str] = field(default_factory=list)  # the sentences written, as they appear in the document
    decoy: str | None = None  # the vague paragraph, for a gap that has one


@dataclass
class SyntheticPolicy:
    seed: int
    difficulty: str
    text: str
    truth: dict[str, ControlTruth]

    def filename(self) -> str:
        return f"synthetic-{self.difficulty}-{self.seed}.txt"


class _Draw:
    """Seeded randomness built on ``random()`` only, so the sequence does not depend on the Python version."""

    def __init__(self, seed: int) -> None:
        self._rng = random.Random(seed)

    def unit(self) -> float:
        return self._rng.random()

    def below(self, n: int) -> int:
        return min(n - 1, int(self.unit() * n))

    def order(self, items: Sequence) -> list:
        keyed = [(self.unit(), i, item) for i, item in enumerate(items)]
        return [item for _key, _i, item in sorted(keyed, key=lambda k: (k[0], k[1]))]


def _recase(original: str, new: str) -> str:
    return new[:1].upper() + new[1:] if original[:1].isupper() else new


def _swapper(draw: _Draw, probability: float = SWAP_PROBABILITY):
    """A function that rewords a sentence with the substitutions this document's author happens to use."""
    # An optional article in front of the word is captured so "an organization" can become "a company".
    active = [
        (re.compile(rf"(?:\b(?P<article>an?)\s+)?\b(?P<word>{pattern})\b", re.IGNORECASE), repl)
        for pattern, repl in SWAPS
        if draw.unit() < probability
    ]

    def apply(text: str) -> str:
        for regex, repl in active:

            def replace(match: re.Match[str], repl: str = repl) -> str:
                new = _recase(match.group("word"), repl)
                article = match.group("article")
                if article is None:
                    return new
                chosen = "an" if new[:1].lower() in "aeiou" else "a"
                return f"{_recase(article, chosen)} {new}"

            text = regex.sub(replace, text)
        return text

    return apply


def _decoy(control: Control, draw: _Draw) -> str:
    template = DECOYS[draw.below(len(DECOYS))]
    topic = control.title.lower()
    return template.format(topic=topic, Topic=topic[:1].upper() + topic[1:])


def generate_policy(
    seed: int,
    *,
    difficulty: str = "easy",
    mix: Mix | None = None,
    catalog: Catalog | None = None,
    control_ids: Sequence[str] | None = None,
) -> SyntheticPolicy:
    if difficulty not in DIFFICULTIES:
        raise ValueError(f"difficulty must be one of {DIFFICULTIES}")
    mix = mix or Mix()
    catalog = catalog or load_catalog()
    controls = catalog.select(list(control_ids) if control_ids else None)
    hard = difficulty == "hard"
    draw = _Draw(seed)
    swap = _swapper(draw) if hard else (lambda text: text)

    truth: dict[str, ControlTruth] = {}
    sections: dict[str, list[tuple[Control, str]]] = {sg: [] for sg in SAFEGUARD_TITLES}
    appendix: list[str] = []
    for control in controls:
        status = mix.pick(draw.unit())
        criteria = control.criteria
        if status == "met":
            chosen = list(range(len(criteria)))
        elif status == "partial":
            keep = 1 + draw.below(len(criteria) - 1)  # at least one, never all
            chosen = sorted(draw.order(range(len(criteria)))[:keep])
        else:
            chosen = []
        entry = ControlTruth(
            control_id=control.id,
            status=status,
            present=[criteria[i].id for i in chosen],
            absent=[c.id for i, c in enumerate(criteria) if i not in chosen],
        )
        truth[control.id] = entry
        if chosen:
            entry.sentences = [swap(criteria[i].synth[0]) for i in chosen]
            in_place = list(entry.sentences)
            moved = None
            if hard and len(in_place) > 1 and draw.unit() < SCATTER_PROBABILITY:
                moved = in_place.pop()  # the control's last sentence turns up in the appendix instead
                appendix.append(moved)
            entry.own_texts = [" ".join(in_place), *([moved] if moved else [])]
            sections[control.safeguard].append((control, entry.own_texts[0]))
        elif draw.unit() < mix.decoy_rate:
            entry.decoy = _decoy(control, draw)
            sections[control.safeguard].append((control, entry.decoy))

    organization = ORGANIZATIONS[draw.below(len(ORGANIZATIONS))]
    filler = iter(draw.order(FILLER))
    lines = [
        f"{organization.upper()} INFORMATION SECURITY POLICY",
        "",
        f"Version 3.{1 + draw.below(8)}. Owner: Information Security.",
        "",
    ]
    lines += ["Purpose and scope", "", next(filler), next(filler), ""]
    number = 0
    for safeguard, title in SAFEGUARD_TITLES.items():
        if not sections[safeguard]:
            continue
        lines += [title, ""]
        for control, paragraph in draw.order(sections[safeguard]):
            number += 1
            lines += [f"Section {number}" if hard else f"{number}. {control.title}", "", paragraph, ""]
            if draw.unit() < 0.3:
                extra = next(filler, None)
                if extra:
                    lines += [extra, ""]
    if appendix:
        lines += ["Appendix. Supplementary requirements", ""]
        for sentence in draw.order(appendix):
            lines += [sentence, ""]
    return SyntheticPolicy(seed=seed, difficulty=difficulty, text="\n".join(lines).rstrip() + "\n", truth=truth)
