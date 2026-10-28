"""Checks that the numbers a model writes in its own words come from the document.

Quotes are checked word for word in ``verify``. The rationale and the list of missing elements are the model's own sentences, and a
fluent sentence can carry a number nobody wrote: "sessions lock after 15 minutes" when the policy says 10. This module finds
durations, lengths, percentages and counts of attempts in such a sentence and reports the ones that appear neither in the passages
the model was shown nor in the control's own description.

Only a number with a unit is looked at, so "two of the three elements" is left alone. Different ways of writing the same period are
read as one: "annually", "every year", "once a year" and "12 months" are all twelve months.
"""

from __future__ import annotations

import html
import re
import unicodedata
from dataclasses import dataclass

from hipaa_audit.catalog import Control

_WORDS = {
    "zero": 0, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9,
    "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14, "fifteen": 15, "sixteen": 16,
    "seventeen": 17, "eighteen": 18, "nineteen": 19, "twenty": 20, "thirty": 30, "forty": 40, "fifty": 50,
    "sixty": 60, "seventy": 70, "eighty": 80, "ninety": 90, "a": 1, "an": 1,
}  # fmt: skip
_ONES = "one|two|three|four|five|six|seven|eight|nine"
_TENS = "twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety"
_NUMBER = (
    rf"\d+(?:\.\d+)?|(?:{_TENS})(?:[- ](?:{_ONES}))?|zero|{_ONES}|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen"
    r"|seventeen|eighteen|nineteen|an?"
)
_UNIT = r"(?:%|(?:percent|seconds?|minutes?|hours?|days?|weeks?|months?|years?|characters?|digits?|attempts?)\b)"
_QUANTITY = re.compile(
    rf"(?<![\w.])(?P<a>{_NUMBER})\b(?:\s*(?:to|or|and|-|–)\s*(?P<b>{_NUMBER})\b)?\s*-?\s*"
    rf"(?:business\s+|calendar\s+|working\s+)?(?P<unit>{_UNIT})"
)
_EVERY = re.compile(r"\b(?:every|each|per)\s+(?P<unit>second|minute|hour|day|night|week|month|quarter|year)\b")
_FREQUENCY = {
    "annually": (12, "month"), "annual": (12, "month"), "yearly": (12, "month"), "semiannually": (6, "month"),
    "semiannual": (6, "month"), "quarterly": (3, "month"), "monthly": (1, "month"), "weekly": (7, "day"),
    "daily": (1, "day"), "nightly": (1, "day"), "hourly": (1, "hour"),
}  # fmt: skip
_FREQUENCY_WORD = re.compile(r"\b(" + "|".join(sorted(_FREQUENCY, key=len, reverse=True)) + r")\b")
_BRACKETED = re.compile(r"\(\s*(\d+(?:\.\d+)?)\s*\)")
_TWICE_A_YEAR = re.compile(r"\btwice (?:a|per|each|every) year\b|\btwice yearly\b")


@dataclass(frozen=True)
class Quantity:
    """An amount with a unit, in a form that does not depend on how it was written, and the words that were matched."""

    value: float
    unit: str
    shown: str

    @property
    def key(self) -> tuple[float, str]:
        return self.value, self.unit


def _flat(text: str) -> str:
    t = unicodedata.normalize("NFKC", html.unescape(text)).lower().replace("semi-annual", "semiannual")
    t = _TWICE_A_YEAR.sub("every six months", t)
    return re.sub(r"\s+", " ", _BRACKETED.sub(r" \1 ", t)).strip()


def _number(word: str) -> float:
    if word in _WORDS:
        return float(_WORDS[word])
    if word[:1].isdigit():
        return float(word)
    parts = re.split(r"[- ]", word)
    return float(sum(_WORDS[p] for p in parts))


def _canonical(value: float, unit: str) -> tuple[float, str]:
    unit = "%" if unit in ("%", "percent") else unit.rstrip("s")
    if unit == "year":
        return value * 12, "month"
    if unit == "quarter":
        return value * 3, "month"
    if unit == "week":
        return value * 7, "day"
    if unit == "night":
        return value, "day"
    return value, unit


def find_quantities(text: str) -> list[Quantity]:
    """Every amount with a unit in the text: '15 minutes', 'six years', '99.9%', 'every quarter', 'annually'."""
    flat = _flat(text)
    found: list[Quantity] = []
    for m in _QUANTITY.finditer(flat):
        shown = m.group(0).strip()
        for group in ("a", "b"):
            if m.group(group):
                value, unit = _canonical(_number(m.group(group)), m.group("unit"))
                found.append(Quantity(value, unit, shown))
    for m in _EVERY.finditer(flat):
        value, unit = _canonical(1, m.group("unit"))
        found.append(Quantity(value, unit, m.group(0)))
    for m in _FREQUENCY_WORD.finditer(flat):
        value, unit = _FREQUENCY[m.group(1)]
        found.append(Quantity(value, unit, m.group(0)))
    return found


def allowed_quantities(texts: list[str]) -> set[tuple[float, str]]:
    """The amounts that appear in any of the texts."""
    return {q.key for text in texts for q in find_quantities(text)}


def ungrounded_quantities(text: str, allowed: set[tuple[float, str]]) -> list[str]:
    """The amounts written in the text that are not in the allowed set, as they were written, each once."""
    out: list[str] = []
    for q in find_quantities(text):
        if q.key not in allowed and q.shown not in out:
            out.append(q.shown)
    return out


def control_reference(control: Control) -> str:
    """What the control itself says, so a model may name the period or length the regulation or the control expects."""
    return " ".join([control.expectation, *(c.text for c in control.criteria)])
