"""Tokenisation and light stemming shared by the keyword index and the hashing embedder."""

from __future__ import annotations

import re

_TOKEN = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_VOWELS = set("aeiou")

STOPWORDS = frozenset(
    """a an and are as at be been but by can do does for from had has have how if in into is it its may of on or our
    shall should such that the their them then there these they this to under was we were what when where which who will
    with within without would you your all any each every per via also not no""".split()
)


def stem(word: str) -> str:
    """A deliberately small suffix stripper. It only has to be consistent between documents and queries."""
    w = word
    if len(w) > 4 and w.endswith("ies"):
        return w[:-3] + "y"
    for suffix in ("ingly", "edly", "ing", "ed"):
        if len(w) > len(suffix) + 2 and w.endswith(suffix):
            base = w[: -len(suffix)]
            if any(ch in _VOWELS for ch in base):
                if len(base) > 2 and base[-1] == base[-2] and base[-1] not in "lsz":
                    base = base[:-1]
                return base
    if len(w) > 5 and w.endswith(("sses", "xes")):
        return w[:-2]
    if len(w) > 3 and w.endswith("s") and not w.endswith(("ss", "us", "is")):
        return w[:-1]
    return w


def tokenize(text: str) -> list[str]:
    """Lower-case, split into alphanumeric tokens, expand hyphenated words ("log-in" -> log, in, login), stem, drop stopwords."""
    out: list[str] = []
    for raw in _TOKEN.findall(text.lower()):
        parts = raw.split("-")
        candidates = parts + ["".join(parts)] if len(parts) > 1 else parts
        for tok in candidates:
            if len(tok) < 2 or tok in STOPWORDS:
                continue
            out.append(stem(tok))
    return out
