"""HIPAA Security Rule control catalog: typed models and loader.

The catalog is data, not code: one YAML file per group of safeguards under ``catalog/data``. Every control is a paraphrase
written for review support (it is not the regulatory text), and the catalog carries a version so a finding can say which
edition it was assessed against.
"""

from __future__ import annotations

from collections import Counter
from functools import lru_cache
from importlib import resources
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, model_validator

Safeguard = Literal["administrative", "physical", "technical", "organizational", "documentation"]
Requirement = Literal["required", "addressable"]

DATA_FILES = (
    "01_administrative_a.yaml",
    "02_administrative_b.yaml",
    "03_physical.yaml",
    "04_technical.yaml",
    "05_organizational_documentation.yaml",
)


class Criterion(BaseModel):
    """One element a policy should show for a control. Used in the prompt, by the offline heuristic and by the
    synthetic-policy generator (``synth``); the language model is asked to judge the control, not to tick boxes."""

    id: str
    text: str
    keywords: list[str] = Field(min_length=2)
    synth: list[str] = Field(min_length=1)


class Control(BaseModel):
    id: str  # stable slug, used in URLs and stored findings
    citation: str  # e.g. "45 CFR 164.308(a)(1)(ii)(A)"
    title: str
    safeguard: Safeguard
    standard: str
    requirement: Requirement
    expectation: str
    criteria: list[Criterion] = Field(min_length=1)
    queries: list[str] = Field(min_length=2)

    @model_validator(mode="after")
    def _criterion_ids_unique(self) -> Control:
        ids = [c.id for c in self.criteria]
        if len(ids) != len(set(ids)):
            raise ValueError(f"{self.id}: duplicate criterion ids")
        return self


class CatalogMeta(BaseModel):
    version: str
    regulation: str
    rule_status: str
    notes: list[str] = Field(default_factory=list)


class Catalog(BaseModel):
    meta: CatalogMeta
    controls: list[Control]

    @model_validator(mode="after")
    def _unique(self) -> Catalog:
        for field in ("id", "citation"):
            seen = Counter(getattr(c, field) for c in self.controls)
            dupes = sorted(k for k, n in seen.items() if n > 1)
            if dupes:
                raise ValueError(f"duplicate control {field}: {dupes}")
        return self

    def get(self, control_id: str) -> Control:
        for control in self.controls:
            if control.id == control_id:
                return control
        raise KeyError(control_id)

    def select(self, ids: list[str] | None) -> list[Control]:
        """Controls in catalog order; ``None`` or an empty list means all of them. Unknown ids raise ``KeyError``."""
        if not ids:
            return list(self.controls)
        wanted = set(ids)
        unknown = wanted - {c.id for c in self.controls}
        if unknown:
            raise KeyError(f"unknown control ids: {sorted(unknown)}")
        return [c for c in self.controls if c.id in wanted]

    def counts_by_safeguard(self) -> dict[str, int]:
        return dict(Counter(c.safeguard for c in self.controls))


def _read(name: str) -> Any:
    text = resources.files(__package__).joinpath("data", name).read_text(encoding="utf-8")
    return yaml.safe_load(text)


@lru_cache(maxsize=1)
def load_catalog() -> Catalog:
    meta = CatalogMeta(**_read("meta.yaml"))
    controls: list[Control] = []
    for name in DATA_FILES:
        controls.extend(Control(**item) for item in _read(name))
    return Catalog(meta=meta, controls=controls)
