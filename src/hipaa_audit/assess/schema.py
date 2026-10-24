"""The structured answer the model must give: one forced tool call per control."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator

from hipaa_audit.models import Status

TOOL_NAME = "record_assessment"

TOOL_SPEC: dict[str, Any] = {
    "name": TOOL_NAME,
    "description": "Record the assessment of one HIPAA Security Rule control against the provided policy excerpts.",
    "input_schema": {
        "type": "object",
        "properties": {
            "status": {
                "type": "string",
                "enum": ["met", "partial", "gap"],
                "description": "met: every expected element is addressed. partial: some are. gap: none, or only a passing mention.",
            },
            "rationale": {"type": "string", "description": "Under 80 words, plain language."},
            "evidence": {
                "type": "array",
                "description": "Verbatim quotes from the excerpts that support the status. Empty for a gap.",
                "items": {
                    "type": "object",
                    "properties": {
                        "excerpt_id": {"type": "string"},
                        "quote": {"type": "string", "description": "Copied character for character from the excerpt."},
                    },
                    "required": ["excerpt_id", "quote"],
                },
            },
            "missing_elements": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Expected elements the excerpts do not show. Must be empty when status is met.",
            },
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        },
        "required": ["status", "rationale", "evidence", "missing_elements", "confidence"],
    },
}


class RawEvidence(BaseModel):
    excerpt_id: str
    quote: str


class RawAssessment(BaseModel):
    """What the backend returns, before the server checks the quotes and applies the downgrade rules."""

    status: Status
    rationale: str = ""
    evidence: list[RawEvidence] = Field(default_factory=list)
    missing_elements: list[str] = Field(default_factory=list)
    confidence: float = 0.5

    @field_validator("confidence", mode="before")
    @classmethod
    def _clamp(cls, value: Any) -> float:
        try:
            return min(1.0, max(0.0, float(value)))
        except (TypeError, ValueError):
            return 0.5
