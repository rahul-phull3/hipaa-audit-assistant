"""Synthetic policies with known answers, and a harness that scores a backend against them."""

from hipaa_audit.evaluation.report import build_report, render_json, render_markdown
from hipaa_audit.evaluation.runner import EvaluationResult, evaluate
from hipaa_audit.evaluation.synthetic import DIFFICULTIES, Mix, SyntheticPolicy, generate_policy

__all__ = [
    "DIFFICULTIES",
    "EvaluationResult",
    "Mix",
    "SyntheticPolicy",
    "build_report",
    "evaluate",
    "generate_policy",
    "render_json",
    "render_markdown",
]
