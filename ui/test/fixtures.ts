import type { ControlInfo, Finding, FindingStatus, Safeguard } from "../src/types";

export function control(id: string, safeguard: Safeguard, extra: Partial<ControlInfo> = {}): ControlInfo {
  return {
    id,
    citation: `45 CFR 164.3${id.length}`,
    title: id.replace(/-/g, " ").replace(/^./, (c) => c.toUpperCase()),
    safeguard,
    standard: "Security management process",
    requirement: "required",
    expectation: "The policy requires something.",
    elements: ["Requires one thing.", "Requires another."],
    ...extra,
  };
}

export function finding(c: ControlInfo, status: FindingStatus, extra: Partial<Finding> = {}): Finding {
  return {
    status,
    rationale: `Rationale for ${c.title}.`,
    evidence: [],
    missing_elements: [],
    confidence: 0.8,
    flags: [],
    retrieved_chunk_ids: [],
    model: "test",
    from_cache: false,
    control: {
      id: c.id,
      citation: c.citation,
      title: c.title,
      safeguard: c.safeguard,
      standard: c.standard,
      requirement: c.requirement,
    },
    needs_review: false,
    ...extra,
  };
}

export const CONTROLS: ControlInfo[] = [
  control("risk-analysis", "administrative"),
  control("sanction-policy", "administrative", { requirement: "required" }),
  control("security-reminders", "administrative", { requirement: "addressable", standard: "Awareness and training" }),
  control("facility-security-plan", "physical", { requirement: "addressable" }),
  control("automatic-logoff", "technical", { requirement: "addressable" }),
  control("transmission-encryption", "technical", { requirement: "addressable" }),
  control("business-associate-contract-terms", "organizational"),
  control("policies-and-procedures", "documentation"),
];
