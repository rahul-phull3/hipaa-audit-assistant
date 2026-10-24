import type { ControlInfo, Finding, FindingStatus, Safeguard } from "./types";

export const SAFEGUARD_ORDER: Safeguard[] = ["administrative", "physical", "technical", "organizational", "documentation"];

export const SAFEGUARD_LABELS: Record<Safeguard, string> = {
  administrative: "Administrative safeguards",
  physical: "Physical safeguards",
  technical: "Technical safeguards",
  organizational: "Business associates",
  documentation: "Policies and documentation",
};

export const SAFEGUARD_SHORT: Record<Safeguard, string> = {
  administrative: "Administrative",
  physical: "Physical",
  technical: "Technical",
  organizational: "Business associates",
  documentation: "Documentation",
};

export type RowStatus = FindingStatus | "pending";

export const STATUS_LABELS: Record<RowStatus, string> = {
  met: "Met",
  partial: "Partial",
  gap: "Gap",
  error: "Not assessed",
  pending: "Waiting",
};

export const STATUS_HELP: Record<Exclude<RowStatus, "pending">, string> = {
  met: "The document addresses every element the control expects.",
  partial: "The document addresses some of the elements.",
  gap: "The document does not address the control, or only mentions it in passing.",
  error: "The reviewer could not assess this control. Run the review again to retry it.",
};

/** One control in a review, with its finding once there is one. */
export interface Row {
  control: ControlInfo;
  finding: Finding | null;
  /** The review has stopped. A control with no finding by then will not get one, so it counts as not assessed, not waiting. */
  settled?: boolean;
}

export type StatusFilter = "all" | "met" | "partial" | "gap" | "error" | "review";

export interface Filter {
  status: StatusFilter;
  safeguard: "all" | Safeguard;
  requiredOnly: boolean;
  query: string;
}

export const NO_FILTER: Filter = { status: "all", safeguard: "all", requiredOnly: false, query: "" };

export function isFiltered(filter: Filter): boolean {
  return filter.status !== "all" || filter.safeguard !== "all" || filter.requiredOnly || filter.query.trim() !== "";
}

export function statusOf(row: Row): RowStatus {
  if (row.finding) return row.finding.status;
  return row.settled ? "error" : "pending";
}

/**
 * The controls of a review in the order the review lists them, each with its finding when there is one. Once the review has
 * stopped (`settled`), a control with no finding is not assessed rather than waiting, as after a cancel or a failure.
 */
export function buildRows(controlIds: string[], controls: ControlInfo[], findings: Finding[], settled = false): Row[] {
  const byControl = new Map(controls.map((c) => [c.id, c]));
  const byFinding = new Map(findings.map((f) => [f.control.id, f]));
  const rows: Row[] = [];
  for (const id of controlIds) {
    const control = byControl.get(id) ?? unknownControl(id, byFinding.get(id));
    rows.push({ control, finding: byFinding.get(id) ?? null, settled });
  }
  return rows;
}

// A finding can outlive its catalog entry (the catalog edition changed); show what the finding itself carries.
function unknownControl(id: string, finding: Finding | undefined): ControlInfo {
  return {
    id,
    citation: finding?.control.citation ?? "",
    title: finding?.control.title ?? id,
    safeguard: finding?.control.safeguard ?? "",
    standard: finding?.control.standard ?? "",
    requirement: finding?.control.requirement ?? "",
    expectation: "",
    elements: [],
  };
}

function matchesQuery(row: Row, query: string): boolean {
  const needle = query.trim().toLowerCase();
  if (!needle) return true;
  const { control, finding } = row;
  const haystack = [
    control.title,
    control.citation,
    control.standard,
    finding?.rationale ?? "",
    ...(finding?.evidence.map((e) => e.quote) ?? []),
    ...(finding?.missing_elements ?? []),
  ];
  return haystack.some((text) => text.toLowerCase().includes(needle));
}

export function matchesFilter(row: Row, filter: Filter): boolean {
  const status = statusOf(row);
  if (filter.status === "review") {
    if (!row.finding?.needs_review) return false;
  } else if (filter.status !== "all" && status !== filter.status) {
    return false;
  }
  if (filter.safeguard !== "all" && row.control.safeguard !== filter.safeguard) return false;
  if (filter.requiredOnly && row.control.requirement !== "required") return false;
  return matchesQuery(row, filter.query);
}

export function applyFilter(rows: Row[], filter: Filter): Row[] {
  return rows.filter((row) => matchesFilter(row, filter));
}

export interface Group {
  safeguard: Safeguard | "";
  label: string;
  rows: Row[];
}

/** Rows grouped by safeguard in the order the Security Rule presents them; controls the catalog does not know go last. */
export function groupRows(rows: Row[]): Group[] {
  const groups: Group[] = [];
  for (const safeguard of SAFEGUARD_ORDER) {
    const members = rows.filter((r) => r.control.safeguard === safeguard);
    if (members.length > 0) groups.push({ safeguard, label: SAFEGUARD_LABELS[safeguard], rows: members });
  }
  const others = rows.filter((r) => !SAFEGUARD_ORDER.includes(r.control.safeguard as Safeguard));
  if (others.length > 0) groups.push({ safeguard: "", label: "Other controls", rows: others });
  return groups;
}

export interface Tally {
  total: number;
  met: number;
  partial: number;
  gap: number;
  error: number;
  pending: number;
  review: number;
}

export function tally(rows: Row[]): Tally {
  const t: Tally = { total: rows.length, met: 0, partial: 0, gap: 0, error: 0, pending: 0, review: 0 };
  for (const row of rows) {
    t[statusOf(row)] += 1;
    if (row.finding?.needs_review) t.review += 1;
  }
  return t;
}

export interface Split {
  before: string;
  match: string;
  after: string;
}

const COLLAPSE = /\s+/g;

/**
 * Where a quoted passage sits in the text around it. The server checks quotes after normalising spaces, quotes and case, so
 * the match here is tolerant in the same way: spaces in the quote match any run of whitespace.
 */
export function locateQuote(text: string, quote: string): Split | null {
  const needle = quote.trim().replace(COLLAPSE, " ");
  if (!needle) return null;
  const exact = text.indexOf(needle);
  if (exact >= 0) return split(text, exact, exact + needle.length);
  const pattern = needle
    .split(" ")
    .map((word) => word.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .join("\\s+");
  const match = new RegExp(pattern, "i").exec(text);
  return match ? split(text, match.index, match.index + match[0].length) : null;
}

function split(text: string, start: number, end: number): Split {
  return { before: text.slice(0, start), match: text.slice(start, end), after: text.slice(end) };
}

/** "page 4, Risk analysis": where a quote came from, in words. */
export function locationLabel(page: number | null, section: string): string {
  const parts: string[] = [];
  if (page !== null) parts.push(`page ${page}`);
  if (section) parts.push(section);
  return parts.join(", ");
}
