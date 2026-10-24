import assert from "node:assert/strict";
import { test } from "node:test";
import {
  NO_FILTER,
  applyFilter,
  buildRows,
  groupRows,
  isFiltered,
  locateQuote,
  locationLabel,
  statusOf,
  tally,
} from "../src/findings";
import { CONTROLS, control, finding } from "./fixtures";

const ids = CONTROLS.map((c) => c.id);

function sample() {
  const [risk, sanction, reminders, facility, logoff, transmission, associate] = CONTROLS;
  assert.ok(risk && sanction && reminders && facility && logoff && transmission && associate);
  const findings = [
    finding(risk, "gap", { needs_review: true, flags: ["injection_suspected"] }),
    finding(sanction, "met", { evidence: [{ chunk_id: "c1", quote: "Violations lead to sanctions.", page: 2, section: "Sanctions" }] }),
    finding(reminders, "partial", { missing_elements: ["Says how often reminders go out."] }),
    finding(facility, "gap"),
    finding(logoff, "met"),
    finding(transmission, "error"),
  ];
  return buildRows(ids, CONTROLS, findings);
}

test("rows follow the review's order and show pending controls until they have a finding", () => {
  const rows = sample();
  assert.deepEqual(rows.map((r) => r.control.id), ids);
  assert.deepEqual(rows.map(statusOf), ["gap", "met", "partial", "gap", "met", "error", "pending", "pending"]);
});

test("once a review has stopped, a control without a finding is not assessed rather than waiting", () => {
  const [risk, sanction] = CONTROLS;
  assert.ok(risk && sanction);
  const findings = [finding(risk, "gap")];
  const running = buildRows([risk.id, sanction.id], CONTROLS, findings, false);
  const stopped = buildRows([risk.id, sanction.id], CONTROLS, findings, true);
  assert.deepEqual(running.map(statusOf), ["gap", "pending"]);
  assert.deepEqual(stopped.map(statusOf), ["gap", "error"]);
  assert.equal(tally(stopped).error, 1);
  assert.equal(tally(stopped).pending, 0);
  assert.deepEqual(applyFilter(stopped, { ...NO_FILTER, status: "error" }).map((r) => r.control.id), [sanction.id]);
});

test("a finding whose control the catalog no longer has still gets a row", () => {
  const orphan = control("retired-control", "technical", { title: "Retired control" });
  const rows = buildRows(["retired-control"], [], [finding(orphan, "gap")]);
  assert.equal(rows[0]?.control.title, "Retired control");
  assert.equal(rows[0]?.control.expectation, "");
  assert.equal(buildRows(["unknown"], [], [])[0]?.control.title, "unknown");
});

test("filters by status, by what needs review, by safeguard and by requirement", () => {
  const rows = sample();
  const only = (patch: Partial<typeof NO_FILTER>) => applyFilter(rows, { ...NO_FILTER, ...patch }).map((r) => r.control.id);
  assert.equal(only({}).length, 8);
  assert.deepEqual(only({ status: "gap" }), ["risk-analysis", "facility-security-plan"]);
  assert.deepEqual(only({ status: "met" }), ["sanction-policy", "automatic-logoff"]);
  assert.deepEqual(only({ status: "error" }), ["transmission-encryption"]);
  assert.deepEqual(only({ status: "review" }), ["risk-analysis"]);
  assert.deepEqual(only({ safeguard: "technical" }), ["automatic-logoff", "transmission-encryption"]);
  assert.deepEqual(only({ safeguard: "technical", status: "met" }), ["automatic-logoff"]);
  assert.equal(only({ requiredOnly: true }).includes("security-reminders"), false);
  assert.equal(only({ requiredOnly: true }).includes("risk-analysis"), true);
});

test("search looks at the title, the citation, the rationale, the quotes and the missing elements", () => {
  const rows = sample();
  const find = (query: string) => applyFilter(rows, { ...NO_FILTER, query }).map((r) => r.control.id);
  assert.deepEqual(find("sanction"), ["sanction-policy"]);
  assert.deepEqual(find("  SANCTIONS  "), ["sanction-policy"]); // the quote and the title both match; case and spaces do not matter
  assert.deepEqual(find("how often reminders"), ["security-reminders"]);
  assert.deepEqual(find("awareness and training"), ["security-reminders"]);
  assert.deepEqual(find("no such words anywhere"), []);
  assert.equal(find("   ").length, 8);
});

test("groups follow the Security Rule's order and leave out empty groups", () => {
  const groups = groupRows(sample());
  assert.deepEqual(groups.map((g) => g.safeguard), ["administrative", "physical", "technical", "organizational", "documentation"]);
  assert.deepEqual(groups.map((g) => g.rows.length), [3, 1, 2, 1, 1]);
  assert.equal(groups[0]?.label, "Administrative safeguards");
  const filtered = groupRows(applyFilter(sample(), { ...NO_FILTER, status: "gap" }));
  assert.deepEqual(filtered.map((g) => g.safeguard), ["administrative", "physical"]);
  const odd = groupRows(buildRows(["x"], [], []));
  assert.deepEqual(odd.map((g) => g.label), ["Other controls"]);
});

test("tally counts what is there and what is still waiting", () => {
  assert.deepEqual(tally(sample()), { total: 8, met: 2, partial: 1, gap: 2, error: 1, pending: 2, review: 1 });
  assert.equal(isFiltered(NO_FILTER), false);
  assert.equal(isFiltered({ ...NO_FILTER, query: " x " }), true);
  assert.equal(isFiltered({ ...NO_FILTER, query: "   " }), false);
  assert.equal(isFiltered({ ...NO_FILTER, requiredOnly: true }), true);
});

test("a quote is found in the text around it, even when spacing differs", () => {
  const text = "First paragraph.\nUsers must log off\n  when they leave a workstation unattended. Last bit.";
  const exact = locateQuote("A. Users log off. B.", "Users log off.");
  assert.deepEqual(exact, { before: "A. ", match: "Users log off.", after: " B." });
  const loose = locateQuote(text, "Users must log off when they leave a workstation unattended.");
  assert.equal(loose?.match, "Users must log off\n  when they leave a workstation unattended.");
  assert.equal(loose?.before, "First paragraph.\n");
  assert.equal(loose?.after, " Last bit.");
  assert.equal(locateQuote(text, "Passwords expire."), null);
  assert.equal(locateQuote(text, "   "), null);
  assert.equal(locateQuote("cost (USD) is $5.00?", "cost (USD) is $5.00?")?.match, "cost (USD) is $5.00?"); // no regular-expression surprises
  assert.equal(locateQuote("cost  (USD)   is\n$5.00?", "cost (USD) is $5.00?")?.match, "cost  (USD)   is\n$5.00?");
});

test("location labels", () => {
  assert.equal(locationLabel(4, "Risk analysis"), "page 4, Risk analysis");
  assert.equal(locationLabel(null, "Risk analysis"), "Risk analysis");
  assert.equal(locationLabel(7, ""), "page 7");
  assert.equal(locationLabel(null, ""), "");
});
