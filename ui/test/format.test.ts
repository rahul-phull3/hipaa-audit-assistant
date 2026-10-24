import assert from "node:assert/strict";
import { test } from "node:test";
import { describeBackend, formatBytes, percent, plural, relativeTime, shortHash } from "../src/format";

const NOW = Date.parse("2026-10-24T12:00:00Z");
const ago = (seconds: number) => new Date(NOW - seconds * 1000).toISOString();

test("relative times", () => {
  assert.equal(relativeTime(ago(5), NOW), "just now");
  assert.equal(relativeTime(ago(44), NOW), "just now");
  assert.equal(relativeTime(ago(60), NOW), "1 minute ago");
  assert.equal(relativeTime(ago(5 * 60), NOW), "5 minutes ago");
  assert.equal(relativeTime(ago(3 * 3600), NOW), "3 hours ago");
  assert.equal(relativeTime(ago(3580), NOW), "1 hour ago");
  assert.equal(relativeTime(ago(2 * 86400), NOW), "2 days ago");
  assert.match(relativeTime(ago(90 * 86400), NOW), /2026/);
  assert.equal(relativeTime("not a date", NOW), "");
  assert.equal(relativeTime(new Date(NOW + 60_000).toISOString(), NOW), "just now"); // a clock a little ahead
});

test("sizes, percentages and plurals", () => {
  assert.equal(formatBytes(512), "512 B");
  assert.equal(formatBytes(2048), "2.0 KB");
  assert.equal(formatBytes(200 * 1024), "200 KB");
  assert.equal(formatBytes(5 * 1024 * 1024), "5.0 MB");
  assert.equal(percent(0.846), "85%");
  assert.equal(percent(2), "100%");
  assert.equal(percent(-1), "0%");
  assert.equal(plural(1, "control"), "1 control");
  assert.equal(plural(48, "control"), "48 controls");
  assert.equal(plural(2, "entry", "entries"), "2 entries");
});

test("the offline reviewer is never called a model", () => {
  assert.deepEqual(describeBackend("heuristic:keywords"), { label: "Offline keyword matching", isModel: false });
  assert.deepEqual(describeBackend("claude-sonnet-5-5"), { label: "claude-sonnet-5-5", isModel: true });
  assert.equal(shortHash("0123456789abcdef"), "0123456789ab");
});
