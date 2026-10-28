// Drives the interface in a real Chromium against a real server (offline keyword reviewer, temporary database).
//
//   npm run e2e                       builds dist/, starts the server, runs every scenario, exits 1 if any failed
//   E2E_OUT=/some/dir npm run e2e     where the screenshots go (default: ui/e2e/out, which git ignores)
//
// Every scenario also fails on a console error or warning, an uncaught exception, a request that leaves the server's origin, and
// any content security policy violation, so a page that "works" but breaks the policy is caught here.
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync } from "node:fs";
import { createServer } from "node:net";
import os from "node:os";
import path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const here = path.dirname(fileURLToPath(import.meta.url));
const ui = path.resolve(here, "..");
const repo = path.resolve(ui, "..");
const samplePolicy = path.join(repo, "examples", "sample_policy.md");
const out = process.env.E2E_OUT ? path.resolve(process.env.E2E_OUT) : path.join(here, "out");
mkdirSync(out, { recursive: true });

// -- the server --------------------------------------------------------------------------------------------------------------

function freePort() {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.on("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

async function startServer(extraEnv = {}) {
  const dir = mkdtempSync(path.join(os.tmpdir(), "hipaa-e2e-"));
  const port = await freePort();
  const env = { ...process.env, PYTHONPATH: path.join(repo, "src"), ...extraEnv };
  delete env.ANTHROPIC_API_KEY;
  for (const name of Object.keys(env)) {
    if (name.startsWith("HIPAA_AUDIT_") && !(name in extraEnv)) delete env[name];
  }
  const child = spawn(
    "python3",
    ["-m", "hipaa_audit", "serve", "--port", String(port), "--backend", "heuristic", "--db", path.join(dir, "e2e.db"), "--log-level", "warning"],
    { cwd: dir, env, stdio: ["ignore", "pipe", "pipe"] },
  );
  let log = "";
  child.stdout.on("data", (chunk) => (log += chunk));
  child.stderr.on("data", (chunk) => (log += chunk));
  const base = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`the server exited early:\n${log}`);
    try {
      if ((await fetch(`${base}/api/health`)).ok) {
        return {
          base,
          log: () => log,
          async stop() {
            child.kill("SIGTERM");
            await Promise.race([new Promise((resolve) => child.once("exit", resolve)), sleep(5000)]);
            if (child.exitCode === null) child.kill("SIGKILL");
          },
        };
      }
    } catch {
      await sleep(150);
    }
  }
  child.kill("SIGKILL");
  throw new Error(`the server did not become ready:\n${log}`);
}

const getJson = async (base, url, headers = {}) => {
  const response = await fetch(base + url, { headers });
  assert.equal(response.status, 200, `${url} answered ${response.status}`);
  return response.json();
};

// -- pages -------------------------------------------------------------------------------------------------------------------

async function openPage(browser, base, { width = 1280, height = 900, colorScheme = "light", mobile = false, allow = [] } = {}) {
  const context = await browser.newContext({
    viewport: { width, height },
    colorScheme,
    deviceScaleFactor: mobile ? 2 : 1,
    isMobile: mobile,
    hasTouch: mobile,
    acceptDownloads: true,
  });
  const page = await context.newPage();
  const problems = [];
  const origin = new URL(base).origin;
  const expected = (text) => allow.some((pattern) => pattern.test(text));
  page.on("console", (message) => {
    if ((message.type() === "error" || message.type() === "warning") && !expected(message.text())) {
      problems.push(`console ${message.type()}: ${message.text()}`);
    }
  });
  page.on("pageerror", (error) => problems.push(`uncaught exception: ${error.message}`));
  page.on("requestfailed", (request) => {
    const reason = request.failure()?.errorText ?? "";
    if (!reason.includes("ERR_ABORTED")) problems.push(`request failed: ${request.url()} (${reason})`);
  });
  page.on("request", (request) => {
    const url = request.url();
    if (!/^(data|blob):/.test(url) && new URL(url).origin !== origin) problems.push(`request left the server: ${url}`);
  });
  await page.addInitScript(() => {
    window.__violations = [];
    document.addEventListener("securitypolicyviolation", (event) => {
      window.__violations.push(`${event.violatedDirective}: ${event.blockedURI || "inline"}`);
    });
  });
  page.setDefaultTimeout(15_000);
  return { context, page, problems };
}

async function finish({ context, page, problems }) {
  const violations = await page.evaluate(() => window.__violations ?? []).catch(() => []);
  await context.close();
  assert.deepEqual([...violations.map((v) => `content security policy: ${v}`), ...problems], [], "the page reported problems");
}

const shot = (page, name, options = {}) => page.screenshot({ path: path.join(out, name), ...options });

async function waitForFinished(page) {
  await page.getByRole("button", { name: "Download report (Markdown)" }).waitFor({ timeout: 45_000 });
}

/** Spot checks every screen should pass: one h1, no skipped heading levels, every control named, every id unique. */
async function checkBasics(page) {
  const found = await page.evaluate(() => {
    const headings = [...document.querySelectorAll("h1,h2,h3,h4")].map((h) => Number(h.tagName[1]));
    const skipped = headings.some((level, i) => i > 0 && level - headings[i - 1] > 1);
    const nameOf = (el) => {
      const labelled = el.getAttribute("aria-labelledby");
      if (labelled) return labelled.split(" ").map((id) => document.getElementById(id)?.textContent ?? "").join(" ").trim();
      return (
        el.getAttribute("aria-label") || [...(el.labels ?? [])].map((l) => l.textContent).join(" ").trim() || el.textContent.trim() || el.getAttribute("title") || ""
      );
    };
    const unnamed = [...document.querySelectorAll("button, a[href], input:not([type=hidden]), select")]
      .filter((el) => nameOf(el) === "")
      .map((el) => el.outerHTML.slice(0, 80));
    const ids = [...document.querySelectorAll("[id]")].map((el) => el.id);
    const duplicates = ids.filter((id, i) => ids.indexOf(id) !== i);
    return {
      h1: headings.filter((level) => level === 1).length,
      skipped,
      unnamed,
      duplicates,
      lang: document.documentElement.lang,
      landmarks: ["main", "header", "footer"].filter((tag) => document.querySelector(tag)),
      overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    };
  });
  assert.equal(found.h1, 1, "exactly one h1");
  assert.equal(found.skipped, false, "heading levels are not skipped");
  assert.deepEqual(found.unnamed, [], "every button, link and field has a name");
  assert.deepEqual(found.duplicates, [], "ids are unique");
  assert.equal(found.lang, "en");
  assert.deepEqual(found.landmarks, ["main", "header", "footer"]);
  assert.ok(found.overflow <= 0, `the page scrolls sideways by ${found.overflow}px`);
}

// -- scenarios ---------------------------------------------------------------------------------------------------------------

const results = [];
async function scenario(name, run) {
  const started = Date.now();
  try {
    await run();
    results.push({ name, ok: true });
    console.log(`ok    ${name} (${((Date.now() - started) / 1000).toFixed(1)} s)`);
  } catch (error) {
    results.push({ name, ok: false });
    console.log(`FAIL  ${name}\n${String(error?.stack ?? error).split("\n").slice(0, 14).map((line) => `        ${line}`).join("\n")}`);
  }
}

const state = { id: "", catalogSize: 0, summary: null, findings: [] };

async function main() {
  console.log("building the interface");
  execFileSync(process.execPath, [path.join(ui, "build.mjs")], { cwd: ui, stdio: "pipe" });

  const server = await startServer();
  const keyed = { server: null };
  const browser = await chromium.launch();
  const { base } = server;
  try {
    await scenario("home page loads, with the strict content security policy and security headers", async () => {
      const h = await openPage(browser, base);
      const response = await h.page.goto(`${base}/`);
      const headers = response.headers();
      assert.match(headers["content-security-policy"], /default-src 'self'/);
      assert.match(headers["content-security-policy"], /script-src 'self'/);
      assert.equal(headers["x-frame-options"], "DENY");
      assert.equal(headers["x-content-type-options"], "nosniff");
      await h.page.getByRole("heading", { level: 1, name: /Check a security policy/ }).waitFor();
      assert.equal(await h.page.title(), "HIPAA policy review");
      await h.page.getByText("Offline keyword matching is on").waitFor();
      await h.page.getByText("No reviews yet").waitFor();
      assert.equal(await h.page.getByRole("button", { name: "Start review" }).isDisabled(), true, "start is disabled until a file is chosen");
      assert.match(await h.page.locator(".privacy").innerText(), /Nothing leaves this server/);
      await checkBasics(h.page);
      await shot(h.page, "01-home-light.png", { fullPage: true });
      await finish(h);
    });

    await scenario("keyboard: the first tab stop is the skip link, and it moves focus to the content", async () => {
      const h = await openPage(browser, base);
      await h.page.goto(`${base}/`);
      await h.page.getByRole("heading", { level: 1 }).waitFor();
      await h.page.keyboard.press("Tab");
      assert.equal(await h.page.evaluate(() => document.activeElement?.textContent), "Skip to the content");
      await h.page.keyboard.press("Enter");
      assert.equal(await h.page.evaluate(() => document.activeElement?.id), "main");
      await finish(h);
    });

    await scenario("upload a policy: rejects a wrong file type, then starts a review and shows the finished result", async () => {
      const h = await openPage(browser, base);
      await h.page.goto(`${base}/`);
      await h.page.getByRole("heading", { level: 1 }).waitFor();
      await h.page.locator('input[type="file"]').setInputFiles({ name: "notes.exe", mimeType: "application/octet-stream", buffer: Buffer.from("MZ") });
      await h.page.getByText("Choose a PDF, DOCX, TXT or Markdown file.").waitFor();
      assert.equal(await h.page.getByRole("button", { name: "Start review" }).isDisabled(), true);

      await h.page.locator('input[type="file"]').setInputFiles(samplePolicy);
      await h.page.locator(".drop-name").filter({ hasText: "sample_policy.md" }).waitFor();
      await shot(h.page, "02-home-file-chosen.png");
      await h.page.getByRole("button", { name: "Start review" }).click();
      await h.page.waitForURL(/#\/audits\/[0-9a-f]{16}$/);
      state.id = h.page.url().split("/").pop();
      await h.page.getByRole("heading", { level: 1, name: "sample_policy.md" }).waitFor();
      assert.equal(await h.page.evaluate(() => document.activeElement?.tagName), "H1", "focus moves to the review's heading");
      await waitForFinished(h.page);

      const [audit, catalog, findings] = await Promise.all([
        getJson(base, `/api/audits/${state.id}`),
        getJson(base, "/api/controls"),
        getJson(base, `/api/audits/${state.id}/findings`),
      ]);
      state.summary = audit.summary;
      state.catalogSize = catalog.controls.length;
      state.findings = findings.findings;
      assert.equal(audit.status, "completed");

      await h.page.waitForTimeout(500);
      await shot(h.page, "03-review-top.png");
      await h.page.waitForTimeout(2500);
      await shot(h.page, "04-review-full.png", { fullPage: true });
      await checkBasics(h.page);
      await finish(h);
    });

    await scenario("keyboard: on a review page the skip link moves focus to the content and leaves the address alone", async () => {
      const h = await openPage(browser, base);
      await h.page.goto(`${base}/#/audits/${state.id}`);
      await h.page.getByRole("heading", { level: 1, name: "sample_policy.md" }).waitFor();
      const before = h.page.url();
      await h.page.keyboard.press("Tab");
      assert.equal(await h.page.evaluate(() => document.activeElement?.textContent), "Skip to the content");
      await h.page.keyboard.press("Enter");
      assert.equal(await h.page.evaluate(() => document.activeElement?.id), "main");
      assert.equal(h.page.url(), before, "using the skip link must not change which page this is");
      await h.page.getByRole("heading", { level: 1, name: "sample_policy.md" }).waitFor();
      await finish(h);
    });

    await scenario("the strip and the counts agree with the server, and the arrow keys move along the strip", async () => {
      const h = await openPage(browser, base);
      await h.page.goto(`${base}/#/audits/${state.id}`);
      await waitForFinished(h.page);
      const cells = h.page.locator(".strip .cell");
      assert.equal(await cells.count(), state.catalogSize);
      const marks = await cells.evaluateAll((els) => els.map((el) => el.dataset.status));
      const tally = (status) => marks.filter((m) => m === status).length;
      for (const status of ["met", "partial", "gap", "error"]) {
        assert.equal(tally(status), state.summary[status], `${status} marks on the strip`);
      }
      assert.equal(tally("pending"), 0, "no control is left waiting");
      const shown = await h.page.locator(".counts li").evaluateAll((items) =>
        Object.fromEntries(items.map((li) => [li.querySelector("span").textContent, Number(li.querySelector("strong").textContent)])),
      );
      assert.equal(shown.Gap, state.summary.gap);
      assert.equal(shown.Partial, state.summary.partial);
      assert.equal(shown.Met, state.summary.met);

      const tabStops = await cells.evaluateAll((els) => els.filter((el) => el.tabIndex === 0).length);
      assert.equal(tabStops, 1, "the strip is a single tab stop");
      await cells.first().focus();
      await h.page.keyboard.press("ArrowRight");
      assert.equal(await h.page.evaluate(() => document.activeElement?.getAttribute("aria-label")), await cells.nth(1).getAttribute("aria-label"));
      await h.page.keyboard.press("End");
      assert.equal(await h.page.evaluate(() => document.activeElement?.getAttribute("aria-label")), await cells.last().getAttribute("aria-label"));
      await h.page.keyboard.press("Home");
      assert.equal(await h.page.evaluate(() => document.activeElement?.getAttribute("aria-label")), await cells.first().getAttribute("aria-label"));
      await finish(h);
    });

    await scenario("filters narrow the findings and can be cleared", async () => {
      const h = await openPage(browser, base);
      await h.page.goto(`${base}/#/audits/${state.id}`);
      await waitForFinished(h.page);
      const rows = h.page.locator(".finding");
      assert.equal(await rows.count(), state.catalogSize);

      await h.page.getByRole("button", { name: /^Gap\s*\d+$/ }).click();
      assert.equal(await rows.count(), state.summary.gap);
      assert.deepEqual(await rows.evaluateAll((els) => [...new Set(els.map((el) => el.dataset.status))]), ["gap"]);
      await h.page.getByText(`Showing ${state.summary.gap} of ${state.catalogSize} controls`).waitFor();

      await h.page.getByRole("searchbox").fill("zzzz-no-such-text");
      await h.page.getByText("No findings match these filters.").waitFor();
      await h.page.getByRole("button", { name: "Clear filters" }).click();
      assert.equal(await rows.count(), state.catalogSize);
      assert.equal(await h.page.getByRole("button", { name: "Clear filters" }).count(), 0);

      await h.page.getByLabel("Required controls only").check();
      const required = await rows.count();
      assert.ok(required > 0 && required < state.catalogSize, `${required} required controls`);
      await h.page.getByRole("button", { name: "Clear filters" }).click();
      await finish(h);
    });

    await scenario("a mark on the strip opens its finding, moves focus there, and the quote can be shown in context", async () => {
      const h = await openPage(browser, base);
      await h.page.goto(`${base}/#/audits/${state.id}`);
      await waitForFinished(h.page);
      await h.page.locator('.strip .cell[data-status="partial"]').first().click();
      const open = h.page.locator('.finding[data-open="true"]');
      await open.waitFor();
      assert.equal(await open.count(), 1);
      assert.equal(await h.page.evaluate(() => document.activeElement?.className), "finding-toggle");
      assert.equal(await open.locator(".finding-toggle").getAttribute("aria-expanded"), "true");
      await open.locator("blockquote").first().waitFor();

      await open.getByRole("button", { name: "Show surrounding text" }).first().click();
      await open.locator(".context mark").first().waitFor();
      assert.ok((await open.locator(".context mark").first().innerText()).trim().length > 0, "the quoted words are highlighted");
      await open.scrollIntoViewIfNeeded();
      await shot(h.page, "05-finding-with-context.png");
      await open.getByRole("button", { name: "Hide surrounding text" }).first().click();
      assert.equal(await open.locator(".context").count(), 0);

      await open.locator(".finding-toggle").click();
      assert.equal(await h.page.locator('.finding[data-open="true"]').count(), 0, "the toggle closes it again");
      await finish(h);
    });

    await scenario("a gap that has only nearby passages says they do not count as support", async () => {
      const withEvidence = state.findings.find((f) => f.status === "gap" && f.evidence.length > 0);
      if (!withEvidence) throw new Error("the sample review has no gap with passages to check");
      const h = await openPage(browser, base);
      await h.page.goto(`${base}/#/audits/${state.id}`);
      await waitForFinished(h.page);
      await h.page.locator(`.strip .cell[aria-label="${withEvidence.control.title}: gap"]`).click();
      const open = h.page.locator('.finding[data-open="true"]');
      await open.getByText("Closest passages in the document. These do not count as support.").waitFor();
      await open.getByText(/The reviewer was shown \d+ passages? of the document for this control\. If the document covers it somewhere else, that part was not seen\./).waitFor();
      await open.scrollIntoViewIfNeeded();
      await shot(h.page, "06-gap-with-closest-passages.png");
      await finish(h);
    });

    await scenario("both reports download, and the JSON one is the documented schema", async () => {
      const h = await openPage(browser, base);
      await h.page.goto(`${base}/#/audits/${state.id}`);
      await waitForFinished(h.page);
      const [markdown] = await Promise.all([h.page.waitForEvent("download"), h.page.getByRole("button", { name: "Download report (Markdown)" }).click()]);
      assert.match(markdown.suggestedFilename(), /\.md$/);
      const mdText = readFileSync(await markdown.path(), "utf8");
      assert.match(mdText, /sample\\?_policy\.md/, "the file name is in the report (Markdown escapes the underscore)");
      assert.match(mdText, /not legal advice|does not certify/i);
      const [json] = await Promise.all([h.page.waitForEvent("download"), h.page.getByRole("button", { name: "Download report (JSON)" }).click()]);
      assert.match(json.suggestedFilename(), /\.json$/);
      const parsed = JSON.parse(readFileSync(await json.path(), "utf8"));
      assert.equal(parsed.schema_version, 1);
      assert.equal(parsed.findings.length, state.catalogSize);
      assert.ok(parsed.findings.every((f) => Number.isInteger(f.passages_seen)), "every finding says how many passages the reviewer saw");
      await finish(h);
    });

    await scenario("a review that does not exist says so and offers the way back", async () => {
      const h = await openPage(browser, base, { allow: [/status of 404/] });
      await h.page.goto(`${base}/#/audits/0123456789abcdef`);
      await h.page.getByText("This review does not exist").waitFor();
      await h.page.getByRole("link", { name: "All reviews" }).click();
      await h.page.getByRole("heading", { level: 1, name: /Check a security policy/ }).waitFor();
      await finish(h);
    });

    await scenario("run again starts a second review, and the list on the home page shows both", async () => {
      const h = await openPage(browser, base);
      await h.page.goto(`${base}/#/audits/${state.id}`);
      await waitForFinished(h.page);
      await h.page.getByRole("button", { name: "Run again" }).click();
      await h.page.waitForFunction((first) => /#\/audits\/[0-9a-f]{16}$/.test(location.hash) && !location.hash.endsWith(first), state.id);
      await waitForFinished(h.page);
      await h.page.getByRole("link", { name: "All reviews" }).click();
      const table = h.page.locator("table.history");
      await table.waitFor();
      assert.equal(await table.locator("tbody tr").count(), 2);
      await table.locator("tbody tr").first().getByRole("link").click();
      await h.page.getByRole("heading", { level: 1, name: "sample_policy.md" }).waitFor();
      await finish(h);
    });

    await scenario("delete asks first, then removes the review", async () => {
      const h = await openPage(browser, base);
      await h.page.goto(`${base}/#/audits/${state.id}`);
      await waitForFinished(h.page);
      await h.page.getByRole("button", { name: "Delete review" }).click();
      await h.page.getByText("Delete this review and its text?").waitFor();
      await h.page.getByRole("button", { name: "Keep it" }).click();
      assert.equal(await h.page.getByText("Delete this review and its text?").count(), 0);
      await h.page.getByRole("button", { name: "Delete review" }).click();
      await h.page.getByRole("button", { name: "Delete", exact: true }).click();
      await h.page.getByRole("heading", { level: 1, name: /Check a security policy/ }).waitFor();
      await h.page.locator("table.history tbody tr").first().waitFor();
      assert.equal(await h.page.locator("table.history tbody tr").count(), 1);
      const gone = await fetch(`${base}/api/audits/${state.id}`);
      assert.equal(gone.status, 404);
      await finish(h);
    });

    // The remaining scenarios keep the review the previous one left behind.
    const [remaining] = (await getJson(base, "/api/audits")).audits;
    state.id = remaining.id;

    await scenario("dark colour scheme", async () => {
      const h = await openPage(browser, base, { colorScheme: "dark" });
      await h.page.goto(`${base}/`);
      await h.page.getByRole("heading", { level: 1 }).waitFor();
      await shot(h.page, "07-home-dark.png", { fullPage: true });
      await h.page.goto(`${base}/#/audits/${state.id}`);
      await waitForFinished(h.page);
      await h.page.waitForTimeout(2800);
      await h.page.locator('.strip .cell[data-status="partial"]').first().click();
      await h.page.locator('.finding[data-open="true"] blockquote').first().waitFor();
      await shot(h.page, "08-review-dark.png", { fullPage: true });
      await finish(h);
    });

    await scenario("a phone: nothing scrolls sideways, targets are large, and a finding reads well", async () => {
      const h = await openPage(browser, base, { width: 390, height: 844, mobile: true });
      await h.page.goto(`${base}/`);
      await h.page.getByRole("heading", { level: 1 }).waitFor();
      await checkBasics(h.page);
      await shot(h.page, "09-home-phone.png", { fullPage: true });
      const start = await h.page.getByRole("button", { name: "Start review" }).boundingBox();
      assert.ok(start && start.height >= 44, `the primary button is ${start?.height}px tall`);

      await h.page.goto(`${base}/#/audits/${state.id}`);
      await waitForFinished(h.page);
      await h.page.waitForTimeout(2800);
      await checkBasics(h.page);
      await shot(h.page, "10-review-phone.png", { fullPage: true });
      await h.page.locator('.strip .cell[data-status="partial"]').first().tap();
      await h.page.locator('.finding[data-open="true"] blockquote').first().waitFor();
      await checkBasics(h.page);
      await h.page.locator('.finding[data-open="true"]').scrollIntoViewIfNeeded();
      await shot(h.page, "11-finding-phone.png");
      await finish(h);
    });

    await scenario("every state a review can be in, shown from a real review's data", async () => {
      const audit = await getJson(base, `/api/audits/${state.id}`);
      const real = (await getJson(base, `/api/audits/${state.id}/findings`)).findings;
      const catalog = await getJson(base, "/api/controls");
      const flag = Object.keys(catalog.flag_labels)[0];
      const withEvidence = real.filter((f) => f.evidence.length > 0);
      const serve = async (page, auditBody, findingsBody) => {
        await page.route(`**/api/audits/${state.id}`, (route) => route.fulfill({ json: auditBody }));
        await page.route(`**/api/audits/${state.id}/findings`, (route) => route.fulfill({ json: { findings: findingsBody } }));
      };

      // Running: the first twenty controls are done and the rest are waiting.
      const running = await openPage(browser, base);
      await serve(running.page, { ...audit, status: "running", done_controls: 20, finished_at: null }, real.slice(0, 20));
      await running.page.goto(`${base}/#/audits/${state.id}`);
      await running.page.getByText("Assessing controls: 20 of 48").waitFor();
      assert.equal(await running.page.locator('.strip .cell[data-status="pending"]').count(), state.catalogSize - 20);
      await running.page.getByRole("button", { name: "Cancel review" }).waitFor();
      await shot(running.page, "12-running.png", { fullPage: true });
      await finish(running);

      // Finished with every mark in use, some findings for a person to look at, and a few controls that could not be assessed.
      const mixed = real.map((f, i) => {
        if (i % 4 === 0) return { ...f, status: "met", evidence: withEvidence[i % withEvidence.length].evidence, missing_elements: [], rationale: "The policy states each element this control expects, in section 4." };
        if (i % 11 === 5) return { ...f, status: "error", evidence: [], missing_elements: [], rationale: "The reviewer did not return an answer for this control." };
        if (i % 6 === 1) return { ...f, needs_review: true, flags: [flag] };
        return f;
      });
      const counts = (status) => mixed.filter((f) => f.status === status).length;
      const richSummary = { ...audit.summary, met: counts("met"), partial: counts("partial"), gap: counts("gap"), error: counts("error"), needs_review: mixed.filter((f) => f.needs_review).length };
      const done = await openPage(browser, base);
      await serve(done.page, { ...audit, summary: richSummary }, mixed);
      await done.page.goto(`${base}/#/audits/${state.id}`);
      await waitForFinished(done.page);
      await done.page.getByRole("button", { name: /findings need review$/ }).waitFor();
      assert.ok((await done.page.locator('.strip .cell[data-status="met"]').count()) > 0);
      assert.ok((await done.page.locator('.strip .cell[data-status="error"]').count()) > 0);
      await done.page.waitForTimeout(2800);
      await shot(done.page, "13-all-states.png", { fullPage: true });
      await done.page.getByRole("button", { name: /findings need review$/ }).click();
      await done.page.getByText(/Showing \d+ of \d+ controls/).waitFor();
      await done.page.locator(".finding-toggle").first().click();
      await done.page.locator('.finding[data-open="true"] .review-note').first().waitFor();
      await shot(done.page, "14-needs-review.png");
      await finish(done);

      // Failed and cancelled.
      const failed = await openPage(browser, base);
      await serve(failed.page, { ...audit, status: "failed", done_controls: 9, error: "The Anthropic API rejected the API key or the request. Check ANTHROPIC_API_KEY and the model name." }, real.slice(0, 9));
      await failed.page.goto(`${base}/#/audits/${state.id}`);
      await failed.page.getByText("This review could not finish").waitFor();
      assert.equal(await failed.page.locator('.strip .cell[data-status="pending"]').count(), 0, "a stopped review has nothing left waiting");
      assert.equal(await failed.page.locator('.strip .cell[data-status="error"]').count(), state.catalogSize - 9);
      await failed.page.waitForTimeout(2800);
      await shot(failed.page, "15-failed.png", { fullPage: true });
      await finish(failed);
    });

    await scenario("a server that needs an API key: asks for it, refuses a wrong one, accepts the right one, remembers it for the tab", async () => {
      const key = randomBytes(18).toString("hex"); // a throwaway key for this run's own server; never printed
      keyed.server = await startServer({ HIPAA_AUDIT_API_KEY: key });
      const url = keyed.server.base;
      const h = await openPage(browser, url, { allow: [/status of 401/] });
      await h.page.goto(`${url}/`);
      await h.page.getByText("This server needs an API key before it will answer.").waitFor();
      assert.equal(await h.page.getByRole("button", { name: "API key", exact: true }).getAttribute("aria-expanded"), "true");
      assert.equal(await h.page.getByRole("button", { name: "Start review" }).count(), 0, "the app stays out of the way until there is a key");
      await shot(h.page, "16-key-needed.png");

      await h.page.getByLabel("API key", { exact: true }).fill("not-the-key");
      await h.page.getByRole("button", { name: "Save key" }).click();
      await h.page.getByText("The server did not accept the saved key.").waitFor();

      await h.page.getByLabel("API key", { exact: true }).fill(key);
      await h.page.getByRole("button", { name: "Save key" }).click();
      await h.page.getByRole("heading", { level: 1, name: /Check a security policy/ }).waitFor();

      await h.page.reload();
      await h.page.getByRole("heading", { level: 1, name: /Check a security policy/ }).waitFor();
      const inStorage = await h.page.evaluate(() => [Object.keys(localStorage).length, Object.keys(sessionStorage).length]);
      assert.deepEqual(inStorage, [0, 1], "the key is in session storage only, never in local storage");

      await h.page.getByRole("button", { name: "API key", exact: true }).click();
      await h.page.getByRole("button", { name: "Forget key" }).click();
      await h.page.getByText("This server needs an API key").first().waitFor();
      await finish(h);
    });
  } finally {
    await browser.close();
    await server.stop();
    await keyed.server?.stop();
  }

  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length} of ${results.length} scenarios passed. Screenshots are in ${out}`);
  process.exit(failed.length ? 1 : 0);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
