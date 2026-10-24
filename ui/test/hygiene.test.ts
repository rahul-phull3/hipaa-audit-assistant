import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

/**
 * The server sends a strict content security policy (no inline script, no inline style, no external hosts; see
 * src/hipaa_audit/api/middleware.py). These checks keep the sources inside it, so a violation fails here instead of showing up
 * as a blank page in a browser.
 */
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const full = path.join(dir, name);
    return statSync(full).isDirectory() ? sources(full) : [full];
  });
}

const read = (file: string) => readFileSync(path.join(root, file), "utf8");
const files = sources(path.join(root, "src")).filter((f) => /\.(tsx?|css)$/.test(f));

test("index.html has no inline script, inline style or event handler attribute", () => {
  const html = read("index.html");
  assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/i, "inline <script>");
  assert.doesNotMatch(html, /<style[\s>]/i, "<style> element");
  assert.doesNotMatch(html, /\sstyle\s*=/i, "style attribute");
  assert.doesNotMatch(html, /\son[a-z]+\s*=/i, "inline event handler");
});

test("nothing renders raw HTML", () => {
  for (const file of files) {
    assert.doesNotMatch(readFileSync(file, "utf8"), /dangerouslySetInnerHTML|\.innerHTML\s*=|insertAdjacentHTML|eval\(/, file);
  }
});

test("the only style prop sets a CSS custom property for the strip animation", () => {
  const using = files.filter((f) => /\bstyle=\{/.test(readFileSync(f, "utf8")));
  assert.deepEqual(
    using.map((f) => path.relative(root, f)),
    [path.join("src", "components", "Strip.tsx")],
  );
  assert.match(readFileSync(using[0]!, "utf8"), /style=\{\{ "--i": index \} as CSSProperties\}/);
});

test("the stylesheet loads no fonts, images or other files", () => {
  const css = read(path.join("src", "styles.css"));
  assert.doesNotMatch(css, /@import|@font-face|url\(/);
});

test("scripts and links in index.html point at files the server serves from the same origin", () => {
  const html = read("index.html");
  for (const [, url] of html.matchAll(/(?:src|href)="([^"]+)"/g)) {
    assert.ok(url && !/^(?:[a-z]+:)?\/\//i.test(url), `external reference ${url}`);
  }
});
