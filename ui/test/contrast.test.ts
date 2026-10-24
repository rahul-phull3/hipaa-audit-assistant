import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

/**
 * Reads the colour tokens out of src/styles.css and checks the pairs the interface actually uses against WCAG 2.2 AA:
 * 4.5:1 for text, 3:1 for the marks, borders and focus rings a person needs to see. Both colour schemes are checked.
 */
const css = readFileSync(new URL("../src/styles.css", import.meta.url), "utf8");

type Rgba = [number, number, number, number];

function blockAfter(pattern: RegExp): string {
  const match = pattern.exec(css);
  assert.ok(match, `styles.css has no block matching ${pattern}`);
  const start = css.indexOf("{", match.index);
  let depth = 0;
  for (let i = start; i < css.length; i += 1) {
    if (css[i] === "{") depth += 1;
    if (css[i] === "}" && --depth === 0) return css.slice(start + 1, i);
  }
  throw new Error(`unterminated block after ${pattern}`);
}

function tokens(block: string): Map<string, string> {
  const found = new Map<string, string>();
  for (const [, name, value] of block.matchAll(/--([\w-]+):\s*([^;]+);/g)) {
    if (name && value) found.set(name, value.trim());
  }
  return found;
}

function parse(value: string): Rgba {
  const hex = /^#([0-9a-f]{6})$/i.exec(value);
  if (hex?.[1]) {
    const n = Number.parseInt(hex[1], 16);
    return [(n >> 16) & 255, (n >> 8) & 255, n & 255, 1];
  }
  const rgba = /^rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*(?:,\s*([\d.]+))?\s*\)$/.exec(value);
  if (rgba) return [Number(rgba[1]), Number(rgba[2]), Number(rgba[3]), rgba[4] === undefined ? 1 : Number(rgba[4])];
  throw new Error(`cannot read the colour "${value}"`);
}

/** A translucent colour as it looks over an opaque one. */
function over(front: Rgba, back: Rgba): Rgba {
  const a = front[3];
  return [0, 1, 2].map((i) => Math.round(front[i]! * a + back[i]! * (1 - a))).concat(1) as Rgba;
}

function luminance([r, g, b]: Rgba): number {
  const channel = (v: number) => {
    const s = v / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
}

function contrast(a: Rgba, b: Rgba): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}

const light = tokens(blockAfter(/^:root\s*\{/m));
const dark = new Map([...light, ...tokens(blockAfter(/@media \(prefers-color-scheme: dark\)/))]);

for (const [scheme, palette] of [
  ["light", light],
  ["dark", dark],
] as const) {
  const color = (name: string): Rgba => {
    const value = palette.get(name);
    assert.ok(value, `--${name} is not defined in the ${scheme} scheme`);
    return parse(value);
  };
  const check = (min: number, foreground: Rgba, background: Rgba, what: string) => {
    const ratio = contrast(foreground, background);
    assert.ok(ratio >= min, `${scheme}: ${what} is ${ratio.toFixed(2)}:1, needs ${min}:1`);
  };

  const paper = color("paper");
  const sheet = color("sheet");
  const washedPaper = (wash: string) => over(color(wash), paper);
  const surfaces: [string, Rgba][] = [
    ["the page", paper],
    ["a sheet", sheet],
  ];

  test(`${scheme}: text is readable on the page and on a sheet`, () => {
    for (const name of ["ink", "ink-2", "ink-3", "pen", "error-text"]) {
      for (const [where, surface] of surfaces) check(4.5, color(name), surface, `--${name} on ${where}`);
    }
  });

  test(`${scheme}: status words and marks are visible on the page, a sheet and a hovered row`, () => {
    const hovered = washedPaper("pen-wash");
    for (const name of ["met", "partial", "gap"]) {
      for (const [where, surface] of [...surfaces, ["a hovered row", hovered] as [string, Rgba]]) {
        check(4.5, color(name), surface, `--${name} as text on ${where}`);
      }
    }
    for (const name of ["error", "pending"]) {
      for (const [where, surface] of surfaces) check(3, color(name), surface, `--${name} mark on ${where}`);
    }
    check(4.5, color("error"), paper, "--error as text on the page");
  });

  test(`${scheme}: buttons and the notices read clearly`, () => {
    check(4.5, color("on-pen"), color("pen"), "button text on --pen");
    check(4.5, color("on-danger"), color("danger"), "button text on --danger");
    check(3, color("mark-tick"), color("met"), "the tick inside a met mark");
    for (const wash of ["pen-wash", "wash-warn", "wash-error"]) {
      const surface = washedPaper(wash);
      check(4.5, color("ink"), surface, `--ink on ${wash}`);
      check(4.5, color("ink-2"), surface, `--ink-2 on ${wash}`);
    }
    check(4.5, color("pen"), washedPaper("pen-wash"), "--pen on its own wash (the Needs review tag)");
    check(3, color("disabled-fg"), color("disabled-bg"), "disabled button text");
  });

  test(`${scheme}: borders and focus rings stand out from what is behind them`, () => {
    for (const name of ["line-strong", "pen"]) {
      for (const [where, surface] of surfaces) check(3, color(name), surface, `--${name} on ${where}`);
    }
  });
}

test("the dark scheme overrides the colours and keeps the same names", () => {
  for (const name of ["paper", "sheet", "ink", "pen", "met", "partial", "gap"]) {
    assert.notEqual(light.get(name), dark.get(name), `--${name} should differ in dark mode`);
  }
});
