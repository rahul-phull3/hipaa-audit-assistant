// Bundles the interface into dist/ with esbuild: one script, one stylesheet, the page and the icon. No dev server and no
// framework tooling; the Python server serves dist/ as static files (see src/hipaa_audit/api/app.py).
import { build, context } from "esbuild";
import { cp, mkdir, rm } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.dirname(fileURLToPath(import.meta.url));
const watch = process.argv.includes("--watch");
const tests = process.argv.includes("--tests");
const nodePaths = (process.env.NODE_PATH ?? "").split(path.delimiter).filter(Boolean);

async function buildTests() {
  const { readdir } = await import("node:fs/promises");
  const out = path.join(root, ".test-build");
  await rm(out, { recursive: true, force: true });
  const entries = (await readdir(path.join(root, "test"))).filter((f) => f.endsWith(".test.ts"));
  await build({
    absWorkingDir: root,
    entryPoints: entries.map((f) => `test/${f}`),
    outdir: out,
    bundle: true,
    platform: "node",
    format: "esm",
    target: "node20",
    sourcemap: "inline",
    jsx: "automatic",
    nodePaths,
    logLevel: "warning",
  });
  console.log(`built ${entries.length} test files into .test-build/`);
}

async function buildApp() {
  const dist = path.join(root, "dist");
  await rm(dist, { recursive: true, force: true });
  await mkdir(dist, { recursive: true });
  const options = {
    absWorkingDir: root,
    // Two entry points with one name: esbuild writes app.js and app.css.
    entryPoints: [
      { in: "src/main.tsx", out: "app" },
      { in: "src/styles.css", out: "app" },
    ],
    outdir: "dist",
    bundle: true,
    format: "esm",
    target: ["es2022", "chrome110", "firefox110", "safari16"],
    jsx: "automatic",
    minify: !watch,
    sourcemap: "linked",
    define: { "process.env.NODE_ENV": JSON.stringify(watch ? "development" : "production") },
    legalComments: "none",
    metafile: true,
    nodePaths,
    logLevel: "info",
  };
  await cp(path.join(root, "index.html"), path.join(dist, "index.html"));
  await cp(path.join(root, "public"), dist, { recursive: true });
  if (watch) {
    const ctx = await context(options);
    await ctx.watch();
    console.log("watching src/ ...");
    return;
  }
  const result = await build(options);
  for (const [file, info] of Object.entries(result.metafile.outputs)) {
    if (!file.endsWith(".map")) console.log(`${file}  ${(info.bytes / 1024).toFixed(1)} KB`);
  }
}

await (tests ? buildTests() : buildApp());
