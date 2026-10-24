import assert from "node:assert/strict";
import { test } from "node:test";
import { Api, ApiError, toApiError } from "../src/api";

type Handler = (url: string, init: RequestInit) => Response | Promise<Response>;

function makeApi(handler: Handler, key: string | null = null) {
  const calls: { url: string; init: RequestInit; headers: Headers }[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = String(input);
    calls.push({ url, init, headers: new Headers(init.headers) });
    return handler(url, init);
  }) as typeof fetch;
  return { api: new Api({ getKey: () => key, fetchImpl }), calls };
}

const json = (body: unknown, init: ResponseInit = {}) =>
  new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" }, ...init });

test("sends the API key only when there is one", async () => {
  const withKey = makeApi(() => json({ status: "ok" }), "secret");
  await withKey.api.status();
  assert.equal(withKey.calls[0]?.headers.get("X-API-Key"), "secret");
  const without = makeApi(() => json({ status: "ok" }));
  await without.api.status();
  assert.equal(without.calls[0]?.headers.has("X-API-Key"), false);
});

test("reads the key again on every request", async () => {
  let key: string | null = null;
  const seen: (string | null)[] = [];
  const api = new Api({
    getKey: () => key,
    fetchImpl: (async (_url: RequestInfo | URL, init: RequestInit = {}) => {
      seen.push(new Headers(init.headers).get("X-API-Key"));
      return json({});
    }) as typeof fetch,
  });
  await api.status();
  key = "later";
  await api.status();
  assert.deepEqual(seen, [null, "later"]);
});

test("turns the server's error body into an ApiError", async () => {
  const { api } = makeApi(() => json({ error: { code: "invalid_request", message: "Unsupported file type." } }, { status: 422 }));
  await assert.rejects(api.getAudit("x"), (error: unknown) => {
    assert.ok(error instanceof ApiError);
    assert.deepEqual([error.status, error.code, error.message], [422, "invalid_request", "Unsupported file type."]);
    assert.equal(error.unauthorized, false);
    return true;
  });
});

test("knows an unauthorized and a missing resource", async () => {
  const { api } = makeApi((url) =>
    url.includes("/api/status")
      ? json({ error: { code: "unauthorized", message: "A valid X-API-Key header is required." } }, { status: 401 })
      : json({ error: { code: "not_found", message: "No such resource." } }, { status: 404 }),
  );
  await assert.rejects(api.status(), (e: unknown) => e instanceof ApiError && e.unauthorized);
  await assert.rejects(api.getAudit("x"), (e: unknown) => e instanceof ApiError && e.notFound);
});

test("falls back to a generic message when the error is not JSON", async () => {
  const { api } = makeApi(() => new Response("<html>Bad gateway</html>", { status: 502 }));
  await assert.rejects(api.status(), (e: unknown) => e instanceof ApiError && e.status === 502 && /502/.test(e.message));
});

test("reports an unreachable server in plain words", async () => {
  const api = new Api({
    getKey: () => null,
    fetchImpl: (async () => {
      throw new TypeError("fetch failed");
    }) as typeof fetch,
  });
  await assert.rejects(api.status(), (e: unknown) => e instanceof ApiError && e.code === "network" && /Cannot reach the server/.test(e.message));
});

test("lets an abort through unchanged", async () => {
  const api = new Api({
    getKey: () => null,
    fetchImpl: (async () => {
      throw new DOMException("aborted", "AbortError");
    }) as typeof fetch,
  });
  await assert.rejects(api.status(), (e: unknown) => e instanceof DOMException && e.name === "AbortError");
});

test("escapes ids in paths", async () => {
  const { api, calls } = makeApi(() => json({ findings: [] }));
  await api.findings("a/b c");
  assert.equal(calls[0]?.url, "/api/audits/a%2Fb%20c/findings");
});

test("uploads the file and the chosen controls as a form", async () => {
  const { api, calls } = makeApi(() => json({ id: "abc" }, { status: 202 }));
  const file = new File(["policy text"], "policy.txt", { type: "text/plain" });
  await api.createAudit(file, ["risk-analysis", "sanction-policy"]);
  const call = calls[0];
  assert.equal(call?.init.method, "POST");
  const form = call?.init.body as FormData;
  assert.equal((form.get("file") as File).name, "policy.txt");
  assert.equal(form.get("controls"), "risk-analysis,sanction-policy");
  assert.equal(call?.headers.has("Content-Type"), false); // the browser adds the multipart boundary itself

  await api.createAudit(file);
  assert.equal((calls[1]?.init.body as FormData).has("controls"), false);
  await api.createAudit(file, []);
  assert.equal((calls[2]?.init.body as FormData).has("controls"), false);
});

test("downloads a report with the file name the server suggests", async () => {
  const { api, calls } = makeApi(
    () => new Response("# Report", { headers: { "Content-Disposition": 'attachment; filename="hipaa-review-policy.md"' } }),
  );
  const download = await api.report("abc", "md");
  assert.equal(download.filename, "hipaa-review-policy.md");
  assert.equal(await download.blob.text(), "# Report");
  assert.equal(calls[0]?.url, "/api/audits/abc/report?format=md");

  const bare = makeApi(() => new Response("{}"));
  assert.equal((await bare.api.report("abc", "json")).filename, "hipaa-review.json");
});

test("deleting returns nothing and posts to the right place", async () => {
  const { api, calls } = makeApi(() => new Response(null, { status: 204 }));
  assert.equal(await api.remove("abc"), undefined);
  assert.equal(calls[0]?.init.method, "DELETE");
  const posted = makeApi(() => json({ id: "n" }, { status: 202 }));
  await posted.api.rerun("abc");
  await posted.api.cancel("abc");
  assert.deepEqual(
    posted.calls.map((c) => `${c.init.method} ${c.url}`),
    ["POST /api/audits/abc/rerun", "POST /api/audits/abc/cancel"],
  );
});

test("toApiError wraps anything", () => {
  assert.equal(toApiError(new ApiError(500, "x", "y")).message, "y");
  assert.equal(toApiError(new Error("boom")).message, "boom");
  assert.equal(toApiError("odd").message, "Something went wrong.");
});
