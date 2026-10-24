import type { Audit, AuditListItem, Catalog, Finding, PassageContext, ServerStatus } from "./types";

/** A failed request, with the machine-readable code and the plain-language message the server sent. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }

  get unauthorized(): boolean {
    return this.status === 401;
  }

  get notFound(): boolean {
    return this.status === 404;
  }
}

export function toApiError(error: unknown): ApiError {
  if (error instanceof ApiError) return error;
  return new ApiError(0, "unknown", error instanceof Error ? error.message : "Something went wrong.");
}

export interface ApiOptions {
  /** The API key to send, or null when none is set. Read on every request so a new key applies at once. */
  getKey: () => string | null;
  fetchImpl?: typeof fetch;
  baseUrl?: string;
}

export interface Download {
  blob: Blob;
  filename: string;
}

export class Api {
  private readonly getKey: () => string | null;
  private readonly fetchImpl: typeof fetch;
  private readonly baseUrl: string;

  constructor(options: ApiOptions) {
    this.getKey = options.getKey;
    this.fetchImpl = options.fetchImpl ?? ((...args) => fetch(...args));
    this.baseUrl = options.baseUrl ?? "";
  }

  private async send(path: string, init: RequestInit = {}): Promise<Response> {
    const headers = new Headers(init.headers);
    const key = this.getKey();
    if (key) headers.set("X-API-Key", key);
    let response: Response;
    try {
      response = await this.fetchImpl(this.baseUrl + path, { ...init, headers });
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") throw error;
      throw new ApiError(0, "network", "Cannot reach the server. Check that it is running, then try again.");
    }
    if (!response.ok) throw await errorFrom(response);
    return response;
  }

  private async json<T>(path: string, init?: RequestInit): Promise<T> {
    const response = await this.send(path, init);
    return (await response.json()) as T;
  }

  status(signal?: AbortSignal): Promise<ServerStatus> {
    return this.json("/api/status", { signal });
  }

  catalog(signal?: AbortSignal): Promise<Catalog> {
    return this.json("/api/controls", { signal });
  }

  async listAudits(signal?: AbortSignal): Promise<AuditListItem[]> {
    const body = await this.json<{ audits: AuditListItem[] }>("/api/audits?limit=50", { signal });
    return body.audits;
  }

  getAudit(id: string, signal?: AbortSignal): Promise<Audit> {
    return this.json(`/api/audits/${encodeURIComponent(id)}`, { signal });
  }

  async findings(id: string, signal?: AbortSignal): Promise<Finding[]> {
    const body = await this.json<{ findings: Finding[] }>(`/api/audits/${encodeURIComponent(id)}/findings`, { signal });
    return body.findings;
  }

  passage(auditId: string, chunkId: string, signal?: AbortSignal): Promise<PassageContext> {
    return this.json(`/api/audits/${encodeURIComponent(auditId)}/chunks/${encodeURIComponent(chunkId)}`, { signal });
  }

  /** Upload a document. `controlIds` limits the review to some controls; omit it to review all of them. */
  createAudit(file: File, controlIds?: string[]): Promise<Audit> {
    const form = new FormData();
    form.append("file", file, file.name);
    if (controlIds && controlIds.length > 0) form.append("controls", controlIds.join(","));
    return this.json("/api/audits", { method: "POST", body: form });
  }

  cancel(id: string): Promise<Audit> {
    return this.json(`/api/audits/${encodeURIComponent(id)}/cancel`, { method: "POST" });
  }

  rerun(id: string): Promise<Audit> {
    return this.json(`/api/audits/${encodeURIComponent(id)}/rerun`, { method: "POST" });
  }

  async remove(id: string): Promise<void> {
    await this.send(`/api/audits/${encodeURIComponent(id)}`, { method: "DELETE" });
  }

  async report(id: string, format: "md" | "json"): Promise<Download> {
    const response = await this.send(`/api/audits/${encodeURIComponent(id)}/report?format=${format}`);
    return { blob: await response.blob(), filename: filenameFrom(response, `hipaa-review.${format}`) };
  }
}

async function errorFrom(response: Response): Promise<ApiError> {
  try {
    const body = (await response.json()) as { error?: { code?: string; message?: string } };
    if (body.error?.message) return new ApiError(response.status, body.error.code ?? "error", body.error.message);
  } catch {
    // The body was not JSON (for example a proxy error page); fall through to a generic message.
  }
  return new ApiError(response.status, "error", `The server answered with status ${response.status}.`);
}

function filenameFrom(response: Response, fallback: string): string {
  const header = response.headers.get("Content-Disposition") ?? "";
  const match = /filename="([^"\\/]+)"/.exec(header);
  return match?.[1] ?? fallback;
}
