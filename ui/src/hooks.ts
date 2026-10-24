import { useCallback, useEffect, useRef, useState } from "react";
import { type Api, toApiError, type ApiError } from "./api";
import type { Audit, Finding } from "./types";

const KEY_STORAGE = "hipaa-audit.api-key";

function readStoredKey(): string | null {
  try {
    return window.sessionStorage.getItem(KEY_STORAGE);
  } catch {
    return null; // storage can be blocked; the key then lasts until the page is closed
  }
}

export interface ApiKey {
  key: string | null;
  /** Always the latest key, also inside code that runs before the next render. */
  read: () => string | null;
  save: (value: string) => void;
  forget: () => void;
}

/** The API key lives in memory and in this tab's session storage; it is never written anywhere that outlives the tab. */
export function useApiKey(): ApiKey {
  const [key, setKey] = useState<string | null>(readStoredKey);
  const latest = useRef(key);
  const read = useCallback(() => latest.current, []);
  const write = useCallback((value: string | null) => {
    latest.current = value;
    setKey(value);
    try {
      if (value) window.sessionStorage.setItem(KEY_STORAGE, value);
      else window.sessionStorage.removeItem(KEY_STORAGE);
    } catch {
      // not stored; the key still works until the page is closed
    }
  }, []);
  const save = useCallback((value: string) => write(value.trim() || null), [write]);
  const forget = useCallback(() => write(null), [write]);
  return { key, read, save, forget };
}

let navigated = false;
if (typeof window !== "undefined") {
  window.addEventListener("hashchange", () => {
    navigated = true;
  });
}

/**
 * True once the person has moved between pages in this tab. A page that opens a fresh load keeps the browser's own starting
 * point, so the skip link stays the first tab stop; a page reached by a link takes focus to its heading, so a screen reader
 * announces where the person has arrived.
 */
export const hasNavigated = (): boolean => navigated;

export type Route = { name: "home" } | { name: "audit"; id: string };

export function parseRoute(hash: string): Route {
  const match = /^#\/audits\/([A-Za-z0-9_-]+)$/.exec(hash);
  return match?.[1] ? { name: "audit", id: match[1] } : { name: "home" };
}

export function useRoute(): Route {
  const [hash, setHash] = useState(() => window.location.hash);
  useEffect(() => {
    const onChange = () => setHash(window.location.hash);
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return parseRoute(hash);
}

export const POLL_MS = 1000;
export const RETRY_MS = 3000;

export interface AuditView {
  audit: Audit | null;
  findings: Finding[];
  error: ApiError | null;
  /** True when the last request failed but an earlier one worked, so the page keeps showing what it has. */
  stale: boolean;
  reload: () => void;
}

const isAbort = (e: unknown) => e instanceof DOMException && e.name === "AbortError";

/** One review: polled every second while it runs, with its findings as they arrive. */
export function useAudit(api: Api, id: string, onUnauthorized: () => void): AuditView {
  const [audit, setAudit] = useState<Audit | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState<ApiError | null>(null);
  const [version, setVersion] = useState(0);
  const reload = useCallback(() => setVersion((v) => v + 1), []);

  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let stopped = false;
    let fetchedFor = "";

    const poll = async () => {
      try {
        const current = await api.getAudit(id, controller.signal);
        // Findings only change when a control finishes or the audit ends, so ask for them only then.
        const marker = `${current.done_controls}:${current.status}`;
        const list =
          current.done_controls > 0 && marker !== fetchedFor ? await api.findings(id, controller.signal) : null;
        if (stopped) return;
        if (list) {
          fetchedFor = marker;
          setFindings(list);
        }
        setAudit(current);
        setError(null);
        if (current.status === "queued" || current.status === "running") timer = setTimeout(poll, POLL_MS);
      } catch (caught) {
        if (stopped || isAbort(caught)) return;
        const failure = toApiError(caught);
        setError(failure);
        if (failure.unauthorized) onUnauthorized();
        else if (!failure.notFound) timer = setTimeout(poll, RETRY_MS); // keep trying through a network blip
      }
    };
    void poll();
    return () => {
      stopped = true;
      controller.abort();
      clearTimeout(timer);
    };
  }, [api, id, version, onUnauthorized]);

  return { audit, findings, error, stale: error !== null && audit !== null, reload };
}

export function useDocumentTitle(title: string): void {
  useEffect(() => {
    document.title = title;
  }, [title]);
}

export function prefersReducedMotion(): boolean {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}
