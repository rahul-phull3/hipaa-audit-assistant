/** "just now", "5 minutes ago", "2 days ago"; older than a month falls back to the date. */
export function relativeTime(iso: string, now: number = Date.now()): string {
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return "";
  const seconds = Math.max(0, Math.round((now - then) / 1000));
  if (seconds < 45) return "just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${plural(minutes, "minute")} ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${plural(hours, "hour")} ago`;
  const days = Math.round(hours / 24);
  if (days <= 30) return `${plural(days, "day")} ago`;
  return new Date(then).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(bytes < 10 * 1024 ? 1 : 0)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function percent(value: number): string {
  return `${Math.round(Math.min(1, Math.max(0, value)) * 100)}%`;
}

export function plural(count: number, one: string, many: string = `${one}s`): string {
  return `${count} ${count === 1 ? one : many}`;
}

export interface BackendDescription {
  label: string;
  isModel: boolean;
}

/** How to name the reviewer. The offline backend is a keyword matcher and the interface must never call it a model. */
export function describeBackend(name: string): BackendDescription {
  if (name.startsWith("heuristic")) return { label: "Offline keyword matching", isModel: false };
  return { label: name, isModel: true };
}

/** First characters of a hash, enough to tell two documents apart. */
export function shortHash(hash: string): string {
  return hash.slice(0, 12);
}

/** What a gap does and does not say: the reviewer sees only the few passages that search put in front of it. */
export function coverageNote(passagesSeen: number): string {
  return `The reviewer was shown ${plural(passagesSeen, "passage")} of the document for this control. If the document covers it somewhere else, that part was not seen.`;
}
