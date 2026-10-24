import { type ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { useApp } from "../app-context";
import { toApiError } from "../api";
import { Counts } from "../components/Counts";
import { Filters } from "../components/Filters";
import { FindingRow } from "../components/FindingRow";
import { Notice } from "../components/Notice";
import { Strip } from "../components/Strip";
import {
  type Filter,
  NO_FILTER,
  applyFilter,
  buildRows,
  groupRows,
  matchesFilter,
  tally,
} from "../findings";
import { describeBackend, formatBytes, plural, relativeTime, shortHash } from "../format";
import { hasNavigated, prefersReducedMotion, useAudit, useDocumentTitle } from "../hooks";
import type { Audit } from "../types";

type Busy = "cancel" | "rerun" | "delete" | "md" | "json" | null;

const isActive = (audit: Audit) => audit.status === "queued" || audit.status === "running";

export function ReviewPage({ id }: { id: string }) {
  const { api, catalog, requireKey } = useApp();
  const { audit, findings, error, stale, reload } = useAudit(api, id, requireKey);
  const [filter, setFilter] = useState<Filter>(NO_FILTER);
  const [open, setOpen] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<string | null>(null);
  const [jumpTo, setJumpTo] = useState<string | null>(null);
  const [busy, setBusy] = useState<Busy>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [sweep, setSweep] = useState<boolean | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  useDocumentTitle(audit ? `${audit.filename} - HIPAA policy review` : "HIPAA policy review");

  const rows = useMemo(
    () => (audit && catalog ? buildRows(audit.control_ids, catalog.controls, findings, !isActive(audit)) : []),
    [audit, catalog, findings],
  );
  const counts = useMemo(() => tally(rows), [rows]);
  const visible = useMemo(() => applyFilter(rows, filter), [rows, filter]);
  const allGroups = useMemo(() => groupRows(rows), [rows]);
  const shownGroups = useMemo(() => groupRows(visible), [visible]);

  // A finished review is introduced with one quick sweep along the strip; a running one fills in as controls finish. The
  // choice is made in the render that first has the audit, so the strip mounts with it.
  if (audit && sweep === null) setSweep(!isActive(audit) && !prefersReducedMotion());
  useEffect(() => {
    if (!sweep) return;
    const timer = setTimeout(() => setSweep(false), 2200);
    return () => clearTimeout(timer);
  }, [sweep]);

  const loaded = audit !== null;
  useEffect(() => {
    if (loaded && hasNavigated()) heading.current?.focus({ preventScroll: true });
  }, [loaded]);

  // After the strip sends someone to a finding: open it, bring it into view and move focus to it.
  useEffect(() => {
    if (!jumpTo) return;
    const toggle = document.querySelector<HTMLButtonElement>(`[data-control="${CSS.escape(jumpTo)}"]`);
    toggle?.scrollIntoView({ block: "center", behavior: prefersReducedMotion() ? "auto" : "smooth" });
    toggle?.focus({ preventScroll: true });
    setJumpTo(null);
  }, [jumpTo]);

  const choose = (controlId: string) => {
    const row = rows.find((r) => r.control.id === controlId);
    if (row && !matchesFilter(row, filter)) setFilter(NO_FILTER);
    setOpen((prev) => new Set(prev).add(controlId));
    setSelected(controlId);
    setJumpTo(controlId);
  };

  const toggle = (controlId: string) =>
    setOpen((prev) => {
      const next = new Set(prev);
      if (!next.delete(controlId)) next.add(controlId);
      return next;
    });

  const act = async (kind: Exclude<Busy, null>, work: () => Promise<void>) => {
    setBusy(kind);
    setProblem(null);
    try {
      await work();
    } catch (caught) {
      const failure = toApiError(caught);
      if (failure.unauthorized) requireKey();
      setProblem(failure.message);
    } finally {
      setBusy(null);
    }
  };

  const download = (format: "md" | "json") =>
    act(format, async () => {
      const { blob, filename } = await api.report(id, format);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    });

  const rerun = () =>
    act("rerun", async () => {
      const next = await api.rerun(id);
      window.location.hash = `#/audits/${next.id}`;
    });

  const cancel = () =>
    act("cancel", async () => {
      await api.cancel(id);
      reload();
    });

  const remove = () =>
    act("delete", async () => {
      await api.remove(id);
      window.location.hash = "#/";
    });

  if (!audit) {
    if (error) {
      return (
        <div className="review">
          <p className="crumbs"><a href="#/">All reviews</a></p>
          <Notice
            tone="error"
            title={error.notFound ? "This review does not exist" : "This review could not be loaded"}
            actions={error.notFound ? undefined : <button type="button" className="btn btn-secondary" onClick={reload}>Try again</button>}
          >
            {error.notFound ? "It may have been deleted. Go back to the list to see the reviews that are left." : error.message}
          </Notice>
        </div>
      );
    }
    return <p className="muted">Loading the review</p>;
  }

  const backend = describeBackend(audit.backend);
  const active = isActive(audit);

  return (
    <div className="review">
      <p className="crumbs"><a href="#/">All reviews</a></p>

      <header className="review-head">
        <h1 ref={heading} tabIndex={-1}>{audit.filename}</h1>
        <dl className="facts">
          <Fact term="Reviewed by">{backend.label}</Fact>
          <Fact term="Started">
            <time dateTime={audit.created_at} title={new Date(audit.created_at).toLocaleString()}>{relativeTime(audit.created_at)}</time>
          </Fact>
          {audit.pages ? <Fact term="Pages">{audit.pages}</Fact> : null}
          <Fact term="Size">{formatBytes(audit.size_bytes)}</Fact>
          <Fact term="Document hash"><span title={audit.sha256}>{shortHash(audit.sha256)}</span></Fact>
        </dl>
        <div className="actions">
          {active ? (
            <button type="button" className="btn btn-secondary" disabled={busy !== null} onClick={cancel}>
              {busy === "cancel" ? "Cancelling" : "Cancel review"}
            </button>
          ) : (
            <>
              <button type="button" className="btn btn-secondary" disabled={busy !== null} onClick={() => download("md")}>
                {busy === "md" ? "Preparing report" : "Download report (Markdown)"}
              </button>
              <button type="button" className="btn btn-secondary" disabled={busy !== null} onClick={() => download("json")}>
                {busy === "json" ? "Preparing report" : "Download report (JSON)"}
              </button>
              <button type="button" className="btn btn-secondary" disabled={busy !== null} onClick={rerun}>
                {busy === "rerun" ? "Starting" : "Run again"}
              </button>
              {confirming ? (
                <span className="confirm" role="group" aria-label="Confirm deleting this review">
                  <span>Delete this review and its text?</span>
                  <button type="button" className="btn btn-danger" disabled={busy !== null} onClick={remove}>
                    {busy === "delete" ? "Deleting" : "Delete"}
                  </button>
                  <button type="button" className="btn btn-quiet" onClick={() => setConfirming(false)}>Keep it</button>
                </span>
              ) : (
                <button type="button" className="btn btn-quiet" disabled={busy !== null} onClick={() => setConfirming(true)}>
                  Delete review
                </button>
              )}
            </>
          )}
        </div>
        {problem ? <p className="inline-error" role="alert">{problem}</p> : null}
      </header>

      {!backend.isModel ? (
        <Notice tone="warning" title="Offline keyword matching">
          No AI model read this document. The marks show where the policy uses the words each control expects, so treat them as
          pointers to check by hand.
        </Notice>
      ) : null}
      {audit.status === "failed" ? (
        <Notice
          tone="error"
          title="This review could not finish"
          actions={<button type="button" className="btn btn-secondary" disabled={busy !== null} onClick={rerun}>Run again</button>}
        >
          {audit.error ?? "The review stopped before it could assess the controls."}
        </Notice>
      ) : null}
      {audit.status === "cancelled" ? (
        <Notice tone="info" title="This review was cancelled">
          {`${audit.done_controls} of ${plural(audit.total_controls, "control")} had been assessed when it stopped.`}
        </Notice>
      ) : null}
      {stale ? (
        <p className="inline-error" role="status">Lost contact with the server. Trying again.</p>
      ) : null}

      <section className="overview" aria-label="Overview">
        {active ? <Progress audit={audit} /> : null}
        <Strip groups={allGroups} selectedId={selected} onSelect={choose} sweep={sweep === true} live={active} />
        <Counts tally={counts} active={active} onReview={() => setFilter({ ...NO_FILTER, status: "review" })} />
      </section>

      <section className="findings-section" aria-label="Findings">
        <Filters filter={filter} tally={counts} onChange={setFilter} shown={visible.length} />
        {shownGroups.length === 0 ? (
          <p className="muted">No findings match these filters.</p>
        ) : (
          shownGroups.map((group) => (
            <section className="group" key={group.safeguard || "other"} aria-labelledby={`group-${group.safeguard || "other"}`}>
              <h2 id={`group-${group.safeguard || "other"}`}>{group.label}</h2>
              <ul className="findings" role="list">
                {group.rows.map((row) => (
                  <FindingRow
                    key={row.control.id}
                    auditId={audit.id}
                    row={row}
                    open={open.has(row.control.id)}
                    onToggle={() => toggle(row.control.id)}
                    showConfidence={backend.isModel}
                  />
                ))}
              </ul>
            </section>
          ))
        )}
      </section>

      <About audit={audit} />
    </div>
  );
}

function Fact({ term, children }: { term: string; children: ReactNode }) {
  return (
    <div>
      <dt>{term}</dt>
      <dd>{children}</dd>
    </div>
  );
}

/** Announced at every quarter, not at every control, so a screen reader is not interrupted 48 times. */
function announcement(audit: Audit): string {
  if (audit.status === "queued") return "The review is waiting to start.";
  const quarter = Math.floor((audit.done_controls / Math.max(1, audit.total_controls)) * 4) * 25;
  return `Assessing controls, ${quarter} percent done.`;
}

function Progress({ audit }: { audit: Audit }) {
  return (
    <div className="progress">
      <progress max={audit.total_controls} value={audit.done_controls} aria-label="Controls assessed" />
      <p>{audit.status === "queued" ? "Waiting to start" : `Assessing controls: ${audit.done_controls} of ${audit.total_controls}`}</p>
      <p className="visually-hidden" role="status">{announcement(audit)}</p>
    </div>
  );
}

function About({ audit }: { audit: Audit }) {
  const { catalog } = useApp();
  const usage = audit.usage;
  return (
    <details className="about">
      <summary>About this review</summary>
      {catalog ? (
        <>
          <p>
            Controls come from catalog {audit.catalog_version} ({catalog.regulation}).
            {audit.catalog_version !== catalog.version ? ` The catalog has since been updated to ${catalog.version}.` : ""}
          </p>
          <p>{catalog.rule_status}</p>
          {catalog.notes.length > 0 ? (
            <ul>
              {catalog.notes.map((note) => (
                <li key={note}>{note}</li>
              ))}
            </ul>
          ) : null}
        </>
      ) : null}
      <p>
        Passages were found with {audit.embedder || "an unrecorded method"}, and the prompt version was {audit.prompt_version}.
        {usage.input_tokens || usage.output_tokens
          ? ` The model used ${usage.input_tokens.toLocaleString()} input and ${usage.output_tokens.toLocaleString()} output tokens.`
          : ""}
      </p>
    </details>
  );
}
