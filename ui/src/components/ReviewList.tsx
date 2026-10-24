import { useEffect, useState } from "react";
import { useApp } from "../app-context";
import { toApiError } from "../api";
import { STATUS_LABELS } from "../findings";
import { describeBackend, plural, relativeTime } from "../format";
import type { AuditListItem, FindingStatus } from "../types";
import { StatusMark } from "./StatusMark";

const COUNTED: FindingStatus[] = ["met", "partial", "gap", "error"];
const REFRESH_MS = 3000;

export function ReviewList() {
  const { api, requireKey } = useApp();
  const [audits, setAudits] = useState<AuditListItem[] | null>(null);
  const [problem, setProblem] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let stopped = false;
    const load = async () => {
      try {
        const list = await api.listAudits(controller.signal);
        if (stopped) return;
        setAudits(list);
        setProblem(null);
        if (list.some((a) => a.status === "queued" || a.status === "running")) timer = setTimeout(load, REFRESH_MS);
      } catch (caught) {
        if (stopped || (caught instanceof DOMException && caught.name === "AbortError")) return;
        const failure = toApiError(caught);
        if (failure.unauthorized) requireKey();
        setProblem(failure.message);
      }
    };
    void load();
    return () => {
      stopped = true;
      controller.abort();
      clearTimeout(timer);
    };
  }, [api, requireKey]);

  if (problem) return <p className="inline-error" role="alert">{problem}</p>;
  if (audits === null) return <p className="muted">Loading reviews</p>;
  if (audits.length === 0) return <p className="muted">No reviews yet. Upload a policy above to start one.</p>;

  return (
    <table className="history">
      <thead>
        <tr>
          <th scope="col">Document</th>
          <th scope="col">Started</th>
          <th scope="col" className="hide-narrow">Reviewed by</th>
          <th scope="col">Result</th>
        </tr>
      </thead>
      <tbody>
        {audits.map((audit) => (
          <tr key={audit.id}>
            <th scope="row">
              <a href={`#/audits/${audit.id}`}>{audit.filename}</a>
            </th>
            <td>
              <time dateTime={audit.created_at} title={new Date(audit.created_at).toLocaleString()}>
                {relativeTime(audit.created_at)}
              </time>
            </td>
            <td className="hide-narrow">{describeBackend(audit.backend).label}</td>
            <td>
              <Result audit={audit} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Result({ audit }: { audit: AuditListItem }) {
  if (audit.status === "queued") return <span>Waiting to start</span>;
  if (audit.status === "running") return <span>{`Assessing ${audit.done_controls} of ${audit.total_controls}`}</span>;
  const counts = COUNTED.filter((s) => (audit.counts[s] ?? 0) > 0);
  const note = audit.status === "failed" ? "Failed" : audit.status === "cancelled" ? "Cancelled" : null;
  return (
    <span className="counts-inline">
      {note ? <span className="result-note">{note}</span> : null}
      {counts.map((status) => (
        <span className="count" key={status} aria-label={`${plural(audit.counts[status] ?? 0, "control")}: ${STATUS_LABELS[status].toLowerCase()}`}>
          <StatusMark status={status} />
          <span aria-hidden="true">{audit.counts[status]}</span>
        </span>
      ))}
      {!note && counts.length === 0 ? <span className="muted">No findings</span> : null}
    </span>
  );
}
