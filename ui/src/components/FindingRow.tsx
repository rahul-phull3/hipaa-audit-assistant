import { useId, useState } from "react";
import { useApp } from "../app-context";
import { toApiError } from "../api";
import { type Row, STATUS_LABELS, locateQuote, locationLabel, statusOf } from "../findings";
import { percent } from "../format";
import type { Evidence, Passage, PassageContext } from "../types";
import { StatusMark } from "./StatusMark";

interface Props {
  auditId: string;
  row: Row;
  open: boolean;
  onToggle: () => void;
  /** Only a language model's confidence is worth showing; the offline matcher's is a ratio of keywords. */
  showConfidence: boolean;
}

export function FindingRow({ auditId, row, open, onToggle, showConfidence }: Props) {
  const { catalog } = useApp();
  const panelId = useId();
  const { control, finding } = row;
  const status = statusOf(row);
  const flagLabels = catalog?.flag_labels ?? {};

  return (
    <li className="finding" id={`finding-${control.id}`} data-status={status} data-open={open}>
      <h3 className="finding-head">
        <button
          type="button"
          className="finding-toggle"
          data-control={control.id}
          aria-expanded={open}
          aria-controls={panelId}
          onClick={onToggle}
        >
          <StatusMark status={status} />
          <span className="finding-title">{control.title}</span>
          <span className="finding-verdict">{STATUS_LABELS[status]}</span>
          <span className="finding-tags">
            {control.requirement ? (
              <span className="tag">{control.requirement === "required" ? "Required" : "Addressable"}</span>
            ) : null}
            {finding?.needs_review ? <span className="tag tag-review">Needs review</span> : null}
          </span>
          <svg className="chevron" viewBox="0 0 12 12" aria-hidden="true" focusable="false">
            <path d="M2.5 4.5 6 8l3.5-3.5" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </button>
      </h3>
      <div className="finding-body" id={panelId} hidden={!open}>
        {open ? (
          <>
            <p className="finding-cite">
              {control.citation}
              {control.standard ? `, ${control.standard}` : ""}
            </p>
            {finding ? (
              <>
                <p className="verdict">{finding.rationale}</p>
                {finding.evidence.length > 0 ? (
                  <section className="evidence" aria-label="Passages from the document">
                    {status === "gap" ? (
                      <p className="evidence-note">Closest passages in the document. These do not count as support.</p>
                    ) : null}
                    {finding.evidence.map((e, i) => (
                      <Quote key={`${e.chunk_id}-${i}`} auditId={auditId} evidence={e} />
                    ))}
                  </section>
                ) : null}
                {finding.missing_elements.length > 0 ? (
                  <section className="missing">
                    <h4>Not shown in the document</h4>
                    <ul>
                      {finding.missing_elements.map((m) => (
                        <li key={m}>{m}</li>
                      ))}
                    </ul>
                  </section>
                ) : null}
                {finding.flags.map((flag) => (
                  <p className="review-note" role="note" key={flag}>
                    <strong>Review note.</strong> {flagLabels[flag] ?? flag}
                  </p>
                ))}
                {showConfidence && status !== "error" ? (
                  <p className="confidence">Reviewer confidence {percent(finding.confidence)}</p>
                ) : null}
              </>
            ) : (
              <p className="verdict">
                {row.settled
                  ? "This control was not assessed because the review stopped before it got here. Run the review again to assess it."
                  : "This control has not been assessed yet."}
              </p>
            )}
            {control.expectation ? (
              <details className="expectation">
                <summary>What this control expects</summary>
                <p>{control.expectation}</p>
                {control.elements.length > 0 ? (
                  <ul>
                    {control.elements.map((el) => (
                      <li key={el}>{el}</li>
                    ))}
                  </ul>
                ) : null}
              </details>
            ) : null}
          </>
        ) : null}
      </div>
    </li>
  );
}

type ContextState =
  | { kind: "closed" }
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; context: PassageContext };

function Quote({ auditId, evidence }: { auditId: string; evidence: Evidence }) {
  const { api, requireKey } = useApp();
  const [view, setView] = useState<ContextState>({ kind: "closed" });
  const where = locationLabel(evidence.page, evidence.section);

  const show = async () => {
    setView({ kind: "loading" });
    try {
      setView({ kind: "ready", context: await api.passage(auditId, evidence.chunk_id) });
    } catch (caught) {
      const failure = toApiError(caught);
      if (failure.unauthorized) requireKey();
      setView({ kind: "error", message: failure.message });
    }
  };

  return (
    <figure className="quote">
      <blockquote>{evidence.quote}</blockquote>
      <figcaption>
        {where ? <span className="where">{where}</span> : null}
        <button
          type="button"
          className="btn btn-link"
          aria-expanded={view.kind === "ready"}
          disabled={view.kind === "loading"}
          onClick={view.kind === "ready" ? () => setView({ kind: "closed" }) : show}
        >
          {view.kind === "ready" ? "Hide surrounding text" : view.kind === "loading" ? "Loading" : "Show surrounding text"}
        </button>
      </figcaption>
      {view.kind === "error" ? (
        <p className="inline-error" role="alert">
          {view.message}
        </p>
      ) : null}
      {view.kind === "ready" ? <Context context={view.context} quote={evidence.quote} /> : null}
    </figure>
  );
}

function Context({ context, quote }: { context: PassageContext; quote: string }) {
  const found = locateQuote(context.text, quote);
  return (
    <div className="context">
      {context.previous ? <Neighbour passage={context.previous} /> : null}
      <div className="passage" data-current="true">
        <p className="passage-where">{locationLabel(context.page, context.section)}</p>
        <p className="passage-text">
          {found ? (
            <>
              {found.before}
              <mark>{found.match}</mark>
              {found.after}
            </>
          ) : (
            context.text
          )}
        </p>
      </div>
      {context.next ? <Neighbour passage={context.next} /> : null}
    </div>
  );
}

function Neighbour({ passage }: { passage: Passage }) {
  return (
    <div className="passage" data-current="false">
      <p className="passage-where">{locationLabel(passage.page, passage.section)}</p>
      <p className="passage-text">{passage.text}</p>
    </div>
  );
}
