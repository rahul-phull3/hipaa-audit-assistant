import { STATUS_LABELS, type Tally } from "../findings";
import { StatusMark } from "./StatusMark";

interface Props {
  tally: Tally;
  active: boolean;
  onReview: () => void;
}

const SHOWN = ["met", "partial", "gap"] as const;

/** How many controls got each mark. There is deliberately no overall score: a single number would suggest a conclusion this tool cannot reach. */
export function Counts({ tally, active, onReview }: Props) {
  return (
    <div className="counts">
      <ul role="list" aria-label="Findings by status">
        {SHOWN.map((status) => (
          <li key={status}>
            <StatusMark status={status} />
            <strong>{tally[status]}</strong>
            <span>{STATUS_LABELS[status]}</span>
          </li>
        ))}
        {tally.error > 0 ? (
          <li>
            <StatusMark status="error" />
            <strong>{tally.error}</strong>
            <span>{STATUS_LABELS.error}</span>
          </li>
        ) : null}
        {active && tally.pending > 0 ? (
          <li>
            <StatusMark status="pending" />
            <strong>{tally.pending}</strong>
            <span>{STATUS_LABELS.pending}</span>
          </li>
        ) : null}
      </ul>
      {tally.review > 0 ? (
        <button type="button" className="btn btn-link" onClick={onReview}>
          {tally.review === 1 ? "1 finding needs review" : `${tally.review} findings need review`}
        </button>
      ) : null}
      <p className="disclaimer">
        These marks describe what the document says. They do not show that a control is carried out, and they are not legal advice.
      </p>
    </div>
  );
}
