import { STATUS_HELP, STATUS_LABELS } from "../findings";
import { StatusMark } from "./StatusMark";

const ORDER = ["met", "partial", "gap", "error"] as const;

export function Legend() {
  return (
    <section className="legend" aria-labelledby="legend-title">
      <h2 id="legend-title">How to read a finding</h2>
      <dl>
        {ORDER.map((status) => (
          <div key={status}>
            <dt>
              <StatusMark status={status} />
              {STATUS_LABELS[status]}
            </dt>
            <dd>{STATUS_HELP[status]}</dd>
          </div>
        ))}
      </dl>
      <p className="legend-note">
        A finding describes what the document says. It does not show that a control is carried out, and it is not legal advice.
        Every quote is checked against the document before it is shown.
      </p>
    </section>
  );
}
