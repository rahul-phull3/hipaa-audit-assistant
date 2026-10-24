import type { Filter, StatusFilter, Tally } from "../findings";
import { NO_FILTER, SAFEGUARD_LABELS, SAFEGUARD_ORDER, STATUS_LABELS, isFiltered } from "../findings";
import type { Safeguard } from "../types";
import { StatusMark } from "./StatusMark";

interface Props {
  filter: Filter;
  tally: Tally;
  onChange: (filter: Filter) => void;
  shown: number;
}

const CHIPS: { value: StatusFilter; label: string; mark?: "gap" | "partial" | "met" | "error" }[] = [
  { value: "all", label: "All" },
  { value: "gap", label: STATUS_LABELS.gap, mark: "gap" },
  { value: "partial", label: STATUS_LABELS.partial, mark: "partial" },
  { value: "met", label: STATUS_LABELS.met, mark: "met" },
  { value: "error", label: STATUS_LABELS.error, mark: "error" },
  { value: "review", label: "Needs review" },
];

function countFor(value: StatusFilter, tally: Tally): number {
  if (value === "all") return tally.total;
  if (value === "review") return tally.review;
  return tally[value];
}

export function Filters({ filter, tally, onChange, shown }: Props) {
  return (
    <div className="filters">
      <div className="chips" role="group" aria-label="Show findings by status">
        {CHIPS.filter((c) => c.value === "all" || c.value === filter.status || countFor(c.value, tally) > 0).map((chip) => (
          <button
            key={chip.value}
            type="button"
            className="chip"
            aria-pressed={filter.status === chip.value}
            onClick={() => onChange({ ...filter, status: chip.value })}
          >
            {chip.mark ? <StatusMark status={chip.mark} /> : null}
            <span>{chip.label}</span>
            <span className="chip-count">{countFor(chip.value, tally)}</span>
          </button>
        ))}
      </div>
      <div className="filter-fields">
        <label className="field-inline">
          <span className="visually-hidden">Safeguard</span>
          <select
            value={filter.safeguard}
            onChange={(e) => onChange({ ...filter, safeguard: e.currentTarget.value as Filter["safeguard"] })}
          >
            <option value="all">All safeguards</option>
            {SAFEGUARD_ORDER.map((s: Safeguard) => (
              <option key={s} value={s}>
                {SAFEGUARD_LABELS[s]}
              </option>
            ))}
          </select>
        </label>
        <label className="check">
          <input
            type="checkbox"
            checked={filter.requiredOnly}
            onChange={(e) => onChange({ ...filter, requiredOnly: e.currentTarget.checked })}
          />
          <span>Required controls only</span>
        </label>
        <label className="field-inline grow">
          <span className="visually-hidden">Search findings</span>
          <input
            type="search"
            placeholder="Search titles, citations and quotes"
            value={filter.query}
            onChange={(e) => onChange({ ...filter, query: e.currentTarget.value })}
          />
        </label>
        {isFiltered(filter) ? (
          <button type="button" className="btn btn-quiet" onClick={() => onChange(NO_FILTER)}>
            Clear filters
          </button>
        ) : null}
      </div>
      <p className="filter-status" role="status">
        {isFiltered(filter) ? `Showing ${shown} of ${tally.total} controls` : ""}
      </p>
    </div>
  );
}
