import { type CSSProperties, type KeyboardEvent, useRef, useState } from "react";
import { type Group, type Row, SAFEGUARD_SHORT, STATUS_LABELS, statusOf } from "../findings";
import { plural } from "../format";
import { StatusMark } from "./StatusMark";

interface Props {
  groups: Group[];
  selectedId: string | null;
  onSelect: (controlId: string) => void;
  /** Play the one-time sweep that introduces a finished review. */
  sweep: boolean;
  /** The review is still running, so a mark settles in when its control finishes. */
  live: boolean;
}

/**
 * Every control in the review as one mark, grouped by safeguard. It shows where the document is thin at a glance, takes the
 * place of a score, fills in while a review runs, and is a way to jump to a finding. It is a single tab stop; the arrow keys
 * move between marks.
 */
export function Strip({ groups, selectedId, onSelect, sweep, live }: Props) {
  const cells = useRef(new Map<string, HTMLButtonElement>());
  const rows = groups.flatMap((g) => g.rows);
  const [active, setActive] = useState<string | null>(null);
  const current = rows.some((r) => r.control.id === active) ? active : (rows[0]?.control.id ?? null);

  const focusAt = (index: number) => {
    const row = rows[Math.max(0, Math.min(rows.length - 1, index))];
    if (!row) return;
    setActive(row.control.id);
    cells.current.get(row.control.id)?.focus();
  };

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const index = rows.findIndex((r) => r.control.id === current);
    const step: Record<string, () => void> = {
      ArrowRight: () => focusAt(index + 1),
      ArrowDown: () => focusAt(index + 1),
      ArrowLeft: () => focusAt(index - 1),
      ArrowUp: () => focusAt(index - 1),
      Home: () => focusAt(0),
      End: () => focusAt(rows.length - 1),
    };
    const move = step[event.key];
    if (move) {
      event.preventDefault();
      move();
    }
  };

  let position = 0;
  return (
    <div className="strip" data-sweep={sweep} data-live={live} role="group" aria-label="All controls in this review, by safeguard" onKeyDown={onKeyDown}>
      {groups.map((group) => (
        <div className="strip-group" key={group.safeguard || "other"} role="group" aria-label={`${group.label}, ${plural(group.rows.length, "control")}`}>
          <div className="strip-cells">
            {group.rows.map((row) => {
              const index = position++;
              return (
                <Cell
                  key={row.control.id}
                  row={row}
                  index={index}
                  selected={row.control.id === selectedId}
                  tabbable={row.control.id === current}
                  register={(node) => {
                    if (node) cells.current.set(row.control.id, node);
                    else cells.current.delete(row.control.id);
                  }}
                  onFocus={() => setActive(row.control.id)}
                  onSelect={() => onSelect(row.control.id)}
                />
              );
            })}
          </div>
          <div className="strip-label" aria-hidden="true">
            {group.safeguard ? SAFEGUARD_SHORT[group.safeguard] : "Other"}
          </div>
        </div>
      ))}
    </div>
  );
}

interface CellProps {
  row: Row;
  index: number;
  selected: boolean;
  tabbable: boolean;
  register: (node: HTMLButtonElement | null) => void;
  onFocus: () => void;
  onSelect: () => void;
}

function Cell({ row, index, selected, tabbable, register, onFocus, onSelect }: CellProps) {
  const status = statusOf(row);
  const label = `${row.control.title}: ${STATUS_LABELS[status].toLowerCase()}`;
  return (
    <button
      type="button"
      className="cell"
      data-status={status}
      data-selected={selected}
      ref={register}
      tabIndex={tabbable ? 0 : -1}
      aria-label={label}
      title={label}
      style={{ "--i": index } as CSSProperties}
      onFocus={onFocus}
      onClick={onSelect}
    >
      <StatusMark key={status} status={status} />
    </button>
  );
}
