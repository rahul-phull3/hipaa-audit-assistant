import { useMemo } from "react";
import { groupRows } from "../findings";
import type { ControlInfo } from "../types";

interface Props {
  controls: ControlInfo[];
  selected: Set<string>;
  onChange: (next: Set<string>) => void;
}

export function ControlPicker({ controls, selected, onChange }: Props) {
  const groups = useMemo(() => groupRows(controls.map((control) => ({ control, finding: null }))), [controls]);
  const everything = selected.size === controls.length;

  const setMany = (ids: string[], on: boolean) => {
    const next = new Set(selected);
    for (const id of ids) (on ? next.add(id) : next.delete(id));
    onChange(next);
  };

  return (
    <details className="picker">
      <summary>{everything ? `All ${controls.length} controls` : `${selected.size} of ${controls.length} controls`}</summary>
      <div className="picker-actions">
        <button type="button" className="btn btn-link" onClick={() => onChange(new Set(controls.map((c) => c.id)))}>
          Select all
        </button>
        <button type="button" className="btn btn-link" onClick={() => onChange(new Set())}>
          Clear
        </button>
      </div>
      {groups.map((group) => {
        const ids = group.rows.map((r) => r.control.id);
        const chosen = ids.filter((id) => selected.has(id)).length;
        return (
          <fieldset className="picker-group" key={group.safeguard || "other"}>
            <legend>{group.label}</legend>
            <label className="check check-group">
              <input
                type="checkbox"
                checked={chosen === ids.length}
                ref={(node) => {
                  if (node) node.indeterminate = chosen > 0 && chosen < ids.length;
                }}
                onChange={(e) => setMany(ids, e.currentTarget.checked)}
              />
              <span>All {group.label.toLowerCase()}</span>
            </label>
            {group.rows.map(({ control }) => (
              <label className="check" key={control.id}>
                <input
                  type="checkbox"
                  checked={selected.has(control.id)}
                  onChange={(e) => setMany([control.id], e.currentTarget.checked)}
                />
                <span>{control.title}</span>
              </label>
            ))}
          </fieldset>
        );
      })}
    </details>
  );
}
