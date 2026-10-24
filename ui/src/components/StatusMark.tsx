import type { ReactNode } from "react";
import type { RowStatus } from "../findings";

/**
 * One mark per status. They differ in shape as well as colour (a filled square with a tick, a half-filled square, an empty
 * square with a dash, a slashed dashed square, a dotted square for a control still waiting), so colour is never the only signal.
 */
export function StatusMark({ status }: { status: RowStatus }) {
  return (
    <svg className="mark" data-status={status} viewBox="0 0 16 16" aria-hidden="true" focusable="false">
      {SHAPES[status]}
    </svg>
  );
}

const BOX = { x: 1.75, y: 1.75, width: 12.5, height: 12.5, rx: 2.5 };

const SHAPES: Record<RowStatus, ReactNode> = {
  met: (
    <>
      <rect x="1" y="1" width="14" height="14" rx="3" fill="currentColor" />
      <path
        d="M4.6 8.5l2.3 2.3 4.5-5"
        fill="none"
        stroke="var(--mark-tick)"
        strokeWidth="1.9"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </>
  ),
  partial: (
    <>
      <path d="M4.25 1.75H8v12.5H4.25a2.5 2.5 0 0 1-2.5-2.5v-7.5a2.5 2.5 0 0 1 2.5-2.5z" fill="currentColor" />
      <rect {...BOX} fill="none" stroke="currentColor" strokeWidth="1.5" />
    </>
  ),
  gap: (
    <>
      <rect {...BOX} fill="none" stroke="currentColor" strokeWidth="1.6" />
      <path d="M5.2 8h5.6" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" />
    </>
  ),
  error: (
    <>
      <rect {...BOX} fill="none" stroke="currentColor" strokeWidth="1.5" strokeDasharray="2.6 2" />
      <path d="M5 11l6-6" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" />
    </>
  ),
  pending: (
    <rect {...BOX} fill="none" stroke="currentColor" strokeWidth="1.5" strokeDasharray="0.1 2.7" strokeLinecap="round" />
  ),
};
