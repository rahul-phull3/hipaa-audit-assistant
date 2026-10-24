import type { ReactNode } from "react";

interface Props {
  tone: "info" | "warning" | "error";
  title?: string;
  children: ReactNode;
  actions?: ReactNode;
}

/** A message that sits in the page flow. Errors are announced at once; the rest are read in order. */
export function Notice({ tone, title, children, actions }: Props) {
  return (
    <div className="notice" data-tone={tone} role={tone === "error" ? "alert" : "note"}>
      <div className="notice-text">
        {title ? <p className="notice-title">{title}</p> : null}
        <div className="notice-body">{children}</div>
      </div>
      {actions ? <div className="notice-actions">{actions}</div> : null}
    </div>
  );
}
