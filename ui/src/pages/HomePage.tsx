import { useEffect, useRef } from "react";
import { Legend } from "../components/Legend";
import { ReviewList } from "../components/ReviewList";
import { UploadPanel } from "../components/UploadPanel";
import { hasNavigated, useDocumentTitle } from "../hooks";

export function HomePage() {
  const heading = useRef<HTMLHeadingElement>(null);
  useDocumentTitle("HIPAA policy review");
  useEffect(() => {
    if (hasNavigated()) heading.current?.focus({ preventScroll: true });
  }, []);

  return (
    <>
      <section className="hero">
        <h1 ref={heading} tabIndex={-1}>
          Check a security policy against the HIPAA Security Rule
        </h1>
        <p className="lede">
          Upload a policy and get a finding for each control: what the document covers, what it leaves out, and the passages that show it.
        </p>
      </section>
      <UploadPanel
        onStarted={(id) => {
          window.location.hash = `#/audits/${id}`;
        }}
      />
      <Legend />
      <section className="recent" aria-labelledby="recent-title">
        <h2 id="recent-title">Recent reviews</h2>
        <ReviewList />
      </section>
    </>
  );
}
