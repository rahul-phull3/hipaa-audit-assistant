import { type MouseEvent, useCallback, useEffect, useMemo, useState } from "react";
import { Api, type ApiError, toApiError } from "./api";
import { AppContext, type AppState } from "./app-context";
import { ApiKeyForm } from "./components/ApiKeyForm";
import { Notice } from "./components/Notice";
import { describeBackend } from "./format";
import { useApiKey, useRoute } from "./hooks";
import { HomePage } from "./pages/HomePage";
import { ReviewPage } from "./pages/ReviewPage";
import type { Catalog, ServerStatus } from "./types";

/** The address of a page is its hash, so the skip link must not follow its own href: it moves focus and leaves the route alone. */
function skipToContent(event: MouseEvent<HTMLAnchorElement>) {
  event.preventDefault();
  document.getElementById("main")?.focus();
}

export function App() {
  const apiKey = useApiKey();
  const api = useMemo(() => new Api({ getKey: apiKey.read }), [apiKey.read]);
  const route = useRoute();
  const [server, setServer] = useState<ServerStatus | null>(null);
  const [catalog, setCatalog] = useState<Catalog | null>(null);
  const [loadError, setLoadError] = useState<ApiError | null>(null);
  const [keyNeeded, setKeyNeeded] = useState(false);
  const [keyPanel, setKeyPanel] = useState(false);
  const [attempt, setAttempt] = useState(0);

  const requireKey = useCallback(() => {
    setKeyNeeded(true);
    setKeyPanel(true);
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void (async () => {
      try {
        const [status, controls] = await Promise.all([api.status(controller.signal), api.catalog(controller.signal)]);
        setServer(status);
        setCatalog(controls);
        setLoadError(null);
        setKeyNeeded(false);
      } catch (caught) {
        if (controller.signal.aborted) return;
        const failure = toApiError(caught);
        if (failure.unauthorized) requireKey();
        else setLoadError(failure);
      }
    })();
    return () => controller.abort();
  }, [api, attempt, requireKey]);

  const state = useMemo<AppState>(() => ({ api, server, catalog, requireKey }), [api, server, catalog, requireKey]);
  const backend = server?.backend;

  return (
    <AppContext.Provider value={state}>
      <a className="skip-link" href="#main" onClick={skipToContent}>
        Skip to the content
      </a>
      <header className="app-header">
        <div className="wrap bar">
          <a className="brand" href="#/">
            <BrandMark />
            <span>HIPAA policy review</span>
          </a>
          <div className="header-tools">
            {backend?.ready && backend.name ? (
              <span className="reviewer">Reviewer: {describeBackend(backend.name).label}</span>
            ) : null}
            <button
              type="button"
              className="btn btn-quiet"
              aria-expanded={keyPanel}
              aria-controls="key-panel"
              onClick={() => setKeyPanel((open) => !open)}
            >
              API key
            </button>
          </div>
        </div>
        {keyPanel ? (
          <div className="wrap key-panel" id="key-panel">
            <p>
              {keyNeeded
                ? apiKey.key
                  ? "The server did not accept the saved key. Enter the right one to continue."
                  : "This server needs an API key before it will answer. Enter the key your administrator set."
                : "Only needed when the server was started with an API key. It is kept in this tab and forgotten when you close it."}
            </p>
            <ApiKeyForm
              hasKey={apiKey.key !== null}
              onSave={(value) => {
                apiKey.save(value);
                setKeyNeeded(false);
                setAttempt((n) => n + 1);
              }}
              onForget={() => {
                apiKey.forget();
                setAttempt((n) => n + 1);
              }}
            />
          </div>
        ) : null}
      </header>

      <main id="main" className="wrap" tabIndex={-1}>
        {loadError ? (
          <Notice
            tone="error"
            title="Cannot load the application data"
            actions={
              <button type="button" className="btn btn-secondary" onClick={() => setAttempt((n) => n + 1)}>
                Try again
              </button>
            }
          >
            {loadError.message}
          </Notice>
        ) : null}
        {keyNeeded && !keyPanel ? (
          <Notice tone="warning" title="This server needs an API key">
            Open the API key panel at the top of the page and enter it.
          </Notice>
        ) : null}
        {server && route.name === "home" ? <BackendNotice server={server} /> : null}
        {keyNeeded || loadError ? null : route.name === "audit" ? <ReviewPage key={route.id} id={route.id} /> : <HomePage />}
      </main>

      <footer className="wrap app-footer">
        <p>
          This tool helps a person review a policy document. It does not certify HIPAA compliance.
          {catalog ? ` Control catalog ${catalog.version}.` : ""}
          {server ? ` Version ${server.version}.` : ""}
        </p>
      </footer>
    </AppContext.Provider>
  );
}

function BackendNotice({ server }: { server: ServerStatus }) {
  if (server.status === "degraded") {
    return (
      <Notice tone="error" title="The database is not responding">
        Reviews cannot be saved or shown until it is back. Check the server's log.
      </Notice>
    );
  }
  if (!server.backend.ready) {
    return (
      <Notice tone="error" title="The reviewer is not ready">
        {server.backend.error ?? "No reviewer is configured."} Reviews cannot start until this is fixed.
      </Notice>
    );
  }
  if (!server.backend.is_ai_model) {
    return (
      <Notice tone="warning" title="Offline keyword matching is on">
        No AI model will read your document. Findings show where the policy uses the words each control expects, so treat them as
        pointers to check by hand. Set an Anthropic API key on the server for a full review.
      </Notice>
    );
  }
  return null;
}

/** Three marks in a row, the same ones a review uses: met, partial, gap. */
function BrandMark() {
  return (
    <svg className="brand-mark" viewBox="0 0 44 14" aria-hidden="true" focusable="false">
      <rect x="0.75" y="0.75" width="12.5" height="12.5" rx="2.5" fill="currentColor" />
      <path d="M3.6 7.3l2.2 2.2 4-4.4" fill="none" stroke="var(--paper)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M18.5 0.75H22v12.5h-3.5a2.5 2.5 0 0 1-2.5-2.5v-7.5a2.5 2.5 0 0 1 2.5-2.5z" fill="currentColor" />
      <rect x="16.75" y="0.75" width="12.5" height="12.5" rx="2.5" fill="none" stroke="currentColor" strokeWidth="1.5" />
      <rect x="31.75" y="0.75" width="12.5" height="12.5" rx="2.5" fill="none" stroke="currentColor" strokeWidth="1.5" />
      <path d="M35.3 7h5.4" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
    </svg>
  );
}
