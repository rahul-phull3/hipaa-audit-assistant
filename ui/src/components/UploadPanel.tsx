import { type DragEvent, type FormEvent, useEffect, useRef, useState } from "react";
import { useApp } from "../app-context";
import { toApiError } from "../api";
import { formatBytes } from "../format";
import { ControlPicker } from "./ControlPicker";

const EXTENSIONS = [".pdf", ".docx", ".txt", ".md", ".markdown"];

/** The problem with a chosen file, in plain words, or null when it can go ahead. The server checks again. */
export function checkFile(file: File, maxMb: number): string | null {
  const name = file.name.toLowerCase();
  if (!EXTENSIONS.some((ext) => name.endsWith(ext))) return "Choose a PDF, DOCX, TXT or Markdown file.";
  if (file.size === 0) return "That file is empty.";
  if (file.size > maxMb * 1024 * 1024) return `That file is ${formatBytes(file.size)}. The limit is ${maxMb} MB.`;
  return null;
}

export function UploadPanel({ onStarted }: { onStarted: (id: string) => void }) {
  const { api, server, catalog, requireKey } = useApp();
  const [file, setFile] = useState<File | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [dragging, setDragging] = useState(false);
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const maxMb = server?.limits.max_upload_mb ?? 10;
  const ready = server ? server.backend.ready : true;

  useEffect(() => {
    if (catalog) setSelected(new Set(catalog.controls.map((c) => c.id)));
  }, [catalog]);

  const choose = (candidate: File | undefined) => {
    if (!candidate) return;
    const issue = checkFile(candidate, maxMb);
    setProblem(issue);
    setFile(issue ? null : candidate);
  };

  const onDrop = (event: DragEvent) => {
    event.preventDefault();
    setDragging(false);
    choose(event.dataTransfer.files[0]);
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!file || !catalog || busy) return;
    setBusy(true);
    setProblem(null);
    try {
      const everything = selected.size === catalog.controls.length;
      const audit = await api.createAudit(file, everything ? undefined : [...selected]);
      onStarted(audit.id);
    } catch (caught) {
      const failure = toApiError(caught);
      if (failure.unauthorized) requireKey();
      setProblem(failure.message);
      setBusy(false);
    }
  };

  const nothingSelected = catalog !== null && selected.size === 0;
  const isModel = server?.backend.is_ai_model ?? false;

  return (
    <form className="upload" onSubmit={submit}>
      <div
        className="drop"
        data-active={dragging}
        data-filled={file !== null}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
      >
        {file ? (
          <>
            <p className="drop-name">{file.name}</p>
            <p className="drop-hint">{formatBytes(file.size)}</p>
            <button
              type="button"
              className="btn btn-quiet"
              onClick={() => {
                setFile(null);
                if (input.current) input.current.value = "";
              }}
            >
              Choose a different file
            </button>
          </>
        ) : (
          <>
            <p className="drop-title">Drop a policy here</p>
            <p className="drop-hint">PDF, DOCX, TXT or Markdown, up to {maxMb} MB</p>
            <label className="btn btn-secondary file-button">
              <input
                ref={input}
                type="file"
                className="visually-hidden"
                accept={EXTENSIONS.join(",")}
                onChange={(e) => choose(e.currentTarget.files?.[0])}
              />
              Choose a file
            </label>
          </>
        )}
      </div>

      {catalog ? <ControlPicker controls={catalog.controls} selected={selected} onChange={setSelected} /> : null}

      {problem ? (
        <p className="inline-error" role="alert">
          {problem}
        </p>
      ) : null}
      {nothingSelected ? <p className="inline-error">Choose at least one control to review.</p> : null}

      <div className="upload-actions">
        <button type="submit" className="btn btn-primary" disabled={!file || !ready || busy || nothingSelected || !catalog}>
          {busy ? "Starting the review" : "Start review"}
        </button>
      </div>

      <p className="privacy">
        {isModel
          ? "Passages from your document are sent to the Anthropic API to be assessed. Do not upload documents that contain patient information."
          : "Nothing leaves this server in offline mode, and no AI model reads the document."}
      </p>
    </form>
  );
}
