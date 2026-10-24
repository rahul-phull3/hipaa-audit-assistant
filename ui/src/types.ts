// The shapes the HTTP API returns. They mirror src/hipaa_audit/api and service.py.

export type AuditStatus = "queued" | "running" | "completed" | "failed" | "cancelled";
export type Status = "met" | "partial" | "gap";
export type FindingStatus = Status | "error";
export type Safeguard = "administrative" | "physical" | "technical" | "organizational" | "documentation";
export type Requirement = "required" | "addressable";

export interface Usage {
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_creation_tokens: number;
}

export interface SafeguardCounts {
  met: number;
  partial: number;
  gap: number;
  error: number;
  total: number;
}

export interface AuditSummary {
  assessed: number;
  met: number;
  partial: number;
  gap: number;
  error: number;
  needs_review: number;
  by_safeguard: Record<string, SafeguardCounts>;
}

export interface AuditRecord {
  id: string;
  filename: string;
  sha256: string;
  size_bytes: number;
  pages: number | null;
  status: AuditStatus;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  backend: string;
  embedder: string;
  catalog_version: string;
  prompt_version: string;
  control_ids: string[];
  total_controls: number;
  done_controls: number;
  chunk_count: number;
  usage: Usage;
  error: string | null;
}

export interface Audit extends AuditRecord {
  summary: AuditSummary;
}

export interface AuditListItem extends AuditRecord {
  counts: Partial<Record<FindingStatus, number>>;
}

export interface ControlSummary {
  id: string;
  citation: string;
  title: string;
  safeguard: Safeguard | "";
  standard: string;
  requirement: Requirement | "";
}

export interface ControlInfo extends ControlSummary {
  expectation: string;
  elements: string[];
}

export interface Catalog {
  version: string;
  regulation: string;
  rule_status: string;
  notes: string[];
  flag_labels: Record<string, string>;
  controls: ControlInfo[];
}

export interface Evidence {
  chunk_id: string;
  quote: string;
  page: number | null;
  section: string;
}

export interface Finding {
  status: FindingStatus;
  rationale: string;
  evidence: Evidence[];
  missing_elements: string[];
  confidence: number;
  flags: string[];
  retrieved_chunk_ids: string[];
  model: string;
  from_cache: boolean;
  control: ControlSummary;
  needs_review: boolean;
}

export interface Passage {
  id: string;
  page: number | null;
  section: string;
  text: string;
}

export interface PassageContext extends Passage {
  previous: Passage | null;
  next: Passage | null;
}

export interface ServerStatus {
  status: "ok" | "degraded";
  version: string;
  backend: { ready: boolean; name: string | null; is_ai_model: boolean; error: string | null };
  embedder: string;
  catalog: { version: string; controls: number };
  limits: { max_upload_mb: number; max_pages: number };
  active_audits: number;
}
