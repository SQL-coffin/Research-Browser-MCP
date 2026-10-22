import { randomUUID } from "node:crypto";

export const TOOL_VERSION = "0.1.0";

export type Status =
  | "success"
  | "invalid_input"
  | "policy_denied"
  | "human_verification_required"
  | "blocked"
  | "rate_limited"
  | "provider_unavailable"
  | "timeout"
  | "content_too_large"
  | "extraction_failed"
  | "evidence_unavailable"
  | "internal_error";

export interface ToolError {
  code: string;
  message: string;
  retryable: boolean;
}

const RETRYABLE: ReadonlySet<Status> = new Set(["rate_limited", "provider_unavailable", "timeout"]);

export function toolError(status: Status, code: string, message: string): ToolError {
  return { code, message, retryable: RETRYABLE.has(status) };
}

export function newRequestId(): string {
  return randomUUID();
}

export type AuditLogger = (entry: Record<string, unknown>) => void;

/** Audit lines go to stderr; stdout is reserved for the MCP stdio transport. */
export const stderrAuditLogger: AuditLogger = (entry) => {
  process.stderr.write(`${JSON.stringify({ ts: new Date().toISOString(), tool_version: TOOL_VERSION, ...entry })}\n`);
};
