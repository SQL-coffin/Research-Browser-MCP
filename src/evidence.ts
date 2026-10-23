import type { ChallengeResult, ContentHash } from "./security.js";
import type { Status } from "./result.js";

// ---------------------------------------------------------------------------
// Evidence persistence: CONTRACT ONLY.
//
// This module fixes the types, configuration surface and failure codes that
// docs/07-evidence-persistence.md describes. The file-system sink is not
// implemented yet: createFileEvidenceStore() returns a store that refuses every
// save, and fetchPublicPage() does not call a store. tests/evidence.test.ts
// states the behaviour the implementation must reach.
// ---------------------------------------------------------------------------

/** Startup configuration. Unset or empty: persistence is off and nothing is written. */
export const EVIDENCE_DIR_ENV = "RESEARCH_BROWSER_EVIDENCE_DIR";

/** Version of the on-disk record layout. Bumped on any incompatible change. */
export const EVIDENCE_SCHEMA_VERSION = 1;

/**
 * One durable evidence record, stored as `records/<evidence_id>.json` under the
 * sink root. Every URL field holds exactly the form the fetch result showed
 * (origin by default; see UrlDisclosure), never the raw request URL.
 */
export interface EvidenceRecord {
  schema_version: typeof EVIDENCE_SCHEMA_VERSION;
  /** Fresh UUID per save; never derived from the URL or the content. */
  evidence_id: string;
  request_id: string;
  tool_version: string;
  source_url: string;
  final_url: string;
  redirect_chain: { url: string; http_status: number; peer_address: string }[];
  retrieved_at: string;
  status: Status;
  http_status: number;
  content_type: string;
  challenge_type: ChallengeResult["challenge_type"];
  /** Same object as the fetch result's content_hash; basis is decoded_body_bytes. */
  content_hash: ContentHash;
  /** Relative to the sink root: `payloads/sha256/<content_hash.value>`. */
  payload_ref: string;
  payload_bytes: number;
  text_truncated: boolean;
  warnings: string[];
}

export type EvidenceFailureCode =
  /** A record with this evidence_id already exists. It is left untouched. */
  | "evidence_exists"
  /** A payload file for this hash exists but its bytes do not hash to it. It is left untouched. */
  | "evidence_payload_mismatch"
  /** Any other storage error (missing root, permissions, disk full, a thrown store). */
  | "evidence_write_failed";

export type EvidenceSaveResult =
  | { ok: true; evidence_id: string; payload_ref: string }
  | { ok: false; code: EvidenceFailureCode };

export interface EvidenceStore {
  /**
   * Persist one record and its payload (the decoded body bytes the hash covers).
   * Must never overwrite an existing record or payload, and must never leave a
   * partially written record at `records/<evidence_id>.json`.
   */
  save(record: EvidenceRecord, payload: Uint8Array): Promise<EvidenceSaveResult>;
}

export class EvidenceConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EvidenceConfigError";
  }
}

/**
 * Reads the sink root from the environment. Unset or empty: undefined, so
 * persistence stays off. A relative path throws EvidenceConfigError, so the
 * server refuses to start. The root directory is never created automatically.
 *
 * NOT IMPLEMENTED: always returns undefined for now.
 */
export function evidenceStoreFromEnv(env: Record<string, string | undefined>): EvidenceStore | undefined {
  void env;
  return undefined;
}

/**
 * File-system sink rooted at an existing absolute directory.
 *
 * NOT IMPLEMENTED: every save reports evidence_write_failed and writes nothing.
 */
export function createFileEvidenceStore(root: string): EvidenceStore {
  void root;
  return { save: async () => ({ ok: false, code: "evidence_write_failed" }) };
}
