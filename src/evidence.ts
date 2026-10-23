import { createHash, randomUUID } from "node:crypto";
import { link, lstat, mkdir, open, readFile, rm, stat } from "node:fs/promises";
import { dirname, isAbsolute, join } from "node:path";
import type { ChallengeResult, ContentHash } from "./security.js";
import type { Status } from "./result.js";

// ---------------------------------------------------------------------------
// Evidence persistence. Contract: docs/07-evidence-persistence.md; required
// behaviour: tests/evidence.test.ts.
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
 */
export function evidenceStoreFromEnv(env: Record<string, string | undefined>): EvidenceStore | undefined {
  const root = (env[EVIDENCE_DIR_ENV] ?? "").trim();
  if (root === "") return undefined;
  // The message names the variable, not its value: the path stays out of logs.
  if (!isAbsolute(root)) throw new EvidenceConfigError(`${EVIDENCE_DIR_ENV} must be an absolute path`);
  return createFileEvidenceStore(root);
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SHA256_HEX = /^[0-9a-f]{64}$/;

const sha256Hex = (data: Uint8Array) => createHash("sha256").update(data).digest("hex");
const hasCode = (err: unknown, code: string) => err instanceof Error && "code" in err && err.code === code;

/** Creates one directory level with mode 0700; never creates parents, so a missing root stays missing. */
async function ensureDir(path: string): Promise<void> {
  try {
    await mkdir(path, { mode: 0o700 });
  } catch (err) {
    if (!hasCode(err, "EEXIST")) throw err;
    if (!(await stat(path)).isDirectory()) throw new Error("not a directory");
  }
}

/**
 * Writes `data` to a fresh temporary file next to `target`, flushes it, then
 * hard-links it into place. link() fails with EEXIST instead of replacing, so
 * the target is either absent or complete, and an existing one is never touched.
 * Returns false when the target already exists.
 */
async function writeNew(target: string, data: Uint8Array | string): Promise<boolean> {
  const tmp = join(dirname(target), `.tmp-${randomUUID()}`);
  try {
    const fh = await open(tmp, "wx", 0o600);
    try {
      await fh.writeFile(data);
      await fh.sync();
    } finally {
      await fh.close();
    }
    try {
      await link(tmp, target);
      return true;
    } catch (err) {
      if (hasCode(err, "EEXIST")) return false;
      throw err;
    }
  } finally {
    await rm(tmp, { force: true });
  }
}

/**
 * File-system sink rooted at an existing absolute directory. Layout, modes and
 * failure codes: docs/07-evidence-persistence.md. Storage errors become
 * evidence_write_failed; their text (paths, OS messages) never leaves here.
 */
export function createFileEvidenceStore(root: string): EvidenceStore {
  const recordsDir = join(root, "records");
  const payloadsDir = join(root, "payloads", "sha256");

  return {
    async save(record, payload) {
      const hex = record.content_hash.value;
      // Names are built only from a UUID and a hash; anything else could steer the path.
      if (!UUID.test(record.evidence_id) || !SHA256_HEX.test(hex)) return { ok: false, code: "evidence_write_failed" };
      if (record.payload_ref !== `payloads/sha256/${hex}` || sha256Hex(payload) !== hex) return { ok: false, code: "evidence_write_failed" };
      const recordPath = join(recordsDir, `${record.evidence_id}.json`);
      const payloadPath = join(payloadsDir, hex);

      try {
        if (!(await stat(root)).isDirectory()) return { ok: false, code: "evidence_write_failed" };
        await ensureDir(recordsDir);
        await ensureDir(join(root, "payloads"));
        await ensureDir(payloadsDir);

        // Checked first so a clashing save adds no payload either; link() below still guards the race.
        if (await exists(recordPath)) return { ok: false, code: "evidence_exists" };

        // Content-addressed: reuse an existing payload only if its bytes really hash to its name.
        if (!(await writeNew(payloadPath, payload)) && sha256Hex(await readFile(payloadPath)) !== hex) {
          return { ok: false, code: "evidence_payload_mismatch" };
        }

        if (!(await writeNew(recordPath, `${JSON.stringify(record, null, 2)}\n`))) return { ok: false, code: "evidence_exists" };
        return { ok: true, evidence_id: record.evidence_id, payload_ref: record.payload_ref };
      } catch {
        return { ok: false, code: "evidence_write_failed" };
      }
    },
  };
}

async function exists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (err) {
    if (hasCode(err, "ENOENT")) return false;
    throw err;
  }
}
