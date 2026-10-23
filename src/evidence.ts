import { createHash, randomUUID } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { chmod, link, lstat, mkdir, open, unlink } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { toolError, TOOL_VERSION, type ToolError } from "./result.js";
import { redactUrl, type ContentHash, type HashBasis } from "./security.js";

/**
 * Evidence persistence. Off by default; an operator enables it with an absolute
 * directory in RESEARCH_BROWSER_EVIDENCE_DIR. Layout:
 *
 *   <root>/objects/sha256/<hex>     the exact bytes the content hash covers (read-only)
 *   <root>/records/<evidence_id>.json  one record per capture
 *   <root>/tmp/                     staging; empty unless a write was interrupted
 *
 * Objects are content-addressed and never overwritten: a new object is staged in
 * tmp/, fsynced, made read-only and hard-linked into place (link fails if the
 * name exists), then read back and re-hashed. An existing object is re-hashed
 * before it is reused. Records hold the origin only, never the path, query,
 * headers or cookies.
 */

export const EVIDENCE_DIR_ENV = "RESEARCH_BROWSER_EVIDENCE_DIR";

export type EvidenceKind = "http_response_body" | "browser_response_body" | "browser_dom" | "browser_screenshot";

export interface EvidenceMeta {
  kind: EvidenceKind;
  media_type: string;
  basis: HashBasis;
  /** Reduced to its origin before it is written. */
  source_url: string;
  request_id: string;
  captured_at: string;
  session_id?: string;
  http_status?: number;
}

export type EvidenceOutcome =
  | { evidence_status: "disabled"; evidence_persisted: false }
  | { evidence_status: "persisted"; evidence_persisted: true; evidence_id: string; content_hash: ContentHash; deduplicated: boolean }
  | { evidence_status: "failed"; evidence_persisted: false; evidence_error: ToolError };

export interface EvidenceSink {
  /**
   * Persists `bytes`. When `declared` is given it must be the SHA-256 of exactly
   * these bytes under the same basis as `meta.basis`; otherwise nothing is written.
   */
  persist(bytes: Uint8Array, meta: EvidenceMeta, declared?: ContentHash): Promise<EvidenceOutcome>;
}

const DISABLED: EvidenceOutcome = Object.freeze({ evidence_status: "disabled", evidence_persisted: false }) as EvidenceOutcome;

export const NO_EVIDENCE: EvidenceSink = {
  persist: async () => ({ ...DISABLED }) as EvidenceOutcome,
};

export interface FileEvidenceOptions {
  maxObjectBytes: number;
}

export const DEFAULT_FILE_EVIDENCE_OPTIONS: FileEvidenceOptions = {
  maxObjectBytes: 25 * 1024 * 1024,
};

class EvidenceError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

const hexOf = (data: Uint8Array) => createHash("sha256").update(data).digest("hex");

export class FileEvidenceStore implements EvidenceSink {
  private readonly opts: FileEvidenceOptions;
  private ready: Promise<void> | null = null;

  constructor(
    private readonly root: string,
    opts: Partial<FileEvidenceOptions> = {},
  ) {
    if (!isAbsolute(root)) throw new Error(`${EVIDENCE_DIR_ENV} must be an absolute path`);
    this.opts = { ...DEFAULT_FILE_EVIDENCE_OPTIONS, ...opts };
  }

  async persist(bytes: Uint8Array, meta: EvidenceMeta, declared?: ContentHash): Promise<EvidenceOutcome> {
    const fail = (code: string, message: string): EvidenceOutcome => ({ evidence_status: "failed", evidence_persisted: false, evidence_error: toolError("evidence_unavailable", code, message) });
    if (bytes.length > this.opts.maxObjectBytes) return fail("evidence_too_large", "Content exceeds the evidence size limit; nothing was written");
    const value = hexOf(bytes);
    if (declared && (declared.algorithm !== "sha256" || declared.basis !== meta.basis || declared.value !== value)) {
      return fail("evidence_hash_mismatch", "The bytes to persist do not match the declared content hash; nothing was written");
    }
    const content_hash: ContentHash = { algorithm: "sha256", basis: meta.basis, value };
    try {
      await this.ensureLayout();
      const deduplicated = await this.putObject(value, bytes);
      const evidence_id = randomUUID();
      const record = {
        schema_version: 1,
        evidence_id,
        kind: meta.kind,
        content_hash,
        byte_length: bytes.length,
        media_type: meta.media_type,
        object: `objects/sha256/${value}`,
        source_origin: redactUrl(meta.source_url, "origin"),
        request_id: meta.request_id,
        ...(meta.session_id !== undefined ? { session_id: meta.session_id } : {}),
        ...(meta.http_status !== undefined ? { http_status: meta.http_status } : {}),
        captured_at: meta.captured_at,
        tool_version: TOOL_VERSION,
      };
      await this.writeOnce(join(this.root, "records", `${evidence_id}.json`), Buffer.from(`${JSON.stringify(record, null, 2)}\n`), 0o400);
      return { evidence_status: "persisted", evidence_persisted: true, evidence_id, content_hash, deduplicated };
    } catch (err) {
      if (err instanceof EvidenceError) return fail(err.code, err.message);
      // Filesystem messages carry the operator's path; report a fixed message.
      return fail("evidence_write_failed", "Evidence could not be written to the configured store");
    }
  }

  private ensureLayout(): Promise<void> {
    this.ready ??= (async () => {
      for (const dir of [this.root, join(this.root, "objects"), join(this.root, "objects", "sha256"), join(this.root, "records"), join(this.root, "tmp")]) {
        await mkdir(dir, { recursive: true, mode: 0o700 });
        const st = await lstat(dir);
        if (!st.isDirectory()) throw new EvidenceError("evidence_write_failed", "Evidence store layout is not a plain directory tree");
      }
    })().catch((err: unknown) => {
      this.ready = null;
      throw err;
    });
    return this.ready;
  }

  /** Returns true when an identical object already existed. */
  private async putObject(value: string, bytes: Uint8Array): Promise<boolean> {
    const finalPath = join(this.root, "objects", "sha256", value);
    if (await this.exists(finalPath)) {
      await this.verifyObject(finalPath, value);
      return true;
    }
    let created: boolean;
    try {
      await this.writeOnce(finalPath, bytes, 0o400);
      created = true;
    } catch (err) {
      if (!(err instanceof Error && "code" in err && err.code === "EEXIST")) throw err;
      created = false; // a concurrent writer won the race
    }
    // Read back what is on disk now, whoever wrote it.
    await this.verifyObject(finalPath, value);
    return !created;
  }

  private async exists(path: string): Promise<boolean> {
    try {
      await lstat(path);
      return true;
    } catch (err) {
      if (err instanceof Error && "code" in err && err.code === "ENOENT") return false;
      throw err;
    }
  }

  private async verifyObject(path: string, value: string): Promise<void> {
    const st = await lstat(path);
    // lstat, and O_NOFOLLOW below: a symlink planted at an object path is never followed.
    if (!st.isFile()) throw new EvidenceError("evidence_object_corrupt", "Existing evidence object is not a regular file");
    let data: Buffer;
    try {
      const fh = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
      try {
        data = await fh.readFile();
      } finally {
        await fh.close();
      }
    } catch {
      throw new EvidenceError("evidence_object_corrupt", "Existing evidence object could not be read back");
    }
    if (hexOf(data) !== value) throw new EvidenceError("evidence_object_corrupt", "Existing evidence object does not match its content hash");
  }

  /** Stage in tmp/, fsync, set the final mode, then link into place (fails if the name exists). */
  private async writeOnce(finalPath: string, bytes: Uint8Array, mode: number): Promise<void> {
    const staged = join(this.root, "tmp", `${randomUUID()}.tmp`);
    const fh = await open(staged, "wx", 0o600);
    try {
      try {
        await fh.writeFile(bytes);
        await fh.sync();
      } finally {
        await fh.close();
      }
      await chmod(staged, mode);
      await link(staged, finalPath);
    } finally {
      await unlink(staged).catch(() => {});
    }
    await this.syncDir(join(finalPath, ".."));
  }

  private async syncDir(dir: string): Promise<void> {
    try {
      const fh = await open(dir, fsConstants.O_RDONLY);
      try {
        await fh.sync();
      } finally {
        await fh.close();
      }
    } catch {
      // Some filesystems do not support fsync on directories; the file itself is synced.
    }
  }
}

/** Unset or blank: evidence is disabled. Otherwise an absolute directory, or startup fails. */
export function evidenceFromEnv(env: Record<string, string | undefined>): EvidenceSink {
  const dir = env[EVIDENCE_DIR_ENV]?.trim();
  if (!dir) return NO_EVIDENCE;
  return new FileEvidenceStore(dir);
}

