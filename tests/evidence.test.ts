import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, beforeEach, describe, it } from "node:test";
import { EVIDENCE_DIR_ENV, evidenceFromEnv, FileEvidenceStore, NO_EVIDENCE, type EvidenceMeta } from "../src/evidence.js";
import { sha256 } from "../src/security.js";

const roots: string[] = [];
function freshRoot(): string {
  const dir = mkdtempSync(join(tmpdir(), "rbmcp-evidence-"));
  roots.push(dir);
  return join(dir, "store");
}
after(() => {
  for (const r of roots) {
    // Objects are written read-only; make them removable again.
    try {
      chmodTree(r);
    } catch {}
    rmSync(r, { recursive: true, force: true });
  }
});
function chmodTree(dir: string) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      chmodSync(p, 0o700);
      chmodTree(p);
    } else if (e.isFile()) chmodSync(p, 0o600);
  }
}

const meta = (extra: Partial<EvidenceMeta> = {}): EvidenceMeta => ({
  kind: "http_response_body",
  media_type: "text/html",
  basis: "decoded_body_bytes",
  source_url: "https://example.org/private/path?token=s3cret#frag",
  request_id: "11111111-1111-4111-8111-111111111111",
  captured_at: "2026-10-23T00:00:00.000Z",
  ...extra,
});

const hex = (b: Uint8Array | string) => createHash("sha256").update(b).digest("hex");

describe("NO_EVIDENCE", () => {
  it("reports disabled and never claims persistence", async () => {
    const out = await NO_EVIDENCE.persist(Buffer.from("x"), meta());
    assert.deepEqual(out, { evidence_status: "disabled", evidence_persisted: false });
  });
});

describe("FileEvidenceStore", () => {
  let root: string;
  let store: FileEvidenceStore;
  beforeEach(() => {
    root = freshRoot();
    store = new FileEvidenceStore(root);
  });

  it("stores the exact bytes under objects/sha256/<hex> and a record under records/<id>.json", async () => {
    const body = Buffer.from("<html><title>t</title>hello</html>");
    const out = await store.persist(body, meta());
    assert.equal(out.evidence_status, "persisted");
    if (out.evidence_status !== "persisted") return;
    assert.equal(out.evidence_persisted, true);
    assert.equal(out.content_hash.value, hex(body));
    assert.equal(out.content_hash.basis, "decoded_body_bytes");
    assert.equal(out.deduplicated, false);

    const object = join(root, "objects", "sha256", hex(body));
    assert.deepEqual(readFileSync(object), body);
    assert.equal(hex(readFileSync(object)), out.content_hash.value, "stored object hashes to the declared value");

    const record = JSON.parse(readFileSync(join(root, "records", `${out.evidence_id}.json`), "utf8"));
    assert.equal(record.evidence_id, out.evidence_id);
    assert.deepEqual(record.content_hash, out.content_hash);
    assert.equal(record.byte_length, body.length);
    assert.equal(record.object, `objects/sha256/${hex(body)}`);
    assert.equal(record.kind, "http_response_body");
    assert.equal(record.media_type, "text/html");
  });

  it("records only the origin: no path, query, fragment, headers or cookies", async () => {
    const out = await store.persist(Buffer.from("x"), meta());
    assert.equal(out.evidence_status, "persisted");
    if (out.evidence_status !== "persisted") return;
    const raw = readFileSync(join(root, "records", `${out.evidence_id}.json`), "utf8");
    const record = JSON.parse(raw);
    assert.equal(record.source_origin, "https://example.org");
    assert.doesNotMatch(raw, /private|s3cret|token|frag/);
    assert.equal("headers" in record, false);
    assert.equal("cookies" in record, false);
  });

  it("refuses to persist when the declared hash does not match the bytes", async () => {
    const body = Buffer.from("actual bytes");
    const out = await store.persist(body, meta(), sha256("other bytes", "decoded_body_bytes"));
    assert.equal(out.evidence_status, "failed");
    assert.equal(out.evidence_persisted, false);
    if (out.evidence_status !== "failed") return;
    assert.equal(out.evidence_error.code, "evidence_hash_mismatch");
    assert.equal(existsSync(join(root, "objects", "sha256", hex(body))), false);
  });

  it("refuses a declared hash with a different basis", async () => {
    const body = Buffer.from("same bytes");
    const out = await store.persist(body, meta(), sha256(body, "extracted_text_utf8"));
    assert.equal(out.evidence_status, "failed");
    if (out.evidence_status === "failed") assert.equal(out.evidence_error.code, "evidence_hash_mismatch");
  });

  it("deduplicates identical content but writes one record per capture", async () => {
    const body = Buffer.from("same");
    const a = await store.persist(body, meta());
    const b = await store.persist(body, meta());
    assert.equal(a.evidence_status, "persisted");
    assert.equal(b.evidence_status, "persisted");
    if (a.evidence_status !== "persisted" || b.evidence_status !== "persisted") return;
    assert.notEqual(a.evidence_id, b.evidence_id);
    assert.equal(b.deduplicated, true);
    assert.equal(readdirSync(join(root, "records")).length, 2);
    assert.equal(readdirSync(join(root, "objects", "sha256")).length, 1);
  });

  it("never overwrites an existing object: a corrupted object fails verification instead", async () => {
    const body = Buffer.from("original");
    const first = await store.persist(body, meta());
    assert.equal(first.evidence_status, "persisted");
    const object = join(root, "objects", "sha256", hex(body));
    chmodSync(object, 0o600);
    writeFileSync(object, "tampered");
    const second = await store.persist(body, meta());
    assert.equal(second.evidence_status, "failed");
    if (second.evidence_status === "failed") assert.equal(second.evidence_error.code, "evidence_object_corrupt");
    assert.equal(readFileSync(object, "utf8"), "tampered", "the store does not repair or replace objects");
  });

  it("does not follow a symlink planted at the object path", async () => {
    const body = Buffer.from("target");
    const elsewhere = join(root, "..", "elsewhere.txt");
    mkdirSync(join(root, "objects", "sha256"), { recursive: true });
    writeFileSync(elsewhere, "target");
    symlinkSync(elsewhere, join(root, "objects", "sha256", hex(body)));
    const out = await store.persist(body, meta());
    assert.equal(out.evidence_status, "failed");
    if (out.evidence_status === "failed") assert.equal(out.evidence_error.code, "evidence_object_corrupt");
  });

  it("writes objects read-only and directories private", async () => {
    const body = Buffer.from("perm");
    await store.persist(body, meta());
    const object = join(root, "objects", "sha256", hex(body));
    assert.equal(statSync(object).mode & 0o777, 0o400);
    assert.equal(statSync(root).mode & 0o777, 0o700);
    assert.equal(lstatSync(join(root, "records")).mode & 0o777, 0o700);
  });

  it("leaves no temporary files behind", async () => {
    await store.persist(Buffer.from("a"), meta());
    await store.persist(Buffer.from("b"), meta());
    assert.deepEqual(readdirSync(join(root, "tmp")), []);
  });

  it("rejects content over the size limit without writing anything", async () => {
    const small = new FileEvidenceStore(root, { maxObjectBytes: 4 });
    const out = await small.persist(Buffer.from("12345"), meta());
    assert.equal(out.evidence_status, "failed");
    if (out.evidence_status === "failed") assert.equal(out.evidence_error.code, "evidence_too_large");
    assert.equal(existsSync(join(root, "records")) && readdirSync(join(root, "records")).length > 0, false);
  });

  it("reports a write failure instead of claiming persistence, without leaking the path", async () => {
    const blocker = freshRoot();
    mkdirSync(join(blocker, ".."), { recursive: true });
    writeFileSync(blocker, "not a directory");
    const broken = new FileEvidenceStore(blocker);
    const out = await broken.persist(Buffer.from("x"), meta());
    assert.equal(out.evidence_status, "failed");
    assert.equal(out.evidence_persisted, false);
    if (out.evidence_status !== "failed") return;
    assert.equal(out.evidence_error.code, "evidence_write_failed");
    assert.doesNotMatch(out.evidence_error.message, /rbmcp-evidence/);
  });

  it("stores optional session and status fields when given", async () => {
    const out = await store.persist(Buffer.from("png"), meta({ kind: "browser_screenshot", media_type: "image/png", basis: "screenshot_png_bytes", session_id: "s-1", http_status: 200 }));
    assert.equal(out.evidence_status, "persisted");
    if (out.evidence_status !== "persisted") return;
    const record = JSON.parse(readFileSync(join(root, "records", `${out.evidence_id}.json`), "utf8"));
    assert.equal(record.session_id, "s-1");
    assert.equal(record.http_status, 200);
    assert.equal(record.content_hash.basis, "screenshot_png_bytes");
  });
});

describe("evidenceFromEnv", () => {
  it("is disabled when the variable is unset or empty", () => {
    assert.equal(evidenceFromEnv({}), NO_EVIDENCE);
    assert.equal(evidenceFromEnv({ [EVIDENCE_DIR_ENV]: "  " }), NO_EVIDENCE);
  });

  it("requires an absolute path", () => {
    assert.throws(() => evidenceFromEnv({ [EVIDENCE_DIR_ENV]: "relative/dir" }), /absolute/);
  });

  it("returns a file store for an absolute path", () => {
    assert.ok(evidenceFromEnv({ [EVIDENCE_DIR_ENV]: freshRoot() }) instanceof FileEvidenceStore);
  });
});
