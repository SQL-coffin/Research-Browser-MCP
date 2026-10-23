import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { after, afterEach, before, describe, it } from "node:test";
import zlib from "node:zlib";
import {
  createFileEvidenceStore,
  EVIDENCE_DIR_ENV,
  EVIDENCE_SCHEMA_VERSION,
  EvidenceConfigError,
  evidenceStoreFromEnv,
  type EvidenceRecord,
  type EvidenceStore,
} from "../src/evidence.js";
import { DEFAULT_FETCH_POLICY, fetchPublicPage, type FetchDeps, type FetchPolicy, type FetchResult, type FetchSuccess } from "../src/fetcher.js";
import { classifyAddress, parseHostAllowlist, type UrlDisclosure } from "../src/security.js";

// Contract: docs/07-evidence-persistence.md. These tests describe the required
// behaviour; the storage logic is not implemented yet, so most of them fail.

// ---------------------------------------------------------------------------
// Fixtures: a local HTTP server, fake DNS, and a temporary sink root per test.
// ---------------------------------------------------------------------------

type Handler = (req: http.IncomingMessage, res: http.ServerResponse) => void;
const routes = new Map<string, Handler>();
let server: http.Server;
let port: number;

const fixtureOnly = (ip: string) => (ip === "127.0.0.1" ? ({ allowed: true } as const) : classifyAddress(ip));

function policy(overrides: Partial<FetchPolicy> = {}): FetchPolicy {
  return {
    ...DEFAULT_FETCH_POLICY,
    allowedSchemes: new Set(["http:", "https:"]),
    allowedPorts: new Set([port]),
    allowedHosts: parseHostAllowlist("fixture.test private.test"),
    isAddressAllowed: fixtureOnly,
    totalTimeoutMs: 3_000,
    connectTimeoutMs: 1_000,
    ...overrides,
  };
}

const logs: Record<string, unknown>[] = [];
function deps(evidence?: EvidenceStore): FetchDeps {
  return {
    resolve: async (host) => {
      if (host === "fixture.test") return [{ address: "127.0.0.1", family: 4 }];
      if (host === "private.test") return [{ address: "10.0.0.7", family: 4 }];
      throw new Error("ENOTFOUND");
    },
    log: (e) => logs.push(e),
    now: () => new Date("2026-10-23T00:00:00Z"),
    ...(evidence ? { evidence } : {}),
  };
}

const url = (path: string, host = "fixture.test") => `http://${host}:${port}${path}`;
const origin = () => `http://fixture.test:${port}`;

function html(body: string | (() => string), status = 200): Handler {
  return (_req, res) => {
    res.writeHead(status, { "content-type": "text/html; charset=utf-8" });
    res.end(typeof body === "function" ? body() : body);
  };
}

before(async () => {
  server = http.createServer((req, res) => {
    const handler = routes.get((req.url ?? "").split("?")[0]!);
    if (handler) handler(req, res);
    else {
      res.writeHead(404, { "content-type": "text/plain" });
      res.end("not found");
    }
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as AddressInfo).port;
});

after(() => {
  server.closeAllConnections();
  server.close();
});

const roots: string[] = [];
function newRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "rb-evidence-"));
  roots.push(root);
  return root;
}
afterEach(() => {
  logs.length = 0;
  for (const r of roots.splice(0)) rmSync(r, { recursive: true, force: true });
});

/** Every file under root, as root-relative paths with forward slashes. */
function filesUnder(root: string): string[] {
  if (!existsSync(root)) return [];
  return readdirSync(root, { recursive: true, withFileTypes: true })
    .filter((d) => d.isFile())
    .map((d) => relative(root, join(d.parentPath, d.name)).split("\\").join("/"))
    .sort();
}

const sha256Hex = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");
const readRecord = (root: string, id: string): EvidenceRecord => JSON.parse(readFileSync(join(root, "records", `${id}.json`), "utf8")) as EvidenceRecord;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function asSuccess(r: FetchResult): FetchSuccess {
  assert.ok("extracted_text" in r, `expected a fetched page, got ${JSON.stringify(r)}`);
  return r;
}

/** A valid record for direct store tests. */
function sampleRecord(payload: Uint8Array, overrides: Partial<EvidenceRecord> = {}): EvidenceRecord {
  const hex = sha256Hex(payload);
  return {
    schema_version: EVIDENCE_SCHEMA_VERSION,
    evidence_id: randomUUID(),
    request_id: randomUUID(),
    tool_version: "0.1.0",
    source_url: "https://example.test",
    final_url: "https://example.test",
    redirect_chain: [],
    retrieved_at: "2026-10-23T00:00:00.000Z",
    status: "success",
    http_status: 200,
    content_type: "text/html",
    challenge_type: "none",
    content_hash: { algorithm: "sha256", basis: "decoded_body_bytes", value: hex },
    payload_ref: `payloads/sha256/${hex}`,
    payload_bytes: payload.byteLength,
    text_truncated: false,
    warnings: [],
    ...overrides,
  };
}

routes.set("/page", html("<html><head><title>Evidence</title></head><body><p>Stable body.</p></body></html>"));

// ---------------------------------------------------------------------------
// 1. Off by default
// ---------------------------------------------------------------------------

describe("evidence persistence is off by default", () => {
  it("has no store when the variable is unset or empty", () => {
    assert.equal(evidenceStoreFromEnv({}), undefined);
    assert.equal(evidenceStoreFromEnv({ [EVIDENCE_DIR_ENV]: "" }), undefined);
  });

  it("refuses a relative root so the server will not start", () => {
    for (const value of ["evidence", "./evidence", "../evidence"]) {
      assert.throws(() => evidenceStoreFromEnv({ [EVIDENCE_DIR_ENV]: value }), EvidenceConfigError, value);
    }
  });

  it("builds a store from an absolute root without creating anything", () => {
    const root = newRoot();
    assert.ok(evidenceStoreFromEnv({ [EVIDENCE_DIR_ENV]: root }), "absolute root yields a store");
    assert.deepEqual(readdirSync(root), []);
    const missing = join(root, "not-created");
    assert.ok(evidenceStoreFromEnv({ [EVIDENCE_DIR_ENV]: missing }));
    assert.equal(existsSync(missing), false, "the root is never created at startup");
  });

  it("returns today's result shape when no store is configured", async () => {
    const r = asSuccess(await fetchPublicPage(url("/page"), policy(), deps()));
    assert.equal(r.status, "success");
    assert.equal(r.evidence_persisted, false);
    assert.equal("evidence_id" in r, false);
    assert.equal("payload_ref" in r, false);
    assert.equal(r.error, undefined);
    assert.equal(logs.some((l) => l.event === "evidence"), false);
  });
});

// ---------------------------------------------------------------------------
// 2. Successful save
// ---------------------------------------------------------------------------

describe("successful save", () => {
  it("writes one record and one payload, and reports them in the result", async () => {
    const root = newRoot();
    const r = asSuccess(await fetchPublicPage(url("/page"), policy(), deps(createFileEvidenceStore(root))));
    assert.equal(r.status, "success");
    assert.equal(r.evidence_persisted, true);
    assert.match(r.evidence_id ?? "", UUID);
    assert.notEqual(r.evidence_id, r.request_id);
    assert.equal(r.payload_ref, `payloads/sha256/${r.content_hash.value}`);
    assert.deepEqual(filesUnder(root), [r.payload_ref, `records/${r.evidence_id}.json`].sort());
  });

  it("stores a record whose fields equal the returned result", async () => {
    const root = newRoot();
    const r = asSuccess(await fetchPublicPage(url("/page"), policy(), deps(createFileEvidenceStore(root))));
    assert.equal(r.evidence_persisted, true);
    const rec = readRecord(root, r.evidence_id!);
    assert.equal(rec.schema_version, 1);
    assert.equal(rec.evidence_id, r.evidence_id);
    assert.equal(rec.request_id, r.request_id);
    assert.equal(rec.tool_version, r.tool_version);
    assert.equal(rec.source_url, r.source_url);
    assert.equal(rec.final_url, r.final_url);
    assert.deepEqual(rec.redirect_chain, r.redirect_chain);
    assert.equal(rec.retrieved_at, "2026-10-23T00:00:00.000Z");
    assert.equal(rec.status, "success");
    assert.equal(rec.http_status, 200);
    assert.equal(rec.content_type, "text/html");
    assert.equal(rec.challenge_type, "none");
    assert.deepEqual(rec.content_hash, r.content_hash);
    assert.equal(rec.payload_ref, r.payload_ref);
    assert.equal(rec.text_truncated, false);
    assert.deepEqual(rec.warnings, r.warnings);
    assert.equal("extracted_text" in rec, false, "extracted text is not stored");
  });

  it("creates private directories and files", { skip: process.platform === "win32" }, async () => {
    const root = newRoot();
    const r = asSuccess(await fetchPublicPage(url("/page"), policy(), deps(createFileEvidenceStore(root))));
    assert.equal(r.evidence_persisted, true);
    const mode = (p: string) => statSync(join(root, p)).mode & 0o777;
    assert.equal(mode("records"), 0o700);
    assert.equal(mode("payloads/sha256"), 0o700);
    assert.equal(mode(`records/${r.evidence_id}.json`), 0o600);
    assert.equal(mode(r.payload_ref!), 0o600);
  });

  it("logs one evidence line without URLs or paths", async () => {
    const root = newRoot();
    const r = asSuccess(await fetchPublicPage(url("/page?token=LOGSECRET"), policy(), deps(createFileEvidenceStore(root))));
    const lines = logs.filter((l) => l.event === "evidence");
    assert.deepEqual(lines, [{ event: "evidence", request_id: r.request_id, evidence_id: r.evidence_id, outcome: "saved" }]);
    const text = JSON.stringify(lines);
    assert.ok(!text.includes(root) && !text.includes("fixture.test") && !text.includes("LOGSECRET"));
  });
});

// ---------------------------------------------------------------------------
// 3. Hash consistency
// ---------------------------------------------------------------------------

describe("hash consistency", () => {
  it("stores exactly the bytes content_hash covers", async () => {
    const root = newRoot();
    const r = asSuccess(await fetchPublicPage(url("/page"), policy(), deps(createFileEvidenceStore(root))));
    assert.equal(r.evidence_persisted, true);
    assert.equal(r.content_hash.basis, "decoded_body_bytes");
    const payload = readFileSync(join(root, r.payload_ref!));
    assert.equal(sha256Hex(payload), r.content_hash.value);
    assert.equal(readRecord(root, r.evidence_id!).payload_bytes, payload.byteLength);
  });

  it("stores the decoded body, not the gzip bytes on the wire", async () => {
    const plain = Buffer.from("<html><body>compressed evidence</body></html>");
    routes.set("/gz", (_req, res) => {
      res.writeHead(200, { "content-type": "text/html", "content-encoding": "gzip" });
      res.end(zlib.gzipSync(plain));
    });
    const root = newRoot();
    const r = asSuccess(await fetchPublicPage(url("/gz"), policy(), deps(createFileEvidenceStore(root))));
    assert.equal(r.evidence_persisted, true);
    assert.deepEqual(readFileSync(join(root, r.payload_ref!)), plain);
    assert.equal(r.content_hash.value, sha256Hex(plain));
  });

  it("stores the full body when extracted text was truncated", async () => {
    const body = `<p>${"word ".repeat(500)}</p>`;
    routes.set("/long", html(body));
    const root = newRoot();
    const r = asSuccess(await fetchPublicPage(url("/long"), policy({ maxTextChars: 100 }), deps(createFileEvidenceStore(root))));
    assert.equal(r.text_truncated, true);
    assert.equal(r.evidence_persisted, true);
    assert.equal(readFileSync(join(root, r.payload_ref!), "utf8"), body);
    assert.equal(readRecord(root, r.evidence_id!).text_truncated, true);
  });
});

// ---------------------------------------------------------------------------
// 4. Append-only, no overwrite
// ---------------------------------------------------------------------------

describe("no overwrite", () => {
  it("keeps both records when the same URL changes between fetches (RB-17)", async () => {
    let n = 0;
    routes.set("/changing", html(() => `<p>version ${++n}</p>`));
    const root = newRoot();
    const store = createFileEvidenceStore(root);
    const a = asSuccess(await fetchPublicPage(url("/changing"), policy(), deps(store)));
    const b = asSuccess(await fetchPublicPage(url("/changing"), policy(), deps(store)));
    assert.ok(a.evidence_persisted && b.evidence_persisted);
    assert.notEqual(a.evidence_id, b.evidence_id);
    assert.notEqual(a.content_hash.value, b.content_hash.value);
    assert.equal(filesUnder(root).length, 4);
    assert.equal(readFileSync(join(root, a.payload_ref!), "utf8"), "<p>version 1</p>");
    assert.equal(readFileSync(join(root, b.payload_ref!), "utf8"), "<p>version 2</p>");
  });

  it("shares one payload between records of identical bytes", async () => {
    const root = newRoot();
    const store = createFileEvidenceStore(root);
    const a = asSuccess(await fetchPublicPage(url("/page"), policy(), deps(store)));
    const b = asSuccess(await fetchPublicPage(url("/page"), policy(), deps(store)));
    assert.ok(a.evidence_persisted && b.evidence_persisted);
    assert.notEqual(a.evidence_id, b.evidence_id);
    assert.equal(a.payload_ref, b.payload_ref);
    assert.equal(filesUnder(root).length, 3);
  });

  it("refuses to overwrite an existing record", async () => {
    const root = newRoot();
    const store = createFileEvidenceStore(root);
    const payload = Buffer.from("first");
    const rec = sampleRecord(payload);
    assert.deepEqual(await store.save(rec, payload), { ok: true, evidence_id: rec.evidence_id, payload_ref: rec.payload_ref });
    const recordPath = join(root, "records", `${rec.evidence_id}.json`);
    const before = readFileSync(recordPath);
    const filesBefore = filesUnder(root);

    const other = Buffer.from("second");
    const clash = sampleRecord(other, { evidence_id: rec.evidence_id });
    assert.deepEqual(await store.save(clash, other), { ok: false, code: "evidence_exists" });
    assert.deepEqual(readFileSync(recordPath), before, "existing record is byte-identical");
    assert.deepEqual(filesUnder(root), filesBefore, "no new payload or temporary file left behind");
  });

  it("refuses to replace a payload whose bytes do not match its hash", async () => {
    const root = newRoot();
    const store = createFileEvidenceStore(root);
    const payload = Buffer.from("genuine bytes");
    const rec = sampleRecord(payload);
    mkdirSync(join(root, "payloads", "sha256"), { recursive: true });
    writeFileSync(join(root, rec.payload_ref), "tampered bytes");

    assert.deepEqual(await store.save(rec, payload), { ok: false, code: "evidence_payload_mismatch" });
    assert.equal(readFileSync(join(root, rec.payload_ref), "utf8"), "tampered bytes", "left as found");
    assert.equal(existsSync(join(root, "records", `${rec.evidence_id}.json`)), false, "no record points at bad bytes");
  });
});

// ---------------------------------------------------------------------------
// 5. Only successful fetches are persisted
// ---------------------------------------------------------------------------

describe("non-success results are never persisted", () => {
  routes.set("/captcha", html("<title>Just a moment...</title><div class=\"g-recaptcha\"></div>", 403));
  routes.set("/server-error", html("<p>oops</p>", 500));

  for (const [name, target] of [
    ["policy denial", () => url("/page", "private.test")],
    ["credentials in URL", () => `http://u:p@fixture.test:${port}/page`],
    ["challenge page", () => url("/captcha")],
    ["HTTP 500", () => url("/server-error")],
    ["HTTP 404", () => url("/missing")],
  ] as const) {
    it(`writes nothing for a ${name}`, async () => {
      const root = newRoot();
      let calls = 0;
      const real = createFileEvidenceStore(root);
      const spy: EvidenceStore = { save: (rec, p) => (calls++, real.save(rec, p)) };
      const r = await fetchPublicPage(target(), policy(), deps(spy));
      assert.notEqual(r.status, "success");
      assert.equal(calls, 0);
      assert.deepEqual(filesUnder(root), []);
      assert.equal("evidence_persisted" in r ? r.evidence_persisted : false, false);
      assert.equal("evidence_id" in r, false);
    });
  }
});

// ---------------------------------------------------------------------------
// 6. Storage failure (RB-16)
// ---------------------------------------------------------------------------

describe("storage failure", () => {
  function assertUnavailable(r: FetchResult, code: string, root?: string) {
    const s = asSuccess(r);
    assert.equal(s.status, "evidence_unavailable");
    assert.equal(s.evidence_persisted, false);
    assert.equal("evidence_id" in s, false);
    assert.equal("payload_ref" in s, false);
    assert.deepEqual({ code: s.error?.code, retryable: s.error?.retryable }, { code, retryable: false });
    assert.equal(s.extracted_text, "Stable body.", "fetched content is still returned");
    assert.match(s.content_hash.value, /^[0-9a-f]{64}$/);
    const line = logs.find((l) => l.event === "evidence");
    assert.deepEqual(line, { event: "evidence", request_id: s.request_id, outcome: code });
    if (root) assert.ok(!JSON.stringify(s).includes(root) && !JSON.stringify(logs).includes(root), "root path leaked");
  }

  it("reports evidence_unavailable when the root does not exist, and does not create it", async () => {
    const root = join(newRoot(), "missing");
    assertUnavailable(await fetchPublicPage(url("/page"), policy(), deps(createFileEvidenceStore(root))), "evidence_write_failed", root);
    assert.equal(existsSync(root), false);
  });

  it("reports evidence_unavailable when the root is a file", async () => {
    const root = join(newRoot(), "a-file");
    writeFileSync(root, "not a directory");
    assertUnavailable(await fetchPublicPage(url("/page"), policy(), deps(createFileEvidenceStore(root))), "evidence_write_failed", root);
    assert.equal(readFileSync(root, "utf8"), "not a directory");
  });

  it("treats a store that throws as a write failure without echoing its message", async () => {
    const thrower: EvidenceStore = {
      save: async () => {
        throw new Error("EACCES: permission denied, open '/srv/evidence-root/records/x.json'");
      },
    };
    const r = await fetchPublicPage(url("/page"), policy(), deps(thrower));
    assertUnavailable(r, "evidence_write_failed", "/srv/evidence-root");
    assert.ok(!JSON.stringify(r).includes("EACCES") && !JSON.stringify(logs).includes("EACCES"));
  });

  it("passes the store's failure code through", async () => {
    for (const code of ["evidence_exists", "evidence_payload_mismatch"] as const) {
      logs.length = 0;
      const store: EvidenceStore = { save: async () => ({ ok: false, code }) };
      assertUnavailable(await fetchPublicPage(url("/page"), policy(), deps(store)), code);
    }
  });
});

// ---------------------------------------------------------------------------
// 7. Sensitive URLs never reach storage
// ---------------------------------------------------------------------------

describe("sensitive URLs are not persisted", () => {
  const SECRETS = ["PATH-S3CRET", "QTOKEN-x1", "ID-y2", "frag-z3", "HOP-S3CRET", "SID-w4"];
  routes.set("/acct/PATH-S3CRET", (_req, res) => {
    res.writeHead(302, { location: "/hop/HOP-S3CRET?sid=SID-w4#frag" });
    res.end();
  });
  routes.set("/hop/HOP-S3CRET", html("<title>Sensitive fixture</title>body"));
  const tokenUrl = () => url("/acct/PATH-S3CRET?token=QTOKEN-x1&id=ID-y2#frag-z3");

  function assertClean(root: string, r: FetchSuccess, allowed: readonly string[] = []) {
    assert.equal(r.evidence_persisted, true);
    const names = filesUnder(root).join("\n");
    const contents = filesUnder(root)
      .filter((f) => f.startsWith("records/"))
      .map((f) => readFileSync(join(root, f), "utf8"))
      .join("\n");
    for (const secret of SECRETS.filter((s) => !allowed.includes(s))) {
      assert.ok(!names.includes(secret), `file name contains ${secret}`);
      assert.ok(!contents.includes(secret), `record contains ${secret}`);
      assert.ok(!JSON.stringify(logs).includes(secret), `log contains ${secret}`);
    }
    assert.ok(!JSON.stringify(r).includes(root), "result shows the root path");
  }

  it("stores origins only by default, including the redirect chain", async () => {
    const root = newRoot();
    const r = asSuccess(await fetchPublicPage(tokenUrl(), policy(), deps(createFileEvidenceStore(root))));
    assertClean(root, r);
    const rec = readRecord(root, r.evidence_id!);
    assert.equal(rec.source_url, origin());
    assert.equal(rec.final_url, origin());
    assert.deepEqual(rec.redirect_chain.map((h) => h.url), [origin()]);
  });

  it("stores the same masked form the result shows for an opted-in host", async () => {
    const root = newRoot();
    const optIn: UrlDisclosure = { fullUrlHosts: parseHostAllowlist("fixture.test") };
    const r = asSuccess(await fetchPublicPage(tokenUrl(), policy(), deps(createFileEvidenceStore(root)), optIn));
    // Opted in: path and non-secret query values are shown by design; secret-looking values, fragments are not.
    assertClean(root, r, ["PATH-S3CRET", "ID-y2", "HOP-S3CRET"]);
    const rec = readRecord(root, r.evidence_id!);
    assert.equal(rec.source_url, r.source_url);
    assert.equal(rec.final_url, r.final_url);
    assert.equal(rec.source_url, url("/acct/PATH-S3CRET?token=REDACTED&id=ID-y2"));
    assert.equal(rec.final_url, url("/hop/HOP-S3CRET?sid=REDACTED"));
    assert.deepEqual(rec.redirect_chain, r.redirect_chain);
  });
});
