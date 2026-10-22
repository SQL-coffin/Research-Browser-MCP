// Integration test for the BUILT fetch path. Run after `npm run build` (it is part
// of `npm run test:smoke`). It loads dist/fetcher.js, dist/security.js and
// dist/index.js, never the TypeScript sources, and runs them against local HTTP
// and HTTPS fixtures. The fixtures are reached through the parameters the unit
// tests already inject (policy, resolver, trust anchor). The production entry
// point builds its policy from the environment only, and a test below checks that
// this policy refuses the fixtures' loopback address.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import zlib from "node:zlib";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

// Types come from the sources and are erased at runtime; the code under test is dist/.
type Fetcher = typeof import("../../src/fetcher.js");
type Security = typeof import("../../src/security.js");
type Entry = typeof import("../../src/index.js");
type FetchPolicy = import("../../src/fetcher.js").FetchPolicy;
type FetchDeps = import("../../src/fetcher.js").FetchDeps;

const DIST = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "dist");
const fromDist = async <T>(file: string): Promise<T> => (await import(pathToFileURL(join(DIST, file)).href)) as T;

let fetcher!: Fetcher;
let security!: Security;
let entry!: Entry;

const PAGE = "<html><head><title>Built &amp; fetched</title></head><body><p>Hello from the fixture.</p></body></html>";
let server: http.Server;
let port: number;
let hits: string[] = [];
const looked: string[] = [];

const routes: Record<string, (res: http.ServerResponse) => void> = {
  "/start": (res) => {
    res.writeHead(302, { location: "/page?token=QTOKEN-d1&id=7" });
    res.end();
  },
  "/page": (res) => {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8", "content-encoding": "gzip" });
    res.end(zlib.gzipSync(PAGE));
  },
  "/to-unlisted": (res) => {
    res.writeHead(302, { location: `http://unlisted.test:${port}/page` });
    res.end();
  },
  "/busy": (res) => {
    res.writeHead(429, { "content-type": "text/html", "retry-after": "7" });
    res.end("slow down");
  },
};

/** Fixture-only policy, passed in by the test exactly as the unit tests do. */
function fixturePolicy(overrides: Partial<FetchPolicy> = {}): FetchPolicy {
  return {
    ...fetcher.DEFAULT_FETCH_POLICY,
    allowedSchemes: new Set(["http:", "https:"]),
    allowedPorts: new Set([port]),
    allowedHosts: security.parseHostAllowlist("fixture.test"),
    // Loopback is allowed for the fixtures only; the default address policy denies it.
    isAddressAllowed: (ip) => (ip === "127.0.0.1" ? ({ allowed: true } as const) : security.classifyAddress(ip)),
    totalTimeoutMs: 3_000,
    connectTimeoutMs: 1_000,
    ...overrides,
  };
}

function fixtureDeps(extra: Partial<FetchDeps> = {}): FetchDeps {
  return {
    resolve: async (host) => {
      looked.push(host);
      if (host === "fixture.test") return [{ address: "127.0.0.1", family: 4 }];
      throw new Error("ENOTFOUND");
    },
    log: () => {},
    now: () => new Date("2026-10-22T00:00:00Z"),
    ...extra,
  };
}

before(async () => {
  for (const file of ["index.js", "fetcher.js", "security.js"]) {
    assert.ok(existsSync(join(DIST, file)), `dist/${file} is missing: run \`npm run build\` first`);
  }
  [fetcher, security, entry] = await Promise.all([fromDist<Fetcher>("fetcher.js"), fromDist<Security>("security.js"), fromDist<Entry>("index.js")]);
  server = http.createServer((req, res) => {
    hits.push(req.url ?? "");
    const handler = routes[(req.url ?? "").split("?")[0]!];
    if (handler) handler(res);
    else {
      res.writeHead(404);
      res.end();
    }
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as AddressInfo).port;
});

after(() => {
  server.closeAllConnections();
  server.close();
});

describe("built fetch path (dist/fetcher.js) against local fixtures", () => {
  it("is compiled JavaScript loaded from dist/, not the TypeScript sources", () => {
    const js = readFileSync(join(DIST, "fetcher.js"), "utf8");
    assert.match(js, /export async function fetchPublicPage\(/);
    assert.doesNotMatch(js, /\binterface FetchPolicy\b|: Promise<FetchResult>/, "dist/fetcher.js must be compiler output");
    assert.equal(typeof fetcher.fetchPublicPage, "function");
  });

  it("follows a redirect, decompresses, extracts and hashes, and shows origins only", async () => {
    hits = [];
    looked.length = 0;
    const r = await fetcher.fetchPublicPage(`http://fixture.test:${port}/start`, fixturePolicy(), fixtureDeps());
    assert.equal(r.status, "success", JSON.stringify(r));
    assert.ok("final_url" in r);
    assert.equal(r.title, "Built & fetched");
    assert.match(r.extracted_text, /Hello from the fixture\./);
    assert.deepEqual(r.content_hash, { algorithm: "sha256", basis: "decoded_body_bytes", value: createHash("sha256").update(PAGE).digest("hex") });
    assert.equal(r.source_url, `http://fixture.test:${port}`);
    assert.equal(r.final_url, `http://fixture.test:${port}`);
    assert.deepEqual(r.redirect_chain, [{ url: `http://fixture.test:${port}`, http_status: 302, peer_address: "127.0.0.1" }]);
    assert.equal(r.evidence_persisted, false);
    assert.deepEqual(hits, ["/start", "/page?token=QTOKEN-d1&id=7"]);
    assert.deepEqual(looked, ["fixture.test", "fixture.test"], "DNS is resolved and checked again on the redirect hop");
  });

  it("shows the full URL only for an opted-in host", async () => {
    const r = await fetcher.fetchPublicPage(`http://fixture.test:${port}/start`, fixturePolicy(), fixtureDeps(), {
      fullUrlHosts: security.parseHostAllowlist("fixture.test"),
    });
    assert.ok("final_url" in r);
    assert.equal(r.final_url, `http://fixture.test:${port}/page?token=REDACTED&id=7`);
  });

  it("aborts before any request bytes when the connected peer fails the policy", async () => {
    let checks = 0;
    hits = [];
    const policy = fixturePolicy({ isAddressAllowed: () => (++checks === 1 ? ({ allowed: true } as const) : { allowed: false, reason: "test_peer" }) });
    const r = await fetcher.fetchPublicPage(`http://fixture.test:${port}/page`, policy, fixtureDeps());
    assert.equal(r.error?.code, "peer_test_peer");
    assert.deepEqual(hits, [], "the fixture must receive no request");
  });

  it("refuses a redirect to an unlisted host before resolving it", async () => {
    hits = [];
    looked.length = 0;
    const r = await fetcher.fetchPublicPage(`http://fixture.test:${port}/to-unlisted`, fixturePolicy(), fixtureDeps());
    assert.equal(r.error?.code, "host_not_allowlisted");
    assert.deepEqual(looked, ["fixture.test"]);
    assert.deepEqual(hits, ["/to-unlisted"]);
  });

  it("cannot reach the fixtures with the production policy built from the environment", async () => {
    // What dist/index.js runs with: the default address policy, HTTPS on 443, and
    // the allowlist from the environment. Listing the fixture host does not open loopback.
    looked.length = 0;
    const production = entry.fetchPolicyFromEnv({ RESEARCH_BROWSER_ALLOWED_HOSTS: "fixture.test" });
    const r = await fetcher.fetchPublicPage("https://fixture.test/", production, fixtureDeps());
    assert.equal(r.error?.code, "address_loopback");
    assert.deepEqual(looked, ["fixture.test"], "refused at the DNS-answer check, before any connection");
  });
});

describe("built fetch path over HTTPS (dist/fetcher.js)", { skip: !process.env.CI && !hasOpenssl() && "openssl not available" }, () => {
  let dir: string;
  let tls: https.Server;
  let tlsPort: number;
  let ca: Buffer;

  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "rb-dist-tls-"));
    execFileSync(
      "openssl",
      ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=fixture.test", "-addext", "subjectAltName=DNS:fixture.test", "-keyout", join(dir, "key.pem"), "-out", join(dir, "cert.pem")],
      { stdio: "ignore" },
    );
    ca = readFileSync(join(dir, "cert.pem"));
    tls = https.createServer({ key: readFileSync(join(dir, "key.pem")), cert: ca }, (_req, res) => {
      res.writeHead(200, { "content-type": "text/html" });
      res.end("<title>secure</title>tls ok");
    });
    await new Promise<void>((r) => tls.listen(0, "127.0.0.1", r));
    tlsPort = (tls.address() as AddressInfo).port;
  });

  after(() => {
    tls.closeAllConnections();
    tls.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it("verifies the certificate and fetches through the pinned TLS connection", async () => {
    const r = await fetcher.fetchPublicPage(`https://fixture.test:${tlsPort}/`, fixturePolicy({ allowedPorts: new Set([tlsPort]) }), fixtureDeps({ tlsCa: ca }));
    assert.equal(r.status, "success", JSON.stringify(r));
    assert.ok("title" in r);
    assert.equal(r.title, "secure");
    assert.equal(r.source_url, `https://fixture.test:${tlsPort}`);
  });

  it("refuses a certificate it does not trust", async () => {
    const r = await fetcher.fetchPublicPage(`https://fixture.test:${tlsPort}/`, fixturePolicy({ allowedPorts: new Set([tlsPort]) }), fixtureDeps());
    assert.equal(r.error?.code, "tls_verification_failed");
  });
});

describe("built MCP server (dist/index.js) handling fetch results", () => {
  it("returns structured fetch results and classifies them by reference, with origins only", async () => {
    const mcp = entry.createServer({ fetchPolicy: fixturePolicy(), fetchDeps: fixtureDeps() });
    const [a, b] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "dist-fetch", version: "0.0.0" });
    await Promise.all([mcp.connect(a), client.connect(b)]);
    try {
      const call = async (name: string, args: Record<string, unknown>) => (await client.callTool({ name, arguments: args })).structuredContent as Record<string, any>;
      const page = await call("research.fetch_public_page", { url: `http://fixture.test:${port}/start` });
      assert.equal(page.status, "success");
      assert.equal(page.title, "Built & fetched");
      assert.equal(page.source_url, `http://fixture.test:${port}`);
      assert.match(page.content_hash.value, /^[0-9a-f]{64}$/);
      const busy = await call("research.fetch_public_page", { url: `http://fixture.test:${port}/busy?token=QTOKEN-b7` });
      assert.equal(busy.status, "rate_limited");
      const classified = await call("research.inspect_challenge", { fetch_request_id: busy.request_id });
      assert.equal(classified.challenge_type, "rate_limited");
      assert.equal(classified.retry_after_seconds, 7);
      assert.equal(classified.source_url, `http://fixture.test:${port}`);
      assert.ok(!JSON.stringify([page, busy, classified]).includes("QTOKEN"));
    } finally {
      await client.close();
    }
  });
});

function hasOpenssl(): boolean {
  try {
    execFileSync("openssl", ["version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}
