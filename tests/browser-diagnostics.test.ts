import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, afterEach, before, describe, it, type TestContext } from "node:test";
import { chromium } from "playwright-core";
import { BrowserAgent, isTlsErrorToken, navigationErrorToken, type BrowserResult } from "../src/browser/actions.js";
import { DEFAULT_BROWSER_CONFIG, type BrowserConfig, type BrowserDeps } from "../src/browser/session.js";
import { DEFAULT_EGRESS_POLICY } from "../src/egress-proxy.js";
import { NO_EVIDENCE } from "../src/evidence.js";
import type { ResolvedAddress } from "../src/fetcher.js";
import { HandoffStore } from "../src/handoff.js";
import { classifyAddress, parseHostAllowlist } from "../src/security.js";

// Request diagnostics of the browser tools (blocked_requests, failed_requests,
// net_error), against real Chromium and local fixtures only. 127.0.0.1 is the only
// "public" address; names come from an injected resolver. The HTTPS fixture is
// trusted only through the test-only SPKI pin. Local runs without a Chromium build
// (or openssl, for the HTTPS cases) may skip; under CI everything must run.

function hasChromium(): boolean {
  try {
    return existsSync(chromium.executablePath());
  } catch {
    return false;
  }
}
function hasOpenssl(): boolean {
  try {
    execFileSync("openssl", ["version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}
const SKIP = !process.env.CI && !hasChromium() && "Chromium not installed for playwright-core";
const TLS_SKIP = SKIP || (!process.env.CI && !hasOpenssl() && "openssl not available");
const T = { timeout: 90_000 };

const fixtureOnly = (ip: string) => (ip === "127.0.0.1" ? ({ allowed: true } as const) : classifyAddress(ip));

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

type Handler = (req: http.IncomingMessage, res: http.ServerResponse, scheme: "http" | "https") => void;
const routes = new Map<string, Handler>();
interface Hit {
  scheme: "http" | "https";
  host: string;
  method: string;
  path: string;
  url: string;
  headers: http.IncomingHttpHeaders;
}
const hits: Hit[] = [];
let server: http.Server;
let port = 0;
let tlsServer: https.Server | null = null;
let tlsPort = 0;
let spki = "";
let certDir = "";

const html = (body: string | (() => string), status = 200, headers: http.OutgoingHttpHeaders = {}): Handler => (_req, res) => {
  res.writeHead(status, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", ...headers });
  res.end(typeof body === "function" ? body() : body);
};
const redirect = (location: () => string, delayMs = 0): Handler => (_req, res) => {
  setTimeout(() => {
    res.writeHead(302, { location: location(), "cache-control": "no-store" });
    res.end();
  }, delayMs);
};

/** A route whose response is held until the test releases it: lets a test decide when a page's late requests start. */
const held = new Map<string, http.ServerResponse[]>();
function holdRoute(path: string): void {
  routes.set(path, (_req, res) => {
    const list = held.get(path) ?? [];
    list.push(res);
    held.set(path, list);
  });
}
async function release(path: string): Promise<void> {
  await waitFor(() => (held.get(path)?.length ?? 0) > 0, `${path} requested by the page`);
  for (const res of held.get(path) ?? []) {
    res.writeHead(200, { "content-type": "text/plain", "cache-control": "no-store" });
    res.end("go");
  }
  held.delete(path);
}

function handle(scheme: "http" | "https") {
  return (req: http.IncomingMessage, res: http.ServerResponse) => {
    const path = (req.url ?? "").split("?")[0]!;
    hits.push({ scheme, host: (req.headers.host ?? "").split(":")[0]!, method: req.method ?? "", path, url: req.url ?? "", headers: req.headers });
    req.resume();
    const handler = routes.get(path);
    if (handler) handler(req, res, scheme);
    else html("<title>404</title>not found", 404)(req, res, scheme);
  };
}

const dns: Record<string, ResolvedAddress[]> = {
  "fixture.test": [{ address: "127.0.0.1", family: 4 }],
  "other.test": [{ address: "127.0.0.1", family: 4 }],
  "private.test": [{ address: "10.0.0.7", family: 4 }],
  // dnsfail.test is allowlisted but has no entry: the resolver throws for it.
};

const logs: Record<string, unknown>[] = [];
const agents: BrowserAgent[] = [];

function makeAgent(config: Partial<BrowserConfig> = {}, deps: Partial<BrowserDeps> = {}, egress: Partial<typeof DEFAULT_EGRESS_POLICY> = {}): BrowserAgent {
  const agent = new BrowserAgent(
    {
      ...DEFAULT_BROWSER_CONFIG,
      actionTimeoutMs: 3_000,
      navigationTimeoutMs: 5_000,
      ...config,
      egress: {
        ...DEFAULT_EGRESS_POLICY,
        allowedSchemes: new Set(["http:", "https:"]),
        allowedPorts: new Set(tlsPort ? [port, tlsPort] : [port]),
        allowedHosts: parseHostAllowlist("fixture.test private.test dnsfail.test"),
        isAddressAllowed: fixtureOnly,
        connectTimeoutMs: 1_000,
        ...egress,
      },
    },
    {
      resolve: async (h) => {
        const e = dns[h];
        if (!e) throw new Error("ENOTFOUND");
        return e;
      },
      log: (e) => logs.push(e),
      now: () => new Date(),
      evidence: NO_EVIDENCE,
      handoff: new HandoffStore(),
      ...(spki ? { testTrustedSpki: [spki] } : {}),
      ...deps,
    },
  );
  agents.push(agent);
  return agent;
}

const url = (path: string, host = "fixture.test") => `http://${host}:${port}${path}`;
const surl = (path: string, host = "fixture.test") => `https://${host}:${tlsPort}${path}`;
const FIX = () => `http://fixture.test:${port}`;
const OTHER = () => `http://other.test:${port}`;
const DNSFAIL = () => `http://dnsfail.test:${port}`;
const SDNSFAIL = () => `https://dnsfail.test:${tlsPort}`;
const NET_ERR = /^net::ERR_[A-Z0-9_]+$/;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function waitFor(cond: () => boolean, label: string, timeoutMs = 10_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond()) {
    if (Date.now() > deadline) assert.fail(`timed out after ${timeoutMs} ms waiting for: ${label}`);
    await sleep(20);
  }
}

async function open(agent: BrowserAgent): Promise<string> {
  const r = await agent.openSession();
  assert.equal(r.status, "success", JSON.stringify(r));
  return r.session_id!;
}

function expect(r: BrowserResult, status: string, code?: string): void {
  assert.equal(r.status, status, JSON.stringify(r, null, 1));
  if (code) assert.equal(r.error?.code, code, JSON.stringify(r, null, 1));
}

type Failed = { origin: string; resource_type: string; status?: number; error_text?: string };
type Blocked = { origin: string; code: string };
const failedOf = (r: BrowserResult): Failed[] => (r.failed_requests ?? []) as Failed[];
const blockedOf = (r: BrowserResult): Blocked[] => (r.blocked_requests ?? []) as Blocked[];

/** Both arrays present, and every entry carries only the contract's fields. */
function assertDiagnosticsShape(label: string, r: BrowserResult): void {
  assert.ok(Array.isArray(r.blocked_requests), `${label}: blocked_requests missing: ${JSON.stringify(r)}`);
  assert.ok(Array.isArray(r.failed_requests), `${label}: failed_requests missing: ${JSON.stringify(r)}`);
  assert.ok(r.blocked_requests.length <= 20 && r.failed_requests.length <= 20, `${label}: more than 20 entries`);
  for (const b of r.blocked_requests) {
    assert.deepEqual(Object.keys(b).sort(), ["code", "origin"], `${label}: ${JSON.stringify(b)}`);
    assert.match(b.origin, /^(https?:\/\/[^/?#]+|\[non-http-url\]|\[unparseable-url\]|\[invalid-host\])$/, `${label}: ${JSON.stringify(b)}`);
    assert.match(b.code, /^[a-z0-9_]+$/, `${label}: ${JSON.stringify(b)}`);
  }
  for (const f of r.failed_requests) {
    for (const k of Object.keys(f)) assert.ok(["origin", "resource_type", "status", "error_text"].includes(k), `${label}: unexpected field ${k} in ${JSON.stringify(f)}`);
    assert.match(f.origin, /^(https?:\/\/[^/?#]+|\[non-http-url\]|\[unparseable-url\]|\[invalid-host\])$/, `${label}: ${JSON.stringify(f)}`);
    assert.match(f.resource_type, /^[a-z]+$/, `${label}: ${JSON.stringify(f)}`);
    if (f.status !== undefined) assert.ok(Number.isInteger(f.status) && f.status >= 400, `${label}: ${JSON.stringify(f)}`);
    if (f.error_text !== undefined) assert.ok(NET_ERR.test(f.error_text) || f.error_text === "request_failed", `${label}: ${JSON.stringify(f)}`);
  }
  if (r.net_error !== undefined) assert.match(r.net_error, NET_ERR, `${label}: net_error`);
}

/**
 * Takes snapshots until `done` holds for everything reported so far, including the
 * `prior` results (each result reports only what is new since the previous one, so
 * the lists are concatenated). Returns the new snapshot results and the totals.
 */
async function snapshotsUntil(agent: BrowserAgent, id: string, label: string, done: (failed: Failed[], blocked: Blocked[]) => boolean, prior: BrowserResult[] = [], timeoutMs = 10_000) {
  const results: BrowserResult[] = [];
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const r = await agent.snapshot(id);
    expect(r, "success");
    assertDiagnosticsShape(label, r);
    results.push(r);
    const failed = [...prior, ...results].flatMap(failedOf);
    const blocked = [...prior, ...results].flatMap(blockedOf);
    if (done(failed, blocked)) return { results, failed, blocked };
    if (Date.now() > deadline) assert.fail(`${label}: not reported within ${timeoutMs} ms; so far ${JSON.stringify({ failed, blocked })}`);
    await sleep(50);
  }
}

const isEgressDnsError = (origin: string) => (e: Record<string, unknown>) => e.event === "egress" && e.kind === "error" && e.code === "dns_resolution_failed" && e.origin === origin;

before(async () => {
  server = http.createServer(handle("http"));
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as AddressInfo).port;
  if (!TLS_SKIP && hasOpenssl()) {
    certDir = mkdtempSync(join(tmpdir(), "rb-diag-tls-"));
    execFileSync(
      "openssl",
      ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=fixture.test", "-addext", "subjectAltName=DNS:fixture.test,DNS:dnsfail.test,DNS:other.test,DNS:private.test", "-keyout", join(certDir, "key.pem"), "-out", join(certDir, "cert.pem")],
      { stdio: "ignore" },
    );
    const cert = readFileSync(join(certDir, "cert.pem"));
    spki = createHash("sha256")
      .update(new X509Certificate(cert).publicKey.export({ type: "spki", format: "der" }))
      .digest("base64");
    tlsServer = https.createServer({ key: readFileSync(join(certDir, "key.pem")), cert }, handle("https"));
    await new Promise<void>((r) => tlsServer!.listen(0, "127.0.0.1", r));
    tlsPort = (tlsServer.address() as AddressInfo).port;
  }
});

afterEach(async () => {
  // Pages from one test (pollers, held requests) must not run into the next.
  for (const a of agents.splice(0)) await a.closeAll();
  for (const list of held.values()) for (const res of list) res.destroy();
  held.clear();
});

after(async () => {
  for (const a of agents.splice(0)) await a.closeAll();
  server.closeAllConnections();
  server.close();
  if (tlsServer) {
    tlsServer.closeAllConnections();
    tlsServer.close();
  }
  if (certDir) rmSync(certDir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// T1: failures after DOMContentLoaded are reported in the next result, once
// ---------------------------------------------------------------------------

describe("T1 late subresource failures", { skip: SKIP }, () => {
  it("reports a fetch 500 and an image 404 that happen after DOMContentLoaded in the next result, and only once", T, async () => {
    holdRoute("/t1-gate");
    routes.set("/t1", html(`<title>T1</title><p>late failures</p><script>
      fetch("/t1-gate").then(() => {
        fetch("/t1-err500").catch(() => {});
        const img = new Image();
        img.src = "/t1-missing.png";
        document.body.appendChild(img);
      }).catch(() => {});
    </script>`));
    routes.set("/t1-err500", html("<title>err</title>boom", 500));
    const agent = makeAgent();
    const id = await open(agent);
    const nav = await agent.navigate(id, url("/t1"));
    expect(nav, "success");
    assertDiagnosticsShape("navigate", nav);
    assert.deepEqual(nav.failed_requests, [], "nothing has failed yet when navigate returns");

    await release("/t1-gate");
    const want500: Failed = { origin: FIX(), resource_type: "fetch", status: 500 };
    const want404: Failed = { origin: FIX(), resource_type: "image", status: 404 };
    const same = (a: Failed) => (b: Failed) => JSON.stringify(b) === JSON.stringify(a);
    const { results, failed } = await snapshotsUntil(agent, id, "T1", (f) => f.some(same(want500)) && f.some(same(want404)));
    for (const want of [want500, want404]) {
      assert.equal(results.filter((r) => failedOf(r).some(same(want))).length, 1, `reported in exactly one result: ${JSON.stringify(want)}`);
      assert.equal(failed.filter(same(want)).length, 1, `reported once: ${JSON.stringify(want)}`);
    }
    await sleep(300);
    const next = await agent.snapshot(id);
    expect(next, "success");
    assertDiagnosticsShape("snapshot after", next);
    assert.deepEqual(next.failed_requests, [], "an entry is not repeated in the result after the one that reported it");
    assert.deepEqual(next.blocked_requests, []);
  });
});

// ---------------------------------------------------------------------------
// T2: DNS failures of an allowlisted name, subresource and navigation
// ---------------------------------------------------------------------------

describe("T2 DNS failures", { skip: SKIP }, () => {
  it("reports a plain-HTTP subresource to a name that does not resolve, origin only", T, async (t) => {
    routes.set("/t2-http", html(() => `<title>T2</title><p>dns</p><img src="${DNSFAIL()}/t2-img.png"><script>fetch("${DNSFAIL()}/t2-fetch").catch(() => {});</script>`));
    const agent = makeAgent();
    const id = await open(agent);
    const nav = await agent.navigate(id, url("/t2-http"));
    expect(nav, "success");
    assertDiagnosticsShape("navigate", nav);
    const fromDnsfail = (f: Failed[]) => f.filter((x) => x.origin === DNSFAIL());
    const { failed } = await snapshotsUntil(agent, id, "T2 http", (f) => fromDnsfail(f).length >= 2, [nav]);
    const entries = fromDnsfail(failed);
    t.diagnostic(`entries: ${JSON.stringify(entries)}`);
    assert.deepEqual(entries.map((e) => e.resource_type).sort(), ["fetch", "image"], JSON.stringify(entries));
    for (const e of entries) {
      // Over plain HTTP the proxy answers the request itself (502), so Chromium sees an
      // HTTP response; a Chromium network error token is reported where there is one.
      assert.ok(e.status === 502 || (e.error_text !== undefined && NET_ERR.test(e.error_text)), JSON.stringify(e));
      if (e.error_text !== undefined) assert.match(e.error_text, NET_ERR);
    }
    assert.ok(logs.some(isEgressDnsError(DNSFAIL())), "the proxy recorded the DNS failure by origin");
  });

  it("reports an HTTPS subresource to a name that does not resolve with a net::ERR_* token", { ...T, skip: TLS_SKIP }, async () => {
    routes.set("/t2-https", html(() => `<title>T2s</title><p>dns</p><img src="${SDNSFAIL()}/t2s-img.png"><script>fetch("${SDNSFAIL()}/t2s-fetch").catch(() => {});</script>`));
    const agent = makeAgent();
    const id = await open(agent);
    const nav = await agent.navigate(id, surl("/t2-https"));
    expect(nav, "success");
    assertDiagnosticsShape("navigate", nav);
    const fromDnsfail = (f: Failed[]) => f.filter((x) => x.origin === SDNSFAIL());
    const { failed } = await snapshotsUntil(agent, id, "T2 https", (f) => fromDnsfail(f).length >= 2, [nav]);
    const entries = fromDnsfail(failed);
    assert.deepEqual(entries.map((e) => e.resource_type).sort(), ["fetch", "image"], JSON.stringify(entries));
    for (const e of entries) {
      assert.match(String(e.error_text), NET_ERR, JSON.stringify(e));
      assert.equal(e.status, undefined, JSON.stringify(e));
    }
    assert.ok(logs.some(isEgressDnsError(SDNSFAIL())), "the proxy recorded the DNS failure by origin");
  });

  it("navigating over HTTPS to a name that does not resolve gives dns_resolution_failed and a sanitized net_error", { ...T, skip: TLS_SKIP }, async () => {
    const agent = makeAgent();
    const id = await open(agent);
    const r = await agent.navigate(id, surl("/t2-nav/zqDNSpath?zqDNSq=1#zqDNSfrag", "dnsfail.test"));
    expect(r, "provider_unavailable", "dns_resolution_failed");
    assert.match(String(r.net_error), NET_ERR, JSON.stringify(r));
    assertDiagnosticsShape("navigate", r);
    assert.doesNotMatch(JSON.stringify(r), /zqDNS/);
  });
});

// ---------------------------------------------------------------------------
// T3 (gap G2): a request the in-browser policy check refuses is a blocked request,
// not a failed one
// ---------------------------------------------------------------------------

describe("T3 in-browser policy refusals are not failures", { skip: SKIP }, () => {
  it("reports a late request to an unlisted host, and a late POST, in blocked_requests only", T, async () => {
    holdRoute("/t3-gate");
    routes.set("/t3", html(() => `<title>T3</title><p>blocked late</p><script>
      fetch("/t3-gate").then(async () => {
        await fetch("${OTHER()}/t3-fetch").catch(() => {});
        await new Promise((ok) => { const img = new Image(); img.onload = img.onerror = ok; img.src = "${OTHER()}/t3-img.png"; document.body.appendChild(img); });
        await fetch("/t3-post", { method: "POST", body: "x" }).catch(() => {});
        await fetch("/t3-done");
      }).catch(() => {});
    </script>`));
    routes.set("/t3-done", html("ok"));
    const agent = makeAgent();
    const id = await open(agent);
    const nav = await agent.navigate(id, url("/t3"));
    expect(nav, "success");
    assert.deepEqual(nav.blocked_requests, [], "nothing was blocked before DOMContentLoaded");
    await release("/t3-gate");
    await waitFor(() => hits.some((h) => h.path === "/t3-done"), "the page finished its late requests");
    await sleep(300);
    const { failed, blocked } = await snapshotsUntil(
      agent,
      id,
      "T3",
      (_f, b) => b.filter((x) => x.origin === OTHER() && x.code === "host_not_allowlisted").length >= 2 && b.some((x) => x.origin === FIX() && x.code === "method_not_allowed"),
    );
    const last = await agent.snapshot(id);
    const allFailed = [...failed, ...failedOf(last)];
    assert.ok(!hits.some((h) => h.path.startsWith("/t3-fetch") || h.path.startsWith("/t3-img") || h.path === "/t3-post"), "the refused requests never reached a server");
    assert.equal(blocked.filter((x) => x.origin === OTHER()).length, 2, JSON.stringify(blocked));
    assert.deepEqual(
      allFailed.filter((x) => x.origin === OTHER() || x.error_text === "net::ERR_BLOCKED_BY_CLIENT"),
      [],
      `a request refused by the in-browser policy check is reported in blocked_requests, not also in failed_requests: ${JSON.stringify(allFailed)}`,
    );
  });
});

// ---------------------------------------------------------------------------
// T4 (gap G1): a navigation's outcome comes from the navigation itself, not from
// another origin's errors (here: the previous page's background polling)
// ---------------------------------------------------------------------------

describe("T4 navigation attribution while the previous page polls", { skip: SKIP }, () => {
  // The old page keeps fetching an allowlisted name that does not resolve, so the
  // proxy records dns_resolution_failed for THAT origin while the next navigation runs.
  const poller = (target: () => string) => html(() => `<title>Poller</title><p>polling</p><script>setInterval(() => { fetch("${target()}/t4-poll?n=" + Date.now()).catch(() => {}); }, 10);</script>`);
  before(() => {
    routes.set("/t4-poller", poller(DNSFAIL));
    routes.set("/t4-spoller", poller(SDNSFAIL));
    routes.set("/t4-ok", html("<title>OK</title>ok"));
    routes.set("/t4-redirect-out", redirect(() => `${OTHER()}/t4-landing`, 500));
    routes.set("/t4-sredirect-out", redirect(() => surl("/t4-landing", "other.test"), 500));
    routes.set("/t4-hang", () => {
      /* never responds */
    });
  });

  /**
   * Loads the poller, then navigates to `target`. Retries (fresh poller each time)
   * until the poller's proxy errors overlapped the navigation, so the result always
   * comes from an attempt that exercised the case.
   */
  async function navigateWhilePolling(t: TestContext, agent: BrowserAgent, pollerUrl: string, pollOrigin: string, target: string): Promise<BrowserResult> {
    const id = await open(agent);
    for (let attempt = 1; attempt <= 8; attempt++) {
      const start = logs.length;
      expect(await agent.navigate(id, pollerUrl), "success");
      await waitFor(() => logs.slice(start).some(isEgressDnsError(pollOrigin)), "the old page produced proxy DNS errors");
      const mark = logs.length;
      const r = await agent.navigate(id, target);
      const end = logs.findIndex((e, i) => i >= mark && e.event === "browser_action" && e.action === "navigate");
      assert.ok(end > mark, "navigate logged its action");
      if (logs.slice(mark, end).some(isEgressDnsError(pollOrigin))) {
        assertDiagnosticsShape("navigate", r);
        t.diagnostic(`overlap reached on attempt ${attempt}`);
        return r;
      }
    }
    return assert.fail("the old page's proxy errors never overlapped the navigation; the case was not exercised");
  }

  it("guard: a plain-HTTP redirect to an unlisted host stays policy_denied / host_not_allowlisted", T, async (t) => {
    const r = await navigateWhilePolling(t, makeAgent(), url("/t4-poller"), DNSFAIL(), url("/t4-redirect-out"));
    expect(r, "policy_denied", "host_not_allowlisted");
    assert.ok(!hits.some((h) => h.path === "/t4-landing"));
  });

  it("an HTTPS redirect to an unlisted host is policy_denied / host_not_allowlisted, not the poller's DNS error", { ...T, skip: TLS_SKIP }, async (t) => {
    const r = await navigateWhilePolling(t, makeAgent(), surl("/t4-spoller"), SDNSFAIL(), surl("/t4-sredirect-out"));
    expect(r, "policy_denied", "host_not_allowlisted");
    assert.ok(!hits.some((h) => h.path === "/t4-landing"));
  });

  it("a navigation that times out is timeout / navigation_timeout, not the poller's DNS error", T, async (t) => {
    const r = await navigateWhilePolling(t, makeAgent({ navigationTimeoutMs: 1_500 }), url("/t4-poller"), DNSFAIL(), url("/t4-hang"));
    expect(r, "timeout", "navigation_timeout");
  });

  it("an untrusted certificate is policy_denied / tls_verification_failed, not the poller's DNS error", { ...T, skip: TLS_SKIP }, async (t) => {
    // No SPKI pin: the fixture certificate is untrusted for this agent.
    const r = await navigateWhilePolling(t, makeAgent({}, { testTrustedSpki: [] }), url("/t4-poller"), DNSFAIL(), surl("/t4-ok"));
    expect(r, "policy_denied", "tls_verification_failed");
    assert.match(String(r.net_error), NET_ERR);
  });
});

// ---------------------------------------------------------------------------
// T5 (gap G3): at most 20 entries, and a warning when entries were dropped
// ---------------------------------------------------------------------------

describe("T5 truncation warning", { skip: SKIP }, () => {
  const latePage = (gate: string, done: string, requests: string) =>
    html(() => `<title>T5</title><p>many</p><script>
      fetch("${gate}").then(() => Promise.allSettled([${requests}])).then(() => fetch("${done}")).catch(() => {});
    </script>`);

  it("reports at most 20 failed requests and warns request_diagnostics_truncated when more were new", T, async () => {
    holdRoute("/t5-gate");
    routes.set("/t5-done", html("ok"));
    routes.set("/t5", latePage("/t5-gate", "/t5-done", Array.from({ length: 30 }, (_, i) => `fetch("/t5-nf-${i}")`).join(",")));
    const agent = makeAgent();
    const id = await open(agent);
    expect(await agent.navigate(id, url("/t5")), "success");
    await release("/t5-gate");
    await waitFor(() => hits.some((h) => h.path === "/t5-done"), "the page finished its 30 requests");
    await sleep(300);
    assert.equal(hits.filter((h) => h.path.startsWith("/t5-nf-")).length, 30);
    const r = await agent.snapshot(id);
    expect(r, "success");
    assertDiagnosticsShape("snapshot", r);
    assert.equal(failedOf(r).length, 20, JSON.stringify(r.failed_requests));
    assert.ok(failedOf(r).every((f) => f.origin === FIX() && f.resource_type === "fetch" && f.status === 404), JSON.stringify(r.failed_requests));
    assert.ok(r.warnings.includes("request_diagnostics_truncated"), `warnings: ${JSON.stringify(r.warnings)}`);
    const next = await agent.snapshot(id);
    assert.deepEqual(next.failed_requests, []);
    assert.ok(!next.warnings.includes("request_diagnostics_truncated"), `warnings: ${JSON.stringify(next.warnings)}`);
  });

  it("reports at most 20 blocked requests and warns request_diagnostics_truncated when more were new", T, async () => {
    holdRoute("/t5b-gate");
    routes.set("/t5b-done", html("ok"));
    routes.set("/t5b", latePage("/t5b-gate", "/t5b-done", Array.from({ length: 30 }, (_, i) => `fetch("${OTHER()}/t5b-${i}")`).join(",")));
    const agent = makeAgent();
    const id = await open(agent);
    expect(await agent.navigate(id, url("/t5b")), "success");
    await release("/t5b-gate");
    await waitFor(() => hits.some((h) => h.path === "/t5b-done"), "the page finished its 30 requests");
    await sleep(300);
    const r = await agent.snapshot(id);
    expect(r, "success");
    assertDiagnosticsShape("snapshot", r);
    assert.equal(blockedOf(r).length, 20, JSON.stringify(r.blocked_requests));
    assert.ok(blockedOf(r).every((b) => b.origin === OTHER() && b.code === "host_not_allowlisted"), JSON.stringify(r.blocked_requests));
    assert.ok(r.warnings.includes("request_diagnostics_truncated"), `warnings: ${JSON.stringify(r.warnings)}`);
  });

  it("does not warn when only a few requests failed", T, async () => {
    holdRoute("/t5f-gate");
    routes.set("/t5f-done", html("ok"));
    routes.set("/t5f", latePage("/t5f-gate", "/t5f-done", Array.from({ length: 3 }, (_, i) => `fetch("/t5f-nf-${i}")`).join(",")));
    const agent = makeAgent();
    const id = await open(agent);
    const nav = await agent.navigate(id, url("/t5f"));
    expect(nav, "success");
    assert.ok(!nav.warnings.includes("request_diagnostics_truncated"), `warnings: ${JSON.stringify(nav.warnings)}`);
    await release("/t5f-gate");
    await waitFor(() => hits.some((h) => h.path === "/t5f-done"), "the page finished its 3 requests");
    await sleep(300);
    const r = await agent.snapshot(id);
    expect(r, "success");
    assert.equal(failedOf(r).length, 3, JSON.stringify(r.failed_requests));
    assert.ok(!r.warnings.includes("request_diagnostics_truncated"), `warnings: ${JSON.stringify(r.warnings)}`);
  });
});

// ---------------------------------------------------------------------------
// T6: nothing but origin, code, resource type, status and net::ERR_* leaves
// ---------------------------------------------------------------------------

describe("T6 sanitization sentinels", { skip: SKIP }, () => {
  it("never returns or logs a path, query, fragment, cookie, header, body or typed text", T, async () => {
    // Every sentinel contains "zqS3NT"; none of them may appear in a result or log.
    const SENTINEL = /zqS3NT/i;
    routes.set("/t6-page/zqS3NTpath01", html(() => `<title>T6</title><p>sanitization</p>
      <input id="t6in" aria-label="Field" oninput="fetch('/t6-typed?v=' + encodeURIComponent(this.value)).catch(() => {})">
      <button onclick="document.title = 'pressed'">Press</button>
      <script>
        document.cookie = "t6c=zqS3NTcookie05; path=/";
        fetch("/t6-err/zqS3NTpath06?zqS3NTq07=zqS3NTv08#zqS3NTfrag09", { headers: { "x-t6": "zqS3NTheader10" } }).catch(() => {});
        fetch("/t6-err500?k=zqS3NTquery11").catch(() => {});
        fetch("/t6-post/zqS3NTpath12", { method: "POST", body: "zqS3NTbody13" }).catch(() => {});
        fetch("${OTHER()}/zqS3NTpath14?zqS3NTq15=1#zqS3NTfrag").catch(() => {});
        fetch("${DNSFAIL()}/zqS3NTpath16?x=zqS3NTquery17").catch(() => {});
        const img = new Image();
        img.src = "/t6-missing/zqS3NTpath18.png?zqS3NTq19=1#zqS3NTfrag20";
        document.body.appendChild(img);
      </script>`));
    routes.set("/t6-err500", html("<title>err</title>boom", 500));
    routes.set("/t6-redirect", redirect(() => `${OTHER()}/zqS3NTredirect27?zqS3NTq28=1#zqS3NTfrag`));
    const results: BrowserResult[] = [];
    const agent = makeAgent();
    const opened = await agent.openSession();
    results.push(opened);
    const id = opened.session_id!;

    const nav = await agent.navigate(id, url("/t6-page/zqS3NTpath01?zqS3NTq02=zqS3NTv03#zqS3NTfrag04"));
    results.push(nav);
    expect(nav, "success");
    await waitFor(() => ["/t6-err/zqS3NTpath06", "/t6-err500", "/t6-missing/zqS3NTpath18.png"].every((p) => hits.some((h) => h.path === p)), "the page's requests reached the server");
    const snap = await snapshotsUntil(agent, id, "T6", (f, b) => f.some((x) => x.origin === DNSFAIL()) && f.some((x) => x.status === 500) && f.some((x) => x.resource_type === "image") && b.some((x) => x.code === "method_not_allowed") && b.some((x) => x.origin === OTHER()), [nav]);
    results.push(...snap.results);
    // Preconditions: the sentinels really travelled in the requests.
    const sent = hits.find((h) => h.path === "/t6-err/zqS3NTpath06");
    assert.match(String(sent?.headers["x-t6"]), SENTINEL, "custom header sent");
    assert.match(String(sent?.headers.cookie), SENTINEL, "page cookie sent");
    assert.ok(!hits.some((h) => h.method === "POST"), "the POST was refused before leaving the browser");

    const els = snap.results.at(-1)!.elements as { index: number; name: string }[];
    const field = els.find((e) => e.name === "Field")!;
    const press = els.find((e) => e.name === "Press")!;
    const typed = await agent.type(id, field.index, "zqS3NTtyped21");
    results.push(typed);
    expect(typed, "success");
    await waitFor(() => hits.some((h) => h.path === "/t6-typed" && SENTINEL.test(h.url)), "the typed text left in a request");
    const afterType = await snapshotsUntil(agent, id, "T6 typed", (f) => f.some((x) => x.status === 404 && x.resource_type === "fetch"), [typed]);
    results.push(...afterType.results);
    results.push(await agent.click(id, press.index));
    results.push(await agent.scroll(id, { direction: "down", pixels: 100 }));
    results.push((await agent.screenshot(id)).result);

    const redirected = await agent.navigate(id, url("/t6-redirect?zqS3NTq29=1#zqS3NTfrag30"));
    results.push(redirected);
    expect(redirected, "policy_denied", "host_not_allowlisted");
    const unlisted = await agent.navigate(id, `${OTHER()}/zqS3NTpath31?zqS3NTq32=1#zqS3NTfrag33`);
    results.push(unlisted);
    expect(unlisted, "policy_denied", "host_not_allowlisted");
    const dnsHttp = await agent.navigate(id, `${DNSFAIL()}/zqS3NTpath34?zqS3NTq35=1#zqS3NTfrag36`);
    results.push(dnsHttp);
    expect(dnsHttp, "provider_unavailable", "dns_resolution_failed");
    if (tlsPort) {
      const dnsHttps = await agent.navigate(id, `${SDNSFAIL()}/zqS3NTpath37?zqS3NTq38=1#zqS3NTfrag39`);
      results.push(dnsHttps);
      expect(dnsHttps, "provider_unavailable", "dns_resolution_failed");
    } else assert.ok(!process.env.CI, "the HTTPS fixture must exist under CI");
    results.push(await agent.closeSession(id));

    for (const [i, r] of results.entries()) {
      assertDiagnosticsShape(`result ${i}`, r);
      assert.doesNotMatch(JSON.stringify(r), SENTINEL, `result ${i} leaks a sentinel: ${JSON.stringify(r)}`);
    }
    const logged = JSON.stringify(logs);
    assert.doesNotMatch(logged, SENTINEL, "a log entry leaks a sentinel");
    // The diagnostics did report these requests, by origin.
    const allFailed = results.flatMap(failedOf);
    const allBlocked = results.flatMap(blockedOf);
    assert.ok(allFailed.some((f) => f.origin === FIX() && f.status === 404), JSON.stringify(allFailed));
    assert.ok(allBlocked.some((b) => b.origin === OTHER() && b.code === "host_not_allowlisted"), JSON.stringify(allBlocked));
  });
});

// ---------------------------------------------------------------------------
// T7: every result path carries both arrays
// ---------------------------------------------------------------------------

describe("T7 diagnostics on every result path", { skip: SKIP }, () => {
  it("openSession, navigate, snapshot, screenshot, click, type, scroll, pause, refusal, resume, unknown session and close", T, async () => {
    routes.set("/t7", html(`<title>T7</title><p>paths</p><input aria-label="Field"><button onclick="document.title = 'pressed'">Press</button><div style="height:3000px"></div>`));
    const agent = makeAgent({ maxSessions: 1 });
    const check: [string, BrowserResult][] = [];
    const opened = await agent.openSession();
    expect(opened, "success");
    check.push(["openSession", opened]);
    const id = opened.session_id!;
    const limited = await agent.openSession();
    expect(limited, "policy_denied", "session_limit_reached");
    check.push(["openSession refused", limited]);

    const nav = await agent.navigate(id, url("/t7"));
    expect(nav, "success");
    check.push(["navigate success", nav]);
    const navDenied = await agent.navigate(id, url("/", "other.test"));
    expect(navDenied, "policy_denied", "host_not_allowlisted");
    check.push(["navigate failure (policy)", navDenied]);
    const navNet = await agent.navigate(id, url("/", "dnsfail.test"));
    expect(navNet, "provider_unavailable", "dns_resolution_failed");
    check.push(["navigate failure (network)", navNet]);
    expect(await agent.navigate(id, url("/t7")), "success");

    const snap = await agent.snapshot(id);
    expect(snap, "success");
    check.push(["snapshot", snap]);
    const els = snap.elements as { index: number; name: string }[];
    const shot = await agent.screenshot(id);
    expect(shot.result, "success");
    check.push(["screenshot", shot.result]);
    const clicked = await agent.click(id, els.find((e) => e.name === "Press")!.index);
    expect(clicked, "success");
    check.push(["click", clicked]);
    const clickBad = await agent.click(id, 999);
    expect(clickBad, "invalid_input", "unknown_element");
    check.push(["click failure", clickBad]);
    const typed = await agent.type(id, els.find((e) => e.name === "Field")!.index, "hello");
    expect(typed, "success");
    check.push(["type", typed]);
    const typeBad = await agent.type(id, els.find((e) => e.name === "Field")!.index, "x".repeat(5_000));
    expect(typeBad, "invalid_input", "text_too_long");
    check.push(["type failure", typeBad]);
    const scrolled = await agent.scroll(id, { direction: "down", pixels: 300 });
    expect(scrolled, "success");
    check.push(["scroll", scrolled]);

    const paused = await agent.pauseForHuman(id);
    expect(paused, "human_verification_required", "paused_unknown");
    check.push(["pause_for_human", paused]);
    for (const [label, r] of [
      ["paused: navigate", await agent.navigate(id, url("/t7"))],
      ["paused: snapshot", await agent.snapshot(id)],
      ["paused: screenshot", (await agent.screenshot(id)).result],
      ["paused: click", await agent.click(id, 1)],
      ["paused: type", await agent.type(id, 1, "x")],
      ["paused: scroll", await agent.scroll(id, {})],
    ] as const) {
      expect(r, "human_verification_required", "session_paused");
      check.push([label, r]);
    }
    const resumed = await agent.resume(id, "no-such-host-event");
    expect(resumed, "human_verification_required");
    check.push(["resume refused", resumed]);

    const ghost = "00000000-0000-4000-8000-000000000000";
    for (const [label, r] of [
      ["unknown: navigate", await agent.navigate(ghost, url("/t7"))],
      ["unknown: snapshot", await agent.snapshot(ghost)],
      ["unknown: screenshot", (await agent.screenshot(ghost)).result],
      ["unknown: click", await agent.click(ghost, 1)],
      ["unknown: type", await agent.type(ghost, 1, "x")],
      ["unknown: scroll", await agent.scroll(ghost, {})],
      ["unknown: pause", await agent.pauseForHuman(ghost)],
      ["unknown: resume", await agent.resume(ghost, "x")],
      ["unknown: close", await agent.closeSession(ghost)],
    ] as const) {
      expect(r, "invalid_input", "unknown_session");
      check.push([label, r]);
    }

    const closed = await agent.closeSession(id);
    expect(closed, "success");
    check.push(["closeSession", closed]);
    const afterClose = await agent.snapshot(id);
    expect(afterClose, "invalid_input", "unknown_session");
    check.push(["closed: snapshot", afterClose]);

    for (const [label, r] of check) assertDiagnosticsShape(label, r);
  });
});

// ---------------------------------------------------------------------------
// T8: policy outcomes stay exactly as they are (regression guard)
// ---------------------------------------------------------------------------

describe("T8 policy outcomes are unchanged", { skip: SKIP }, () => {
  before(() => {
    routes.set("/t8-ok", html("<title>OK</title><p>fine</p>"));
    routes.set("/t8-redirect-out", redirect(() => `${OTHER()}/t8-landing`));
    routes.set("/t8-redirect-private", redirect(() => url("/t8-landing", "private.test")));
  });

  async function outcome(target: string, deps: Partial<BrowserDeps> = {}): Promise<BrowserResult> {
    const agent = makeAgent({}, deps);
    const id = await open(agent);
    hits.length = 0;
    const r = await agent.navigate(id, target);
    assertDiagnosticsShape(target, r);
    await agent.closeSession(id);
    return r;
  }

  it("allowlisted host: success", T, async () => {
    const r = await outcome(url("/t8-ok"));
    expect(r, "success");
    assert.equal(r.http_status, 200);
    assert.equal(r.title, "OK");
  });

  it("unlisted host: policy_denied / host_not_allowlisted, nothing sent", T, async () => {
    expect(await outcome(url("/t8-ok", "other.test")), "policy_denied", "host_not_allowlisted");
    assert.deepEqual(hits, []);
  });

  it("allowlisted name with a private address: policy_denied / address_private, nothing sent", T, async () => {
    expect(await outcome(url("/t8-ok", "private.test")), "policy_denied", "address_private");
    assert.deepEqual(hits, []);
  });

  it("redirect to an unlisted host: policy_denied / host_not_allowlisted", T, async () => {
    const r = await outcome(url("/t8-redirect-out"));
    expect(r, "policy_denied", "host_not_allowlisted");
    assert.deepEqual(
      hits.map((h) => h.path),
      ["/t8-redirect-out"],
    );
  });

  it("redirect to a private address: policy_denied / address_private", T, async () => {
    const r = await outcome(url("/t8-redirect-private"));
    expect(r, "policy_denied", "address_private");
    assert.deepEqual(
      hits.map((h) => h.path),
      ["/t8-redirect-private"],
    );
  });

  it("file:// URL: policy_denied / scheme_not_allowed", T, async () => {
    expect(await outcome("file:///etc/passwd"), "policy_denied", "scheme_not_allowed");
  });

  it("allowlisted name that does not resolve (HTTP): provider_unavailable / dns_resolution_failed", T, async () => {
    expect(await outcome(url("/t8-ok", "dnsfail.test")), "provider_unavailable", "dns_resolution_failed");
  });

  it("HTTPS with an untrusted certificate: policy_denied / tls_verification_failed", { ...T, skip: TLS_SKIP }, async () => {
    // No SPKI pin for this agent: the fixture certificate is untrusted, and stays refused.
    const r = await outcome(surl("/t8-ok"), { testTrustedSpki: [] });
    expect(r, "policy_denied", "tls_verification_failed");
    assert.match(String(r.net_error), NET_ERR);
  });

  it("HTTPS allowlisted with the pinned fixture certificate: success", { ...T, skip: TLS_SKIP }, async () => {
    const r = await outcome(surl("/t8-ok"));
    expect(r, "success");
    assert.equal(r.title, "OK");
  });

  it("HTTPS private address and redirect to an unlisted host: refused as before", { ...T, skip: TLS_SKIP }, async () => {
    expect(await outcome(surl("/t8-ok", "private.test")), "policy_denied", "address_private");
    routes.set("/t8-sredirect-out", redirect(() => surl("/t8-landing", "other.test")));
    expect(await outcome(surl("/t8-sredirect-out")), "policy_denied", "host_not_allowlisted");
    assert.ok(!hits.some((h) => h.path === "/t8-landing"));
  });
});

// ---------------------------------------------------------------------------
// R: fixes for the security audit and independent review of the diagnostics
// ---------------------------------------------------------------------------

describe("R review and audit fixes", { skip: SKIP }, () => {
  /** Resets the TCP connection under a request (TLS or plain), so the peer sees ECONNRESET. */
  const resetConnection = (req: http.IncomingMessage) => {
    const sock = req.socket as unknown as { _parent?: { resetAndDestroy?: () => void }; resetAndDestroy: () => void };
    if (sock._parent?.resetAndDestroy) sock._parent.resetAndDestroy();
    else sock.resetAndDestroy();
  };
  let closedPort = 0;
  before(async () => {
    const probe = http.createServer();
    await new Promise<void>((r) => probe.listen(0, "127.0.0.1", r));
    closedPort = (probe.address() as AddressInfo).port;
    await new Promise<void>((r) => probe.close(() => r()));
    dns["refused.test"] = [{ address: "127.0.0.1", family: 4 }];
    routes.set("/r-reset.js", (req) => resetConnection(req));
    routes.set("/r-hang", () => {
      /* never responds */
    });
  });
  const agentR = (config: Partial<BrowserConfig> = {}, deps: Partial<BrowserDeps> = {}) =>
    makeAgent(config, deps, {
      allowedHosts: parseHostAllowlist("fixture.test private.test dnsfail.test refused.test"),
      allowedPorts: new Set(tlsPort ? [port, tlsPort, closedPort] : [port, closedPort]),
    });

  /** Navigates to `target` while the page loaded from `noiseUrl` keeps producing `noise`; retries until they overlapped. */
  async function navigateDuringNoise(agent: BrowserAgent, noiseUrl: string, noise: (e: Record<string, unknown>) => boolean, target: string): Promise<BrowserResult> {
    const id = await open(agent);
    for (let attempt = 1; attempt <= 8; attempt++) {
      const start = logs.length;
      expect(await agent.navigate(id, noiseUrl), "success");
      await waitFor(() => logs.slice(start).some(noise), "the old page produced its noise");
      const mark = logs.length;
      const r = await agent.navigate(id, target);
      const end = logs.findIndex((e, i) => i >= mark && e.event === "browser_action" && e.action === "navigate");
      if (logs.slice(mark, end).some(noise)) return r;
    }
    return assert.fail("the old page's noise never overlapped the navigation");
  }

  it("R1 (F1): an HTTPS 503 CAPTCHA page whose same-origin script connection is reset still pauses the session", { ...T, skip: TLS_SKIP }, async () => {
    routes.set("/r1-captcha", html(`<html><head><title>Just a moment</title></head><body><div class="g-recaptcha"></div><script src="/r-reset.js"></script></body></html>`, 503));
    const agent = agentR();
    const id = await open(agent);
    const r = await agent.navigate(id, surl("/r1-captcha"));
    expect(r, "human_verification_required", "paused_captcha");
    assert.equal(r.session_state, "BLOCKED");
  });

  it("R1 (F1): a plain-HTTP 500 page whose same-origin script connection is reset is a success with http_status 500", T, async () => {
    routes.set("/r1-500", html(`<title>Server error</title><p>oops</p><script src="/r-reset.js"></script>`, 500));
    const agent = agentR();
    const id = await open(agent);
    const r = await agent.navigate(id, url("/r1-500"));
    expect(r, "success");
    assert.equal(r.http_status, 500);
  });

  it("R2 (F2): another origin's blocked requests do not override the navigation's own network error", T, async () => {
    routes.set("/r2-noise", html(() => `<title>Noise</title><script>setInterval(() => { const i = new Image(); i.src = "${OTHER()}/r2.png?n=" + Date.now(); }, 10);</script>`));
    routes.set("/r2-loop", redirect(() => url("/r2-loop")));
    const r = await navigateDuringNoise(agentR(), url("/r2-noise"), (e) => e.event === "browser_request_blocked" && e.origin === OTHER(), url("/r2-loop"));
    expect(r, "provider_unavailable", "navigation_failed");
    assert.equal(r.net_error, "net::ERR_TOO_MANY_REDIRECTS");
  });

  it("R3 (F3): the old page's failing iframes are not part of the navigation's own chain", T, async () => {
    routes.set("/r3-noise", html(() => `<title>Frames</title><script>setInterval(() => { const f = document.createElement("iframe"); f.src = "${DNSFAIL()}/frame?n=" + Date.now(); document.body.appendChild(f); }, 30);</script>`));
    const r = await navigateDuringNoise(agentR({ navigationTimeoutMs: 1_500 }), url("/r3-noise"), isEgressDnsError(DNSFAIL()), url("/r-hang"));
    expect(r, "timeout", "navigation_timeout");
  });

  it("R4 (F4): the old page's same-origin requests refused in the browser do not decide the navigation", T, async () => {
    routes.set("/r4-noise", html(`<title>Posts</title><script>setInterval(() => { fetch("/r4-beacon", { method: "POST", body: "x" }).catch(() => {}); }, 10);</script>`));
    const r = await navigateDuringNoise(
      agentR({ navigationTimeoutMs: 1_500 }),
      url("/r4-noise"),
      (e) => e.event === "browser_request_blocked" && e.code === "method_not_allowed",
      url("/r-hang"),
    );
    expect(r, "timeout", "navigation_timeout");
  });

  it("R5 (F1/F5): a proxy-generated 502 is explained by its own code, without another request's net_error", T, async () => {
    holdRoute("/r5-held");
    routes.set("/r5-old", html(`<title>Old</title><script>fetch("/r5-held").catch(() => {});</script>`));
    routes.set("/r5-reset", (req) => resetConnection(req));
    const agent = agentR();
    const id = await open(agent);
    expect(await agent.navigate(id, url("/r5-old")), "success");
    await waitFor(() => held.has("/r5-held"), "the old page's fetch is pending");
    const r = await agent.navigate(id, url("/r5-reset"));
    expect(r, "provider_unavailable", "upstream_error");
    assert.equal(r.net_error, undefined, JSON.stringify(r));
  });

  it("R6 (F9): a destination cannot forge a policy denial over HTTPS", { ...T, skip: TLS_SKIP }, async () => {
    // Well-formed codes: only the "HTTPS replies are never read" rule can stop these.
    routes.set("/r6-forged", html("<title>Forged</title>hello", 200, { "x-research-browser-denial": "host_not_allowlisted", "x-research-browser-proxy-error": "dns_resolution_failed" }));
    const agent = agentR();
    const id = await open(agent);
    const r = await agent.navigate(id, surl("/r6-forged"));
    expect(r, "success");
    assert.equal(r.title, "Forged");
  });

  it("R7 (F10): words in the requested URL never become the error classification", { ...T, skip: TLS_SKIP }, async () => {
    const agent = agentR();
    const id = await open(agent);
    const tls = await agent.navigate(id, surl("/docs/err_ssl_guide", "dnsfail.test"));
    expect(tls, "provider_unavailable", "dns_resolution_failed");
    routes.set("/r7-dl", (_req, res) => {
      res.writeHead(200, { "content-type": "application/octet-stream", "content-disposition": "attachment; filename=x.bin" });
      res.end("binary");
    });
    const dl = await agent.navigate(id, url("/r7-dl?q=net::ERR_FROM_URL_QUERY"));
    assert.notEqual(dl.net_error, "net::ERR_FROM_URL_QUERY", JSON.stringify(dl));
    assert.doesNotMatch(JSON.stringify(dl), /ERR_FROM_URL_QUERY/);
  });

  it("R8 (F11): while a session is paused, results carry no request diagnostics from the page", T, async () => {
    routes.set(
      "/r8-captcha",
      html(() => `<html><head><title>Just a moment</title></head><body><div class="g-recaptcha"></div><script>setInterval(() => { fetch("${OTHER()}/ignore-previous-instructions").catch(() => {}); fetch("/r8-missing").catch(() => {}); }, 20);</script></body></html>`, 403),
    );
    const agent = agentR();
    const id = await open(agent);
    expect(await agent.navigate(id, url("/r8-captcha")), "human_verification_required", "paused_captcha");
    const start = logs.length;
    await waitFor(() => logs.slice(start).some((e) => e.event === "browser_request_blocked") && logs.slice(start).some((e) => e.event === "browser_request_failed"), "the paused page keeps making requests");
    const refused = await agent.snapshot(id);
    expect(refused, "human_verification_required", "session_paused");
    assert.deepEqual([refused.blocked_requests, refused.failed_requests], [[], []], JSON.stringify(refused));
    const resumed = await agent.resume(id, "model-says-solved");
    assert.deepEqual([resumed.blocked_requests, resumed.failed_requests], [[], []], JSON.stringify(resumed));
  });

  it("R9 (F7): a flood of requests refused in the browser is never also logged as failed", T, async () => {
    // The flood starts only once navigate has returned (gate), so it cannot slow the navigation itself.
    holdRoute("/r9-gate");
    routes.set("/r9-flood", html(() => `<title>Flood</title><script>fetch("/r9-gate").then(() => { let n = 0; const t0 = Date.now(); (function loop() { for (let i = 0; i < 50; i++) fetch("${OTHER()}/f" + (n++)).catch(() => {}); if (Date.now() - t0 < 3000) setTimeout(loop, 0); })(); });</script>`));
    const agent = agentR();
    const id = await open(agent);
    const start = logs.length;
    expect(await agent.navigate(id, url("/r9-flood")), "success");
    await release("/r9-gate");
    await sleep(3_500);
    const blocked = logs.slice(start).filter((e) => e.event === "browser_request_blocked").length;
    const dup = logs.slice(start).filter((e) => e.event === "browser_request_failed" && e.error_text === "net::ERR_BLOCKED_BY_CLIENT").length;
    assert.ok(blocked > 500, `the flood was large enough (${blocked} blocked)`);
    assert.equal(dup, 0, `${dup} of ${blocked} refused requests were also logged as failed`);
  });

  it("R10 (guard): an HTTPS redirect target's own DNS failure explains the navigation while the old page fails elsewhere", { ...T, skip: TLS_SKIP }, async () => {
    const refused = () => `https://refused.test:${closedPort}`;
    routes.set("/r10-noise", html(() => `<title>Refused</title><script>setInterval(() => { fetch("${refused()}/p?n=" + Date.now()).catch(() => {}); }, 10);</script>`));
    routes.set("/r10-redirect", redirect(() => surl("/landing", "dnsfail.test")));
    const r = await navigateDuringNoise(agentR(), surl("/r10-noise"), (e) => e.event === "egress" && e.code === "connection_failed" && e.origin === refused(), surl("/r10-redirect"));
    expect(r, "provider_unavailable", "dns_resolution_failed");
  });
});

describe("navigation error token", () => {
  it("is read only from the start of the error, never from a URL in it", () => {
    assert.equal(navigationErrorToken("page.goto: net::ERR_CERT_AUTHORITY_INVALID at https://a.test/?q=net::ERR_FAKE\nCall log:"), "net::ERR_CERT_AUTHORITY_INVALID");
    assert.equal(navigationErrorToken("net::ERR_ABORTED; maybe frame was detached?"), "net::ERR_ABORTED");
    assert.equal(navigationErrorToken('page.goto: Navigation to "https://a.test/?x=net::ERR_EVIL" is interrupted by another navigation to "https://b.test/"'), undefined);
    assert.equal(navigationErrorToken("page.goto: Download is starting\nCall log:\n  - navigating to \"https://a.test/dl?q=net::ERR_FROM_URL\""), undefined);
    assert.equal(navigationErrorToken("page.goto: Timeout 5000ms exceeded."), undefined);
  });
});

describe("TLS error tokens", () => {
  it("classifies every certificate and TLS handshake token as a TLS failure, and nothing else", () => {
    for (const token of [
      "net::ERR_CERT_AUTHORITY_INVALID",
      "net::ERR_CERT_COMMON_NAME_INVALID",
      "net::ERR_CERT_DATE_INVALID",
      "net::ERR_CERTIFICATE_TRANSPARENCY_REQUIRED",
      "net::ERR_SSL_PROTOCOL_ERROR",
      "net::ERR_SSL_VERSION_OR_CIPHER_MISMATCH",
      "net::ERR_BAD_SSL_CLIENT_AUTH_CERT",
      "net::ERR_TLS13_DOWNGRADE_DETECTED",
      "net::ERR_ECH_FALLBACK_CERTIFICATE_INVALID",
    ]) {
      assert.equal(isTlsErrorToken(token), true, token);
    }
    for (const token of ["net::ERR_TUNNEL_CONNECTION_FAILED", "net::ERR_ABORTED", "net::ERR_NAME_NOT_RESOLVED", "net::ERR_CONNECTION_RESET", "net::ERR_EMPTY_RESPONSE", "ERR_CERT_AUTHORITY_INVALID"]) {
      assert.equal(isTlsErrorToken(token), false, token);
    }
  });
});
