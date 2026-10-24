import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import net, { type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import tls from "node:tls";
import { after, before, beforeEach, describe, it } from "node:test";
import { DEFAULT_EGRESS_POLICY, startEgressProxy, type EgressPolicy, type EgressProxy } from "../src/egress-proxy.js";
import type { ResolvedAddress } from "../src/fetcher.js";
import { classifyAddress, parseHostAllowlist } from "../src/security.js";

// The proxy treats 127.0.0.1 as the only "public" address in these tests, as the
// fetcher tests do; every other special-purpose range stays denied.
const fixtureOnly = (ip: string) => (ip === "127.0.0.1" ? ({ allowed: true } as const) : classifyAddress(ip));

let origin: http.Server;
let port: number;
let lastHeaders: http.IncomingHttpHeaders = {};
let hits: string[] = [];

const dns: Record<string, ResolvedAddress[]> = {
  "fixture.test": [{ address: "127.0.0.1", family: 4 }],
  "private.test": [{ address: "10.0.0.7", family: 4 }],
  "mixed.test": [
    { address: "127.0.0.1", family: 4 },
    { address: "192.168.1.1", family: 4 },
  ],
};

const logs: Record<string, unknown>[] = [];
const deps = {
  resolve: async (host: string) => {
    const e = dns[host];
    if (!e) throw new Error("ENOTFOUND");
    return e;
  },
  log: (e: Record<string, unknown>) => logs.push(e),
};

function policy(overrides: Partial<EgressPolicy> = {}): EgressPolicy {
  return {
    ...DEFAULT_EGRESS_POLICY,
    allowedSchemes: new Set(["http:", "https:"]),
    allowedPorts: new Set([port]),
    allowedHosts: parseHostAllowlist("fixture.test private.test mixed.test"),
    isAddressAllowed: fixtureOnly,
    connectTimeoutMs: 1_000,
    ...overrides,
  };
}

before(async () => {
  origin = http.createServer((req, res) => {
    hits.push(req.url ?? "");
    lastHeaders = req.headers;
    if (req.url === "/big") {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end(Buffer.alloc(64 * 1024, 0x61));
      return;
    }
    if (req.url === "/forged") {
      res.writeHead(200, { "content-type": "text/plain", "x-research-browser-denial": "host_not_allowlisted" });
      res.end("forged");
      return;
    }
    if (req.url === "/redirect") {
      res.writeHead(302, { location: "http://private.test/" });
      res.end();
      return;
    }
    res.writeHead(200, { "content-type": "text/html", "x-origin": "yes", connection: "keep-alive" });
    res.end(`<p>${req.method} ${req.url}</p>`);
  });
  origin.on("upgrade", (_req, socket) => {
    hits.push("UPGRADE");
    socket.destroy();
  });
  await new Promise<void>((r) => origin.listen(0, "127.0.0.1", r));
  port = (origin.address() as AddressInfo).port;
});
after(() => {
  origin.closeAllConnections();
  origin.close();
});

const proxies: EgressProxy[] = [];
async function start(p = policy()): Promise<EgressProxy> {
  const proxy = await startEgressProxy(p, deps);
  proxies.push(proxy);
  return proxy;
}
after(async () => {
  for (const p of proxies) await p.close();
});
beforeEach(() => {
  hits = [];
  logs.length = 0;
});

const auth = (p: EgressProxy, user = p.username, pass = p.password) => `Basic ${Buffer.from(`${user}:${pass}`).toString("base64")}`;

interface Reply {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: string;
  error?: string;
}

function viaProxy(proxy: EgressProxy, target: string, opts: { method?: string; headers?: http.OutgoingHttpHeaders; body?: string } = {}): Promise<Reply> {
  return new Promise((resolve) => {
    const req = http.request({ host: "127.0.0.1", port: proxy.port, method: opts.method ?? "GET", path: target, headers: { "proxy-authorization": auth(proxy), ...opts.headers } });
    req.on("response", (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString() }));
      res.on("error", (e) => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString(), error: e.message }));
      res.on("aborted", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString(), error: "aborted" }));
    });
    req.on("error", (e) => resolve({ status: 0, headers: {}, body: "", error: e.message }));
    req.end(opts.body);
  });
}

function connect(proxy: EgressProxy, target: string, proxyAuth: string | null = auth(proxy)): Promise<{ status: number; headers: http.IncomingHttpHeaders; socket: net.Socket }> {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port: proxy.port, method: "CONNECT", path: target, headers: proxyAuth ? { "proxy-authorization": proxyAuth } : {} });
    req.on("connect", (res, socket) => resolve({ status: res.statusCode ?? 0, headers: res.headers, socket }));
    req.on("response", (res) => {
      res.resume();
      resolve({ status: res.statusCode ?? 0, headers: res.headers, socket: res.socket });
    });
    req.on("error", reject);
    req.end();
  });
}

describe("egress proxy: access to the proxy itself", () => {
  it("listens on loopback only", async () => {
    const proxy = await start();
    assert.equal(proxy.host, "127.0.0.1");
  });

  it("requires the per-proxy credentials (407 otherwise)", async () => {
    const proxy = await start();
    const none = await new Promise<number>((resolve) => {
      http.get({ host: "127.0.0.1", port: proxy.port, path: `http://fixture.test:${port}/` }, (res) => {
        res.resume();
        resolve(res.statusCode ?? 0);
      });
    });
    assert.equal(none, 407);
    const wrong = await viaProxy(proxy, `http://fixture.test:${port}/`, { headers: { "proxy-authorization": auth(proxy, proxy.username, "wrong") } });
    assert.equal(wrong.status, 407);
    const tunnel = await connect(proxy, `fixture.test:${port}`, null);
    assert.equal(tunnel.status, 407);
    assert.deepEqual(hits, [], "nothing reached the origin");
  });

  it("issues distinct random credentials per proxy", async () => {
    const a = await start();
    const b = await start();
    assert.notEqual(a.password, b.password);
    assert.ok(a.password.length >= 32);
    const cross = await viaProxy(a, `http://fixture.test:${port}/`, { headers: { "proxy-authorization": auth(b) } });
    assert.equal(cross.status, 407);
  });

  it("rejects origin-form requests (the proxy is not a web server)", async () => {
    const proxy = await start();
    const r = await viaProxy(proxy, "/");
    assert.equal(r.status, 400);
  });
});

describe("egress proxy: plain HTTP", () => {
  it("forwards an allowlisted GET and strips proxy credentials and hop-by-hop headers", async () => {
    const proxy = await start();
    const r = await viaProxy(proxy, `http://fixture.test:${port}/page?q=1`, { headers: { "x-test": "1", "proxy-connection": "keep-alive" } });
    assert.equal(r.status, 200);
    assert.equal(r.body, "<p>GET /page?q=1</p>");
    assert.equal(r.headers["x-origin"], "yes");
    assert.equal(lastHeaders["proxy-authorization"], undefined);
    assert.equal(lastHeaders["proxy-connection"], undefined);
    assert.equal(lastHeaders["x-test"], "1");
  });

  it("denies a host that is not allowlisted and records the denial by origin", async () => {
    const proxy = await start(policy({ allowedHosts: parseHostAllowlist("other.test") }));
    const r = await viaProxy(proxy, `http://fixture.test:${port}/secret/path?token=abc`);
    assert.equal(r.status, 403);
    assert.equal(r.headers["x-research-browser-denial"], "host_not_allowlisted");
    assert.deepEqual(hits, []);
    const d = proxy.denials().at(-1);
    assert.equal(d?.code, "host_not_allowlisted");
    assert.equal(d?.origin, `http://fixture.test:${port}`);
    assert.doesNotMatch(JSON.stringify(logs), /secret|token|abc/);
  });

  it("denies every request when the allowlist is empty", async () => {
    const proxy = await start(policy({ allowedHosts: parseHostAllowlist("") }));
    const r = await viaProxy(proxy, `http://fixture.test:${port}/`);
    assert.equal(r.status, 403);
    assert.equal(r.headers["x-research-browser-denial"], "host_allowlist_empty");
  });

  it("denies a host that resolves to a private address", async () => {
    const proxy = await start();
    const r = await viaProxy(proxy, `http://private.test:${port}/`);
    assert.equal(r.status, 403);
    assert.equal(r.headers["x-research-browser-denial"], "address_private");
  });

  it("denies a mixed DNS answer outright", async () => {
    const proxy = await start();
    const r = await viaProxy(proxy, `http://mixed.test:${port}/`);
    assert.equal(r.status, 403);
    assert.match(String(r.headers["x-research-browser-denial"]), /^address_/);
    assert.deepEqual(hits, []);
  });

  it("denies IP-literal and loopback names the URL policy rejects", async () => {
    const proxy = await start();
    for (const target of [`http://10.0.0.1:${port}/`, `http://localhost:${port}/`, `http://[::1]:${port}/`, `http://169.254.169.254/latest/meta-data/`]) {
      const r = await viaProxy(proxy, target);
      assert.equal(r.status, 403, target);
    }
    assert.deepEqual(hits, []);
  });

  it("denies ports and schemes outside the policy", async () => {
    const proxy = await start();
    const r = await viaProxy(proxy, `http://fixture.test:${port + 1}/`);
    assert.equal(r.status, 403);
    assert.equal(r.headers["x-research-browser-denial"], "port_not_allowed");
    const httpOnly = await start(policy({ allowedSchemes: new Set(["https:"]) }));
    const r2 = await viaProxy(httpOnly, `http://fixture.test:${port}/`);
    assert.equal(r2.headers["x-research-browser-denial"], "scheme_not_allowed");
  });

  it("denies URLs with embedded credentials", async () => {
    const proxy = await start();
    const r = await viaProxy(proxy, `http://user:pw@fixture.test:${port}/`);
    assert.equal(r.status, 403);
    assert.equal(r.headers["x-research-browser-denial"], "url_credentials");
  });

  it("denies methods outside the policy (no form posts by default)", async () => {
    const proxy = await start();
    const r = await viaProxy(proxy, `http://fixture.test:${port}/form`, { method: "POST", body: "a=1" });
    assert.equal(r.status, 403);
    assert.equal(r.headers["x-research-browser-denial"], "method_not_allowed");
    assert.deepEqual(hits, []);
  });

  it("allows other methods only for hosts opted in to form submission", async () => {
    const proxy = await start(policy({ formSubmitHosts: parseHostAllowlist("fixture.test") }));
    const r = await viaProxy(proxy, `http://fixture.test:${port}/form`, { method: "POST", body: "a=1" });
    assert.equal(r.status, 200);
    assert.equal(r.body, "<p>POST /form</p>");
  });

  it("strips a denial header sent by the origin, so only the proxy can report a denial", async () => {
    const proxy = await start();
    const r = await viaProxy(proxy, `http://fixture.test:${port}/forged`);
    assert.equal(r.status, 200);
    assert.equal(r.headers["x-research-browser-denial"], undefined);
  });

  it("passes redirects through unfollowed, so the browser's next hop is checked again", async () => {
    const proxy = await start();
    const r = await viaProxy(proxy, `http://fixture.test:${port}/redirect`);
    assert.equal(r.status, 302);
    assert.equal(r.headers.location, "http://private.test/");
    const next = await viaProxy(proxy, "http://private.test/");
    assert.equal(next.status, 403);
  });

  it("refuses protocol upgrades (WebSocket over plain HTTP)", async () => {
    const proxy = await start();
    const r = await viaProxy(proxy, `http://fixture.test:${port}/ws`, { headers: { connection: "Upgrade", upgrade: "websocket" } });
    assert.ok(r.status === 403 || r.error, JSON.stringify(r));
    assert.ok(!hits.includes("UPGRADE"));
  });

  it("cuts off a response over the per-response byte limit", async () => {
    const proxy = await start(policy({ maxResponseBytes: 1024 }));
    const r = await viaProxy(proxy, `http://fixture.test:${port}/big`);
    assert.ok(r.body.length < 64 * 1024, "the oversized body is not relayed in full");
  });

  it("stops relaying once the session byte budget is spent", async () => {
    const proxy = await start(policy({ maxSessionBytes: 2_000 }));
    await viaProxy(proxy, `http://fixture.test:${port}/big`);
    const r = await viaProxy(proxy, `http://fixture.test:${port}/`);
    assert.equal(r.status, 403);
    assert.equal(r.headers["x-research-browser-denial"], "session_byte_budget_exceeded");
  });

  it("reports an unreachable allowlisted host as 502 without retrying elsewhere", async () => {
    const closed = net.createServer();
    await new Promise<void>((r) => closed.listen(0, "127.0.0.1", r));
    const deadPort = (closed.address() as AddressInfo).port;
    await new Promise<void>((r) => closed.close(() => r()));
    const proxy = await start(policy({ allowedPorts: new Set([deadPort]) }));
    const r = await viaProxy(proxy, `http://fixture.test:${deadPort}/`);
    assert.equal(r.status, 502);
  });

  it("logs origins only", async () => {
    const proxy = await start();
    await viaProxy(proxy, `http://fixture.test:${port}/private/path?session=xyz`);
    assert.ok(logs.length > 0);
    assert.doesNotMatch(JSON.stringify(logs), /private\/path|session=|xyz/);
  });
});

describe("egress proxy: CONNECT tunnels", () => {
  it("denies a tunnel to a non-allowlisted host", async () => {
    const proxy = await start(policy({ allowedHosts: parseHostAllowlist("other.test") }));
    const t = await connect(proxy, `fixture.test:${port}`);
    assert.equal(t.status, 403);
    assert.equal(t.headers["x-research-browser-denial"], "host_not_allowlisted");
    t.socket.destroy();
  });

  it("denies a tunnel to a private address", async () => {
    const proxy = await start(policy({ allowedPorts: new Set([443, port]) }));
    for (const target of ["private.test:443", "10.0.0.1:443", "[::1]:443", "localhost:443"]) {
      const t = await connect(proxy, target);
      assert.equal(t.status, 403, target);
      t.socket.destroy();
    }
  });

  it("rejects malformed CONNECT targets", async () => {
    const proxy = await start();
    for (const target of [`user@fixture.test:${port}`, `fixture.test:${port}/path`, "fixture.test", `fixture.test:${port}:1`]) {
      const t = await connect(proxy, target);
      assert.equal(t.status, 400, target);
      t.socket.destroy();
    }
  });

  it("denies a tunnel to a port outside the policy", async () => {
    const proxy = await start();
    const t = await connect(proxy, `fixture.test:22`);
    assert.equal(t.status, 403);
    assert.equal(t.headers["x-research-browser-denial"], "port_not_allowed");
    t.socket.destroy();
  });
});

describe("egress proxy: CONNECT with TLS end to end", { skip: !process.env.CI && !hasOpenssl() && "openssl not available" }, () => {
  let dir: string;
  let server: https.Server;
  let tlsPort: number;
  let ca: Buffer;

  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "rb-proxy-tls-"));
    execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=fixture.test", "-addext", "subjectAltName=DNS:fixture.test", "-keyout", join(dir, "key.pem"), "-out", join(dir, "cert.pem")], { stdio: "ignore" });
    ca = readFileSync(join(dir, "cert.pem"));
    server = https.createServer({ key: readFileSync(join(dir, "key.pem")), cert: ca }, (_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("tunnel ok");
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    tlsPort = (server.address() as AddressInfo).port;
  });
  after(() => {
    server.closeAllConnections();
    server.close();
    rmSync(dir, { recursive: true, force: true });
  });

  function overTls(socket: net.Socket, trust: Buffer | undefined): Promise<string> {
    return new Promise((resolve, reject) => {
      const s = tls.connect({ socket, servername: "fixture.test", ...(trust ? { ca: trust } : {}), rejectUnauthorized: true }, () => {
        s.write("GET / HTTP/1.1\r\nhost: fixture.test\r\nconnection: close\r\n\r\n");
      });
      let data = "";
      s.on("data", (d: Buffer) => (data += d.toString()));
      s.on("end", () => resolve(data));
      s.on("error", reject);
    });
  }

  it("relays an allowlisted tunnel; the client still verifies the certificate", async () => {
    const proxy = await start(policy({ allowedPorts: new Set([tlsPort]) }));
    const t = await connect(proxy, `fixture.test:${tlsPort}`);
    assert.equal(t.status, 200);
    const reply = await overTls(t.socket, ca);
    assert.match(reply, /tunnel ok/);
    assert.ok(proxy.bytesRelayed() > 0);
  });

  it("does not terminate TLS: an untrusted certificate fails at the client", async () => {
    const proxy = await start(policy({ allowedPorts: new Set([tlsPort]) }));
    const t = await connect(proxy, `fixture.test:${tlsPort}`);
    assert.equal(t.status, 200);
    await assert.rejects(overTls(t.socket, undefined), /self.signed|certificate/i);
  });

  it("closes open tunnels when the proxy closes", async () => {
    const proxy = await startEgressProxy(policy({ allowedPorts: new Set([tlsPort]) }), deps);
    const t = await connect(proxy, `fixture.test:${tlsPort}`);
    const closed = new Promise<void>((r) => t.socket.on("close", () => r()));
    await proxy.close();
    await closed;
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

describe("egress proxy diagnostics", () => {
  it("records resolver failures as origin-only error events", async () => {
    const proxy = await start(policy({ allowedHosts: parseHostAllowlist("dnsfail.test") }));
    const r = await viaProxy(proxy, `http://dnsfail.test:${port}/private/path?token=secret`);
    assert.equal(r.status, 502);
    const event = proxy.events().at(-1);
    assert.equal(event?.kind, "error");
    assert.equal(event?.code, "dns_resolution_failed");
    assert.equal(event?.origin, `http://dnsfail.test:${port}`);
    assert.doesNotMatch(JSON.stringify(event), /private|token|secret/);
    assert.doesNotMatch(JSON.stringify(logs), /private|token|secret/);
  });
});

// ---------------------------------------------------------------------------
// Contract: docs/08-browser-diagnostics-contract.md (D1, D2). These tests are
// written before the implementation and fail until it lands.
// ---------------------------------------------------------------------------

function resolverError(code: string, message: string): NodeJS.ErrnoException {
  const err = new Error(message) as NodeJS.ErrnoException;
  err.code = code;
  return err;
}

describe("egress proxy diagnostics contract: DNS timeout (D1)", () => {
  it("bounds name resolution by connectTimeoutMs and records dns_timeout", { timeout: 5_000 }, async () => {
    const proxy = await startEgressProxy(policy({ allowedHosts: parseHostAllowlist("hang.test"), connectTimeoutMs: 300 }), {
      ...deps,
      resolve: () => new Promise<ResolvedAddress[]>(() => {}),
    });
    proxies.push(proxy);
    const started = Date.now();
    const r = await viaProxy(proxy, `http://hang.test:${port}/private/path?token=secret`);
    const elapsed = Date.now() - started;
    assert.equal(r.status, 504, JSON.stringify(r));
    assert.ok(elapsed < 300 + 500, `answered after ${elapsed} ms`);
    const event = proxy.events().at(-1);
    assert.equal(event?.kind, "error");
    assert.equal(event?.code, "dns_timeout");
    assert.equal(event?.origin, `http://hang.test:${port}`);
    assert.equal(r.headers["x-research-browser-denial"], undefined, "a timeout is not a policy denial");
    assert.doesNotMatch(JSON.stringify(proxy.events()) + JSON.stringify(logs), /private|token|secret/);
  });

  it("never connects when the resolver answers after the deadline", { timeout: 5_000 }, async () => {
    const proxy = await startEgressProxy(policy({ allowedHosts: parseHostAllowlist("late.test"), connectTimeoutMs: 200 }), {
      ...deps,
      resolve: () => new Promise<ResolvedAddress[]>((res) => setTimeout(() => res([{ address: "127.0.0.1", family: 4 }]), 500)),
    });
    proxies.push(proxy);
    const r = await viaProxy(proxy, `http://late.test:${port}/late`);
    assert.equal(r.status, 504, JSON.stringify(r));
    await new Promise((res) => setTimeout(res, 600));
    assert.deepEqual(hits, [], "no request may reach the origin after the deadline");
  });

  it("bounds CONNECT tunnels the same way", { timeout: 5_000 }, async () => {
    const proxy = await startEgressProxy(policy({ allowedHosts: parseHostAllowlist("hang.test"), connectTimeoutMs: 300 }), {
      ...deps,
      resolve: () => new Promise<ResolvedAddress[]>(() => {}),
    });
    proxies.push(proxy);
    const started = Date.now();
    const r = await connect(proxy, `hang.test:${port}`);
    r.socket.destroy();
    assert.equal(r.status, 504);
    assert.ok(Date.now() - started < 300 + 500);
    assert.equal(proxy.events().at(-1)?.code, "dns_timeout");
  });
});

describe("egress proxy diagnostics contract: resolver error classes (D2)", () => {
  const cases: [string, string, number][] = [
    ["ENOTFOUND", "dns_resolution_failed", 502],
    ["ENODATA", "dns_resolution_failed", 502],
    ["EAI_AGAIN", "dns_temporary_failure", 502],
    ["ESERVFAIL", "dns_temporary_failure", 502],
    ["ETIMEOUT", "dns_timeout", 504],
  ];
  for (const [errno, code, status] of cases) {
    it(`maps ${errno} to ${code} without echoing the resolver message`, { timeout: 5_000 }, async () => {
      const proxy = await startEgressProxy(policy({ allowedHosts: parseHostAllowlist("dnserr.test") }), {
        ...deps,
        resolve: async () => {
          throw resolverError(errno, `getaddrinfo ${errno} dnserr.test via resolver-10-1-2-3.corp.internal`);
        },
      });
      proxies.push(proxy);
      const r = await viaProxy(proxy, `http://dnserr.test:${port}/`);
      assert.equal(r.status, status, JSON.stringify(r));
      const event = proxy.events().at(-1);
      assert.equal(event?.kind, "error");
      assert.equal(event?.code, code);
      assert.doesNotMatch(JSON.stringify(proxy.events()) + JSON.stringify(logs) + r.body, /getaddrinfo|corp\.internal|resolver-10/);
    });
  }

  it("keeps dns_resolution_failed for an error without a recognized code", { timeout: 5_000 }, async () => {
    const proxy = await startEgressProxy(policy({ allowedHosts: parseHostAllowlist("dnserr.test") }), {
      ...deps,
      resolve: async () => {
        throw new Error("something odd");
      },
    });
    proxies.push(proxy);
    const r = await viaProxy(proxy, `http://dnserr.test:${port}/`);
    assert.equal(r.status, 502);
    assert.equal(proxy.events().at(-1)?.code, "dns_resolution_failed");
  });
});
