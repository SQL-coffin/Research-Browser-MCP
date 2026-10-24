import assert from "node:assert/strict";
import { execFileSync, spawn, type ChildProcess } from "node:child_process";
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

// Diagnostics contract: event kinds and codes, denial header only on denials,
// ring sizes and seq order, origin-only audit logs, upstream errors after a
// connection was admitted (gap G4), and a policy regression matrix guarding
// that diagnostics never change an allow/deny decision or status code.
describe("egress proxy diagnostics contract", () => {
  type Diagnostic = ReturnType<EgressProxy["events"]>[number];

  const DENIAL = "x-research-browser-denial";
  const EVENT_KEYS = ["at", "code", "kind", "origin", "seq"];
  // Distinct markers per request part, so a leak names the part that leaked.
  const SENTINELS = /PATHSENTINEL|QUERYSENTINEL|QVALSENTINEL|FRAGSENTINEL|COOKIESENTINEL|CVALSENTINEL|HEADERSENTINEL|BODYSENTINEL/;
  const SECRET_TAIL = "/PATHSENTINEL_p1/deeper?QUERYSENTINEL_q2=QVALSENTINEL_v3#FRAGSENTINEL_f4";
  const SECRET_HEADERS = { cookie: "COOKIESENTINEL_c5=CVALSENTINEL_c6", "x-diag-probe": "HEADERSENTINEL_h7", authorization: "Bearer HEADERSENTINEL_h8" };
  const SECRET_BODY = "BODYSENTINEL_b9=1";

  // Same resolver as the other tests, plus a name with an empty DNS answer.
  const diagDeps = {
    resolve: async (host: string): Promise<ResolvedAddress[]> => (host === "noanswer.test" ? [] : deps.resolve(host)),
    log: deps.log,
  };

  let deadPort = 0; // nothing listens here
  let appPort = 0; // HTTP fixture: complete, mid-body abort, reset before headers, hang, oversized
  let resetPort = 0; // raw TCP: resets the connection on the first byte it receives
  let echoPort = 0; // raw TCP: echoes the first chunk, then closes normally
  let silentPort = 0; // raw TCP: accepts and never sends
  let closeDelimitedPort = 0; // raw HTTP: response body delimited by connection close
  let sendResetPort = 0; // raw TCP: sends bytes, then resets (a tunnel that already carried data)
  let app: http.Server;
  const rawServers: net.Server[] = [];
  const rawSockets = new Set<net.Socket>();

  async function listen(server: net.Server): Promise<number> {
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    return (server.address() as AddressInfo).port;
  }

  function rawServer(onSocket: (s: net.Socket) => void): Promise<number> {
    const server = net.createServer((s) => {
      rawSockets.add(s);
      s.on("close", () => rawSockets.delete(s));
      s.on("error", () => {});
      onSocket(s);
    });
    rawServers.push(server);
    return listen(server);
  }

  before(async () => {
    const probe = net.createServer();
    deadPort = await listen(probe);
    await new Promise<void>((r) => probe.close(() => r()));

    app = http.createServer((req, res) => {
      const path = req.url ?? "";
      if (path.startsWith("/midbody")) {
        res.writeHead(200, { "content-type": "text/plain", "content-length": "100000" });
        res.write("partial body");
        setTimeout(() => req.socket.destroy(), 50);
        return;
      }
      if (path.startsWith("/reset-before-headers")) {
        req.socket.resetAndDestroy();
        return;
      }
      if (path.startsWith("/hang")) return;
      if (path.startsWith("/forged-proxy-error")) {
        res.writeHead(200, { "content-type": "text/plain", "x-research-browser-proxy-error": "dns_resolution_failed" });
        res.end("forged");
        return;
      }
      if (path.startsWith("/big")) {
        res.writeHead(200, { "content-type": "text/plain" });
        res.end(Buffer.alloc(64 * 1024, 0x62));
        return;
      }
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("complete");
    });
    appPort = await listen(app);
    resetPort = await rawServer((s) => s.once("data", () => s.resetAndDestroy()));
    echoPort = await rawServer((s) => s.once("data", (d: Buffer) => s.end(d)));
    silentPort = await rawServer(() => {});
    closeDelimitedPort = await rawServer((s) => s.once("data", () => s.end("HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n\r\nbody delimited by close")));
    sendResetPort = await rawServer((s) =>
      s.once("data", () => {
        s.write("server-bytes");
        setTimeout(() => s.resetAndDestroy(), 50);
      }),
    );
  });
  after(() => {
    app.closeAllConnections();
    app.close();
    for (const s of rawSockets) s.destroy();
    for (const s of rawServers) s.close();
  });

  function diagPolicy(overrides: Partial<EgressPolicy> = {}): EgressPolicy {
    return policy({
      allowedHosts: parseHostAllowlist("fixture.test private.test mixed.test dnsfail.test noanswer.test"),
      allowedPorts: new Set([port, deadPort, appPort, resetPort, echoPort, silentPort, closeDelimitedPort, sendResetPort]),
      ...overrides,
    });
  }

  async function startDiag(p = diagPolicy()): Promise<EgressProxy> {
    const proxy = await startEgressProxy(p, diagDeps);
    proxies.push(proxy);
    return proxy;
  }

  function connectWith(proxy: EgressProxy, target: string, headers: http.OutgoingHttpHeaders): Promise<{ status: number; headers: http.IncomingHttpHeaders; socket: net.Socket }> {
    return new Promise((resolve, reject) => {
      const req = http.request({ host: "127.0.0.1", port: proxy.port, method: "CONNECT", path: target, headers: { "proxy-authorization": auth(proxy), ...headers } });
      req.on("connect", (res, socket) => resolve({ status: res.statusCode ?? 0, headers: res.headers, socket }));
      req.on("error", reject);
      req.end();
    });
  }

  /** An established tunnel whose received bytes are collected (keeps the socket flowing so 'close' fires). */
  async function tunnel(proxy: EgressProxy, target: string): Promise<{ status: number; socket: net.Socket; received: () => string }> {
    const t = await connect(proxy, target);
    let data = "";
    t.socket.on("error", () => {});
    t.socket.on("data", (d: Buffer) => (data += d.toString()));
    return { status: t.status, socket: t.socket, received: () => data };
  }

  function closed(socket: net.Socket, ms = 3_000): Promise<boolean> {
    return new Promise((resolve) => {
      if (socket.closed) return resolve(true);
      const timer = setTimeout(() => resolve(false), ms);
      socket.once("close", () => {
        clearTimeout(timer);
        resolve(true);
      });
    });
  }

  async function waitFor(cond: () => boolean, ms = 1_500): Promise<boolean> {
    const end = Date.now() + ms;
    while (!cond()) {
      if (Date.now() > end) return false;
      await new Promise((r) => setTimeout(r, 10));
    }
    return true;
  }

  const settle = (ms = 200) => new Promise((r) => setTimeout(r, ms));

  function assertEvent(event: Diagnostic | undefined, kind: "error" | "deny", code: string, origin: string, label = code): void {
    assert.ok(event, `${label}: expected a ${kind} event`);
    assert.deepEqual(Object.keys(event).sort(), EVENT_KEYS, `${label}: origin-only event shape`);
    assert.equal(event.kind, kind, label);
    assert.equal(event.code, code, label);
    assert.equal(event.origin, origin, label);
  }

  // Failures before any byte reaches a destination: reply 502, kind "error".
  const errorCases = () => [
    { authority: `dnsfail.test:${port}`, code: "dns_resolution_failed" },
    { authority: `noanswer.test:${port}`, code: "dns_no_answer" },
    { authority: `fixture.test:${deadPort}`, code: "connection_failed" },
  ];

  // ---- P1: kind "error" events, origin-only, status unchanged -------------

  it("P1: DNS and connection failures on plain HTTP are origin-only error events; status stays 502", async () => {
    const proxy = await startDiag();
    for (const c of errorCases()) {
      const r = await viaProxy(proxy, `http://${c.authority}${SECRET_TAIL}`);
      assert.equal(r.status, 502, c.code);
      assertEvent(proxy.events().at(-1), "error", c.code, `http://${c.authority}`);
    }
    assert.equal(proxy.events().length, 3, JSON.stringify(proxy.events()));
    assert.deepEqual(proxy.denials(), [], "errors are not denials");
    assert.doesNotMatch(JSON.stringify(proxy.events()), SENTINELS);
  });

  it("P1: DNS and connection failures on CONNECT are origin-only error events; reply stays 502", async () => {
    const proxy = await startDiag();
    for (const c of errorCases()) {
      const t = await connect(proxy, c.authority);
      t.socket.destroy();
      assert.equal(t.status, 502, c.code);
      assertEvent(proxy.events().at(-1), "error", c.code, `https://${c.authority}`);
    }
    assert.equal(proxy.events().length, 3, JSON.stringify(proxy.events()));
    assert.deepEqual(proxy.denials(), [], "errors are not denials");
  });

  describe("P1: connect timeout (listener whose accept queue is full)", { skip: process.platform === "win32" && "needs a POSIX listen backlog and SIGSTOP" }, () => {
    // A child process listens with backlog 1 and stops itself, so it never accepts.
    // Once the queue is full the kernel drops further SYNs and connects hang.
    const STALLED_LISTENER =
      'const s = require("node:net").createServer(); s.listen({ port: 0, host: "127.0.0.1", backlog: 1 }, () => process.stdout.write(s.address().port + "\\n", () => process.kill(process.pid, "SIGSTOP")));';
    let child: ChildProcess | undefined;
    let stalledPort = 0;
    let ready = false;
    const fillers: net.Socket[] = [];

    before(async () => {
      child = spawn(process.execPath, ["-e", STALLED_LISTENER], { stdio: ["ignore", "pipe", "ignore"] });
      const c = child;
      stalledPort = await new Promise<number>((resolve, reject) => {
        c.stdout!.once("data", (d: Buffer) => resolve(Number(String(d).trim())));
        c.once("error", reject);
        c.once("exit", () => reject(new Error("stalled listener exited early")));
      });
      for (let i = 0; i < 16; i++) {
        const s = net.connect({ host: "127.0.0.1", port: stalledPort });
        fillers.push(s);
        const state = await new Promise<"connected" | "pending" | "failed">((resolve) => {
          const timer = setTimeout(() => resolve("pending"), 250);
          s.once("connect", () => {
            clearTimeout(timer);
            resolve("connected");
          });
          s.once("error", () => {
            clearTimeout(timer);
            resolve("failed");
          });
        });
        s.on("error", () => {});
        if (state === "failed") break;
        if (state === "pending") {
          ready = true;
          break;
        }
      }
    });
    after(() => {
      for (const s of fillers) s.destroy();
      child?.stdout?.destroy();
      child?.kill("SIGKILL");
    });

    it("plain HTTP: connect_timeout is an origin-only error event; status stays 504, no denial header", async (t) => {
      if (!ready) return t.skip("the kernel did not hold back connections to a full accept queue");
      const proxy = await startDiag(diagPolicy({ allowedPorts: new Set([stalledPort]), connectTimeoutMs: 300 }));
      const r = await viaProxy(proxy, `http://fixture.test:${stalledPort}${SECRET_TAIL}`);
      assert.equal(r.status, 504);
      assert.equal(r.headers[DENIAL], undefined);
      assertEvent(proxy.events().at(-1), "error", "connect_timeout", `http://fixture.test:${stalledPort}`);
      assert.deepEqual(proxy.denials(), []);
    });

    it("CONNECT: connect_timeout is an origin-only error event; reply stays 504, no denial header", async (t) => {
      if (!ready) return t.skip("the kernel did not hold back connections to a full accept queue");
      const proxy = await startDiag(diagPolicy({ allowedPorts: new Set([stalledPort]), connectTimeoutMs: 300 }));
      const tn = await connect(proxy, `fixture.test:${stalledPort}`);
      tn.socket.destroy();
      assert.equal(tn.status, 504);
      assert.equal(tn.headers[DENIAL], undefined);
      assertEvent(proxy.events().at(-1), "error", "connect_timeout", `https://fixture.test:${stalledPort}`);
      assert.deepEqual(proxy.denials(), []);
    });
  });

  // ---- P2: denial header only on denials -----------------------------------

  it("P2: plain-HTTP error responses carry no denial header; policy denials still do", async () => {
    const proxy = await startDiag();
    for (const c of errorCases()) {
      const r = await viaProxy(proxy, `http://${c.authority}/`);
      assert.equal(r.status, 502, c.code);
      assert.equal(r.headers[DENIAL], undefined, c.code);
    }
    const denials = [
      { target: `http://unlisted.test:${port}/`, code: "host_not_allowlisted" },
      { target: `http://private.test:${port}/`, code: "address_private" },
      { target: `http://fixture.test:${port}/form`, code: "method_not_allowed", method: "POST" },
      { target: "http://fixture.test:22/", code: "port_not_allowed" },
    ];
    for (const d of denials) {
      const r = await viaProxy(proxy, d.target, d.method ? { method: d.method, body: "a=1" } : {});
      assert.equal(r.status, 403, d.code);
      assert.equal(r.headers[DENIAL], d.code, d.code);
      const origin = new URL(d.target).origin;
      assertEvent(proxy.denials().at(-1), "deny", d.code, origin);
      assertEvent(proxy.events().at(-1), "deny", d.code, origin);
    }
    assert.deepEqual(hits, [], "no denied request reached the origin");
  });

  it("P2: CONNECT error replies carry no denial header; policy denials still do", async () => {
    const proxy = await startDiag();
    for (const c of errorCases()) {
      const t = await connect(proxy, c.authority);
      t.socket.destroy();
      assert.equal(t.status, 502, c.code);
      assert.equal(t.headers[DENIAL], undefined, c.code);
    }
    const denials = [
      { target: `unlisted.test:${port}`, code: "host_not_allowlisted" },
      { target: `private.test:${port}`, code: "address_private" },
      { target: "fixture.test:22", code: "port_not_allowed" },
    ];
    for (const d of denials) {
      const t = await connect(proxy, d.target);
      t.socket.destroy();
      assert.equal(t.status, 403, d.code);
      assert.equal(t.headers[DENIAL], d.code, d.code);
      assertEvent(proxy.denials().at(-1), "deny", d.code, `https://${d.target}`);
    }
  });

  // ---- P3: denials() vs events(), seq order, ring size ---------------------

  it("P3: denials() holds only denials; events() holds both in strictly increasing seq order, at most 50 of each kind", async () => {
    const proxy = await startDiag();
    for (let i = 0; i < 30; i++) {
      await viaProxy(proxy, `http://unlisted.test:${port}/`); // deny
      await viaProxy(proxy, `http://dnsfail.test:${port}/`); // error
    }
    const events = proxy.events();
    assert.equal(events.length, 60, "30 of each kind fit in their own 50-entry buffers");
    assert.deepEqual(new Set(events.map((e) => e.kind)), new Set(["deny", "error"]));
    for (let i = 1; i < events.length; i++) assert.ok(events[i]!.seq > events[i - 1]!.seq, `seq not increasing at ${i}`);
    assert.equal(events.at(-1)?.seq, 60, "seq counts every event over the proxy's lifetime");
    assert.equal(events[0]?.seq, 1);

    const denials = proxy.denials();
    assert.ok(denials.length > 0 && denials.length <= 50, `denials().length = ${denials.length}`);
    assert.ok(
      denials.every((d) => d.kind === "deny" && d.code === "host_not_allowlisted"),
      "denials() holds only kind deny",
    );
    for (let i = 1; i < denials.length; i++) assert.ok(denials[i]!.seq > denials[i - 1]!.seq, `denial seq not increasing at ${i}`);
    assert.equal(denials.at(-1)?.seq, 59, "the newest denial is last");
  });

  it("P3: neither list exceeds 50 after more than 50 denials", async () => {
    const proxy = await startDiag();
    for (let i = 0; i < 55; i++) await viaProxy(proxy, `http://unlisted.test:${port}/`);
    await viaProxy(proxy, `http://dnsfail.test:${port}/`);
    const denials = proxy.denials();
    assert.ok(denials.length > 0 && denials.length <= 50, `denials().length = ${denials.length}`);
    assert.ok(denials.every((d) => d.kind === "deny"));
    assert.equal(denials.at(-1)?.seq, 55);
    assert.equal(denials.length, 50, "the newest 50 denials are kept");
    assert.equal(denials[0]?.seq, 6);
    const events = proxy.events();
    assert.equal(events.length, 51, "50 denials plus the one error");
    assert.equal(events.at(-1)?.kind, "error");
    assert.equal(events.at(-1)?.seq, 56);
  });

  it("F6: error noise never pushes a denial out (denials and errors are buffered separately)", async () => {
    const proxy = await startDiag();
    await viaProxy(proxy, `http://private.test:${port}/`); // deny: address_private
    for (let i = 0; i < 60; i++) await viaProxy(proxy, `http://dnsfail.test:${port}/`); // errors
    assert.deepEqual(
      proxy.denials().map((d) => [d.seq, d.code]),
      [[1, "address_private"]],
    );
    const events = proxy.events();
    assert.equal(events.filter((e) => e.kind === "error").length, 50);
    assert.equal(events[0]?.code, "address_private");
    for (let i = 1; i < events.length; i++) assert.ok(events[i]!.seq > events[i - 1]!.seq, `seq not increasing at ${i}`);
  });

  it("F1: proxy-generated plain-HTTP error replies name their code in x-research-browser-proxy-error; denials and destination replies never do", async () => {
    const PROXY_ERROR = "x-research-browser-proxy-error";
    const proxy = await startDiag();
    for (const c of errorCases()) {
      const r = await viaProxy(proxy, `http://${c.authority}/`);
      assert.equal(r.status, 502, c.code);
      assert.equal(r.headers[PROXY_ERROR], c.code, c.code);
      assert.equal(r.headers[DENIAL], undefined, c.code);
    }
    const reset = await viaProxy(proxy, `http://fixture.test:${appPort}/reset-before-headers`);
    assert.equal(reset.status, 502);
    assert.equal(reset.headers[PROXY_ERROR], "upstream_error");
    const denied = await viaProxy(proxy, `http://unlisted.test:${port}/`);
    assert.equal(denied.status, 403);
    assert.equal(denied.headers[PROXY_ERROR], undefined);
    const forged = await viaProxy(proxy, `http://fixture.test:${appPort}/forged-proxy-error`);
    assert.equal(forged.status, 200);
    assert.equal(forged.headers[PROXY_ERROR], undefined, "a destination cannot claim to be the proxy");
  });

  it("F1: a tunnel whose destination already sent data and then resets records no upstream_error (indistinguishable from a normal close)", async () => {
    const proxy = await startDiag();
    const t = await tunnel(proxy, `fixture.test:${sendResetPort}`);
    assert.equal(t.status, 200);
    const gone = closed(t.socket);
    t.socket.write("hello");
    assert.ok(await gone, "the proxy closes the client side");
    await settle();
    assert.match(t.received(), /server-bytes/);
    assert.ok(!proxy.events().some((e) => e.code === "upstream_error"), JSON.stringify(proxy.events()));
  });

  it("F12: allow lines name the connection type as transport; kind only ever means deny or error", async () => {
    const proxy = await startDiag();
    logs.length = 0;
    await viaProxy(proxy, `http://fixture.test:${port}/`);
    await viaProxy(proxy, `http://unlisted.test:${port}/`);
    await viaProxy(proxy, `http://dnsfail.test:${port}/`);
    const egress = logs.filter((l) => l.event === "egress");
    const allow = egress.find((l) => l.decision === "allow");
    assert.equal(allow?.transport, "http", JSON.stringify(allow));
    assert.equal(allow && "kind" in allow, false, JSON.stringify(allow));
    for (const l of egress.filter((x) => x.decision !== "allow")) assert.equal(l.kind, l.decision, JSON.stringify(l));
  });

  // ---- P4: audit log lines are origin + code only --------------------------

  it("P4: plain-HTTP audit log lines name origin and code but no path, query, fragment, header, cookie or body", async () => {
    const proxy = await startDiag();
    const cases = [
      ...errorCases(),
      { authority: `unlisted.test:${port}`, code: "host_not_allowlisted" },
      { authority: `private.test:${port}`, code: "address_private" },
      { authority: "fixture.test:22", code: "port_not_allowed" },
      { authority: `fixture.test:${port}`, code: "method_not_allowed", method: "POST" },
    ];
    for (const c of cases) {
      logs.length = 0;
      const opts = "method" in c ? { method: c.method, headers: SECRET_HEADERS, body: SECRET_BODY } : { headers: SECRET_HEADERS };
      await viaProxy(proxy, `http://${c.authority}${SECRET_TAIL}`, opts);
      const origin = `http://${c.authority}`;
      assert.ok(
        logs.some((l) => l.origin === origin && l.code === c.code),
        `${c.code}: no log line with origin and code: ${JSON.stringify(logs)}`,
      );
      assert.doesNotMatch(JSON.stringify(logs), SENTINELS, c.code);
    }
    logs.length = 0;
    const ok = await viaProxy(proxy, `http://fixture.test:${port}${SECRET_TAIL}`, { headers: SECRET_HEADERS });
    assert.equal(ok.status, 200);
    assert.ok(logs.some((l) => l.origin === `http://fixture.test:${port}`));
    assert.doesNotMatch(JSON.stringify(logs), SENTINELS, "allowed request");
    assert.doesNotMatch(JSON.stringify(proxy.events()), SENTINELS);
  });

  it("P4: CONNECT audit log lines name origin and code but no header or cookie", async () => {
    const proxy = await startDiag();
    const cases = [
      ...errorCases(),
      { authority: `unlisted.test:${port}`, code: "host_not_allowlisted" },
      { authority: `private.test:${port}`, code: "address_private" },
      { authority: "fixture.test:22", code: "port_not_allowed" },
    ];
    for (const c of cases) {
      logs.length = 0;
      const t = await connectWith(proxy, c.authority, SECRET_HEADERS);
      t.socket.destroy();
      const origin = `https://${c.authority}`;
      assert.ok(
        logs.some((l) => l.origin === origin && l.code === c.code),
        `${c.code}: no log line with origin and code: ${JSON.stringify(logs)}`,
      );
      assert.doesNotMatch(JSON.stringify(logs), SENTINELS, c.code);
    }
    assert.doesNotMatch(JSON.stringify(proxy.events()), SENTINELS);
  });

  // ---- P5: upstream errors after admission (gap G4) ------------------------

  async function upstreamErrors(proxy: EgressProxy): Promise<Diagnostic[]> {
    await waitFor(() => proxy.events().some((e) => e.code === "upstream_error"));
    await settle(100); // catch a duplicate recorded for the same failure
    return proxy.events().filter((e) => e.code === "upstream_error");
  }

  it("[gap G4] P5a: an upstream that drops the connection mid-body is one upstream_error event (plain HTTP), status unchanged", async () => {
    const proxy = await startDiag();
    const r = await viaProxy(proxy, `http://fixture.test:${appPort}/midbody${SECRET_TAIL}`, { headers: SECRET_HEADERS });
    assert.equal(r.status, 200, "headers were already relayed, so the status stays 200");
    assert.ok(r.error, "the client sees a truncated response");
    const errors = await upstreamErrors(proxy);
    assert.equal(errors.length, 1, `events: ${JSON.stringify(proxy.events())}`);
    assertEvent(errors[0], "error", "upstream_error", `http://fixture.test:${appPort}`);
    assert.deepEqual(proxy.denials(), [], "an upstream error is not a denial");
    assert.ok(logs.some((l) => l.origin === `http://fixture.test:${appPort}` && l.code === "upstream_error"), JSON.stringify(logs));
    assert.doesNotMatch(JSON.stringify(logs), SENTINELS);
    assert.doesNotMatch(JSON.stringify(proxy.events()), SENTINELS);
  });

  it("[gap G4] P5a: an upstream reset before the response headers is one upstream_error event (plain HTTP), status stays 502", async () => {
    const proxy = await startDiag();
    const r = await viaProxy(proxy, `http://fixture.test:${appPort}/reset-before-headers${SECRET_TAIL}`, { headers: SECRET_HEADERS });
    assert.equal(r.status, 502);
    assert.equal(r.headers[DENIAL], undefined, "an upstream error is not a denial");
    const errors = await upstreamErrors(proxy);
    assert.equal(errors.length, 1, `events: ${JSON.stringify(proxy.events())}`);
    assertEvent(errors[0], "error", "upstream_error", `http://fixture.test:${appPort}`);
    assert.deepEqual(proxy.denials(), []);
    assert.ok(logs.some((l) => l.origin === `http://fixture.test:${appPort}` && l.code === "upstream_error"), JSON.stringify(logs));
    assert.doesNotMatch(JSON.stringify(logs), SENTINELS);
  });

  it("[gap G4] P5b: an upstream reset inside a CONNECT tunnel is one upstream_error event", async () => {
    const proxy = await startDiag();
    const t = await tunnel(proxy, `fixture.test:${resetPort}`);
    assert.equal(t.status, 200);
    const gone = closed(t.socket);
    t.socket.write("hello");
    assert.ok(await gone, "the proxy closes the client side of a reset tunnel");
    const errors = await upstreamErrors(proxy);
    assert.equal(errors.length, 1, `events: ${JSON.stringify(proxy.events())}`);
    assertEvent(errors[0], "error", "upstream_error", `https://fixture.test:${resetPort}`);
    assert.deepEqual(proxy.denials(), []);
    assert.ok(logs.some((l) => l.origin === `https://fixture.test:${resetPort}` && l.code === "upstream_error"), JSON.stringify(logs));
  });

  it("P5: completed plain-HTTP responses record no event (content-length and close-delimited bodies)", async () => {
    const proxy = await startDiag();
    const a = await viaProxy(proxy, `http://fixture.test:${appPort}/ok`);
    assert.equal(a.status, 200);
    assert.equal(a.body, "complete");
    assert.equal(a.error, undefined);
    const b = await viaProxy(proxy, `http://fixture.test:${closeDelimitedPort}/`);
    assert.equal(b.status, 200);
    assert.equal(b.body, "body delimited by close");
    const c = await viaProxy(proxy, `http://fixture.test:${port}/`);
    assert.equal(c.status, 200);
    await settle();
    assert.deepEqual(proxy.events(), []);
  });

  it("P5: tunnels closed normally by either side record no event", async () => {
    const proxy = await startDiag();
    const echo = await tunnel(proxy, `fixture.test:${echoPort}`);
    assert.equal(echo.status, 200);
    echo.socket.write("ping");
    assert.ok(await closed(echo.socket), "the upstream closed the tunnel");
    assert.equal(echo.received(), "ping");

    const ended = await tunnel(proxy, `fixture.test:${silentPort}`);
    assert.equal(ended.status, 200);
    ended.socket.end();
    assert.ok(await closed(ended.socket), "a client half-close ends the tunnel");

    const aborted = await tunnel(proxy, `fixture.test:${silentPort}`);
    assert.equal(aborted.status, 200);
    aborted.socket.destroy();

    await settle();
    assert.deepEqual(proxy.events(), []);
  });

  it("P5: idle-timeout closes record no event (tunnel closed; plain HTTP stays 502)", async () => {
    const proxy = await startDiag(diagPolicy({ idleTimeoutMs: 150 }));
    const t = await tunnel(proxy, `fixture.test:${silentPort}`);
    assert.equal(t.status, 200);
    assert.ok(await closed(t.socket), "the idle tunnel is closed by the proxy");
    const r = await viaProxy(proxy, `http://fixture.test:${appPort}/hang`);
    assert.equal(r.status, 502);
    assert.equal(r.headers[DENIAL], undefined);
    await settle();
    assert.deepEqual(proxy.events(), []);
  });

  it("P5: a response cut off by the byte limit is only a response_too_large denial, not an upstream_error", async () => {
    const proxy = await startDiag(diagPolicy({ maxResponseBytes: 1024 }));
    const r = await viaProxy(proxy, `http://fixture.test:${appPort}/big`);
    assert.ok(r.body.length < 64 * 1024);
    await settle();
    assert.deepEqual(
      proxy.events().map((e) => [e.kind, e.code, e.origin]),
      [["deny", "response_too_large", `http://fixture.test:${appPort}`]],
    );
  });

  it("P5: connections the proxy closes itself (session byte budget, shutdown) record no upstream_error", async () => {
    const budget = await startDiag(diagPolicy({ maxSessionBytes: 2_000 }));
    const r = await viaProxy(budget, `http://fixture.test:${appPort}/big`);
    assert.ok(r.body.length < 64 * 1024);
    await settle();
    assert.ok(!budget.events().some((e) => e.code === "upstream_error"), JSON.stringify(budget.events()));

    const closing = await startDiag();
    const pending = viaProxy(closing, `http://fixture.test:${appPort}/big`);
    await closing.close();
    await pending;
    await settle();
    assert.ok(!closing.events().some((e) => e.code === "upstream_error"), JSON.stringify(closing.events()));
  });

  // ---- P6: policy regression matrix ----------------------------------------

  it("P6: plain-HTTP allow/deny decisions and statuses are unchanged", async () => {
    const proxy = await startDiag();
    const rows: { target: string; method?: string; status: number; denial?: string }[] = [
      { target: `http://fixture.test:${port}/m-get`, status: 200 },
      { target: `http://fixture.test:${port}/m-head`, method: "HEAD", status: 200 },
      { target: `http://unlisted.test:${port}/m`, status: 403, denial: "host_not_allowlisted" },
      { target: `http://private.test:${port}/m`, status: 403, denial: "address_private" },
      { target: `http://mixed.test:${port}/m`, status: 403, denial: "address_private" },
      { target: `http://10.0.0.1:${port}/m`, status: 403, denial: "address_private" },
      { target: `http://127.0.0.1:${port}/m`, status: 403, denial: "host_not_allowlisted" },
      { target: `http://[::1]:${port}/m`, status: 403, denial: "address_loopback" },
      { target: `http://localhost:${port}/m`, status: 403, denial: "host_not_public" },
      { target: `http://printer.local:${port}/m`, status: 403, denial: "host_not_public" },
      { target: `http://user:pw@fixture.test:${port}/m`, status: 403, denial: "url_credentials" },
      { target: "http://fixture.test:22/m", status: 403, denial: "port_not_allowed" },
      { target: "http://169.254.169.254/latest/meta-data/", status: 403, denial: "port_not_allowed" },
      { target: `http://fixture.test:${port}/m-post`, method: "POST", status: 403, denial: "method_not_allowed" },
      { target: `https://fixture.test:${port}/m`, status: 400 },
    ];
    const reached: string[] = [];
    for (const row of rows) {
      const seqBefore = proxy.events().at(-1)?.seq ?? 0;
      const r = await viaProxy(proxy, row.target, row.method === "POST" ? { method: row.method, body: "a=1" } : row.method ? { method: row.method } : {});
      assert.equal(r.status, row.status, row.target);
      assert.equal(r.headers[DENIAL], row.denial, row.target);
      const fresh = proxy.events().filter((e) => e.seq > seqBefore);
      assert.deepEqual(
        fresh.map((e) => [e.kind, e.code]),
        row.denial ? [["deny", row.denial]] : [],
        row.target,
      );
      if (row.status === 200) reached.push(new URL(row.target).pathname);
    }
    assert.deepEqual(hits, reached, "only allowed requests reached the origin");
  });

  it("P6: CONNECT allow/deny decisions and statuses are unchanged", async () => {
    const proxy = await startDiag();
    const rows: { target: string; status: number; denial?: string }[] = [
      { target: `fixture.test:${port}`, status: 200 },
      { target: `unlisted.test:${port}`, status: 403, denial: "host_not_allowlisted" },
      { target: `private.test:${port}`, status: 403, denial: "address_private" },
      { target: `mixed.test:${port}`, status: 403, denial: "address_private" },
      { target: `10.0.0.1:${port}`, status: 403, denial: "address_private" },
      { target: `127.0.0.1:${port}`, status: 403, denial: "host_not_allowlisted" },
      { target: `[::1]:${port}`, status: 403, denial: "address_loopback" },
      { target: `localhost:${port}`, status: 403, denial: "host_not_public" },
      { target: `user:pw@fixture.test:${port}`, status: 400 },
      { target: "fixture.test:22", status: 403, denial: "port_not_allowed" },
      { target: "169.254.169.254:443", status: 403, denial: "port_not_allowed" },
    ];
    for (const row of rows) {
      const seqBefore = proxy.events().at(-1)?.seq ?? 0;
      const t = await connect(proxy, row.target);
      t.socket.destroy();
      assert.equal(t.status, row.status, row.target);
      assert.equal(t.headers[DENIAL], row.denial, row.target);
      const fresh = proxy.events().filter((e) => e.seq > seqBefore);
      assert.deepEqual(
        fresh.map((e) => [e.kind, e.code]),
        row.denial ? [["deny", row.denial]] : [],
        row.target,
      );
    }
    assert.deepEqual(hits, [], "a tunnel alone sends no request to the origin");
  });
});

// ---------------------------------------------------------------------------
// Phase 1 contract: docs/08-browser-diagnostics-contract.md.
// D1 tests are written before the implementation and fail until it lands. The
// D2 tests are guards for behavior that is already correct.
// ---------------------------------------------------------------------------

/** Proposed in docs/08 §D1; the name needs reviewer approval before it is public. */
const DNS_TIMEOUT_CODE = "dns_timeout";

function resolverError(code: string, message: string): NodeJS.ErrnoException {
  const err = new Error(message) as NodeJS.ErrnoException;
  err.code = code;
  return err;
}

async function startWithResolver(p: EgressPolicy, resolve: (host: string) => Promise<ResolvedAddress[]>): Promise<EgressProxy> {
  const proxy = await startEgressProxy(p, { ...deps, resolve });
  proxies.push(proxy);
  return proxy;
}

const never = () => new Promise<ResolvedAddress[]>(() => {});

describe("D1: name resolution is bounded by connectTimeoutMs", () => {
  // Today the timer starts after resolution, so these requests never get a reply;
  // the 5 s test timeout turns that hang into a failure instead of stalling the run.
  it("plain HTTP: a resolver that never settles ends in 504 and one origin-only error event", { timeout: 5_000 }, async () => {
    const proxy = await startWithResolver(policy({ allowedHosts: parseHostAllowlist("hang.test"), connectTimeoutMs: 300 }), never);
    const started = Date.now();
    const r = await viaProxy(proxy, `http://hang.test:${port}/private/path?token=secret#frag`);
    const elapsed = Date.now() - started;
    assert.equal(r.status, 504, JSON.stringify(r));
    assert.ok(elapsed < 300 + 700, `answered after ${elapsed} ms`);
    assert.equal(r.headers["x-research-browser-denial"], undefined, "a timeout is not a policy denial");
    assert.equal(r.headers["x-research-browser-proxy-error"], DNS_TIMEOUT_CODE);
    const errors = proxy.events().filter((e) => e.kind === "error");
    assert.deepEqual(errors.map((e) => [e.origin, e.code]), [[`http://hang.test:${port}`, DNS_TIMEOUT_CODE]]);
    assert.deepEqual(proxy.denials(), []);
    assert.doesNotMatch(JSON.stringify(proxy.events()) + JSON.stringify(logs) + r.body, /private|token|secret|frag/);
  });

  it("CONNECT: a resolver that never settles ends in 504 and one origin-only error event", { timeout: 5_000 }, async () => {
    const proxy = await startWithResolver(policy({ allowedHosts: parseHostAllowlist("hang.test"), connectTimeoutMs: 300 }), never);
    const started = Date.now();
    const r = await connect(proxy, `hang.test:${port}`);
    r.socket.destroy();
    assert.equal(r.status, 504);
    assert.ok(Date.now() - started < 300 + 700);
    assert.equal(r.headers["x-research-browser-denial"], undefined);
    assert.deepEqual(proxy.events().map((e) => [e.kind, e.code]), [["error", DNS_TIMEOUT_CODE]]);
  });

  it("an answer that arrives after the deadline is never connected to", { timeout: 5_000 }, async () => {
    // The answer is a valid, allowed address: only the deadline should stop the connection.
    const proxy = await startWithResolver(policy({ allowedHosts: parseHostAllowlist("late.test"), connectTimeoutMs: 200 }), () =>
      new Promise((res) => setTimeout(() => res([{ address: "127.0.0.1", family: 4 }]), 500)),
    );
    const r = await viaProxy(proxy, `http://late.test:${port}/late`);
    assert.equal(r.status, 504, JSON.stringify(r));
    // A negative check needs a bounded wait: 600 ms is past the late answer (500 ms) plus a connect on loopback.
    await new Promise((res) => setTimeout(res, 600));
    assert.ok(!hits.includes("/late"), "no request may reach the destination after the deadline");
    assert.ok(!logs.some((l) => l.event === "egress" && l.decision === "allow"), JSON.stringify(logs));
  });
});

describe("D2 guards: resolver errors never leak the resolver's message", () => {
  // Realistic resolver errors carry err.code and a message naming the resolver.
  const MESSAGE = (code: string) => `getaddrinfo ${code} dnserr.test via resolver-10-1-2-3.corp.internal`;
  for (const errno of ["ENOTFOUND", "ENODATA", "EAI_AGAIN", "ESERVFAIL", "ETIMEOUT", "ECONNREFUSED"]) {
    it(`${errno}: one origin-only error event, 502, no denial header, no resolver text`, { timeout: 5_000 }, async () => {
      const proxy = await startWithResolver(policy({ allowedHosts: parseHostAllowlist("dnserr.test") }), async () => {
        throw resolverError(errno, MESSAGE(errno));
      });
      const r = await viaProxy(proxy, `http://dnserr.test:${port}/`);
      assert.equal(r.status, 502, JSON.stringify(r));
      assert.equal(r.headers["x-research-browser-denial"], undefined);
      const errors = proxy.events().filter((e) => e.kind === "error");
      assert.equal(errors.length, 1);
      assert.equal(errors[0]!.origin, `http://dnserr.test:${port}`);
      // Today every resolver failure is dns_resolution_failed. docs/08 §D2 proposes finer codes;
      // until that is approved this guard pins only the privacy property and the family.
      assert.match(errors[0]!.code, /^dns_[a-z_]+$/);
      assert.doesNotMatch(JSON.stringify(proxy.events()) + JSON.stringify(logs) + r.body + JSON.stringify(r.headers), /getaddrinfo|corp\.internal|resolver-10/);
    });
  }
});
