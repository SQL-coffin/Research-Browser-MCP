// Smoke test for the BUILT browser path. Run after `npm run build` (part of
// `npm run test:smoke`). Two parts:
//  - dist/index.js over stdio with the browser enabled: the tools are listed, a
//    session opens, the empty default allowlist refuses navigation before any DNS,
//    and closing the session (and then the server) leaves no browser process behind;
//  - dist/browser/*.js loaded directly and run against a local fixture, through
//    the same injected policy and resolver the unit tests use.
// It needs no network.
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { dirname, join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { chromium } from "playwright-core";

type Actions = typeof import("../../src/browser/actions.js");
type Session = typeof import("../../src/browser/session.js");
type Egress = typeof import("../../src/egress-proxy.js");
type Evidence = typeof import("../../src/evidence.js");
type Handoff = typeof import("../../src/handoff.js");
type Security = typeof import("../../src/security.js");

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const DIST = join(ROOT, "dist");
const SERVER = join(DIST, "index.js");
const fromDist = async <T>(file: string): Promise<T> => (await import(pathToFileURL(join(DIST, file)).href)) as T;

function hasChromium(): boolean {
  try {
    return existsSync(chromium.executablePath());
  } catch {
    return false;
  }
}
const SKIP = !process.env.CI && !hasChromium() && "Chromium not installed for playwright-core";
const TEST = { timeout: 60_000 };

const children = new Set<number>();
process.on("exit", () => {
  for (const pid of children) {
    try {
      process.kill(pid, "SIGKILL");
    } catch {}
  }
});

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function waitForExit(pid: number, ms: number): Promise<boolean> {
  const deadline = Date.now() + ms;
  while (isAlive(pid)) {
    if (Date.now() >= deadline) return false;
    await new Promise((r) => setTimeout(r, 25));
  }
  return true;
}

/** Every process descended from `pid` (Linux /proc; empty elsewhere). */
function descendants(pid: number): number[] {
  if (!existsSync("/proc")) return [];
  const parent = new Map<number, number>();
  for (const name of readdirSync("/proc")) {
    if (!/^\d+$/.test(name)) continue;
    try {
      const stat = readFileSync(`/proc/${name}/stat`, "utf8");
      const ppid = Number(stat.slice(stat.lastIndexOf(")") + 2).split(" ")[1]);
      parent.set(Number(name), ppid);
    } catch {}
  }
  const out: number[] = [];
  const walk = (p: number) => {
    for (const [child, pp] of parent) {
      if (pp === p) {
        out.push(child);
        walk(child);
      }
    }
  };
  walk(pid);
  return out;
}

function withTimeout<T>(promise: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${what} timed out after ${ms} ms`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

function start(env: Record<string, string>) {
  // Only what the browser needs to find its build is passed through; no allowlist.
  const passthrough = process.env.PLAYWRIGHT_BROWSERS_PATH ? { PLAYWRIGHT_BROWSERS_PATH: process.env.PLAYWRIGHT_BROWSERS_PATH } : {};
  const transport = new StdioClientTransport({ command: process.execPath, args: [SERVER], env: { ...passthrough, ...env }, cwd: ROOT, stderr: "pipe" });
  let stderr = "";
  transport.stderr?.on("data", (c) => (stderr += String(c)));
  const client = new Client({ name: "dist-browser-smoke", version: "0.0.0" });
  const ready = client.connect(transport);
  ready.catch(() => {});
  const pid = transport.pid!;
  children.add(pid);
  const call = async (name: string, args: Record<string, unknown> = {}) =>
    (await withTimeout(client.callTool({ name, arguments: args }), 30_000, name)).structuredContent as Record<string, any>;
  return {
    client,
    pid,
    ready,
    call,
    stderr: () => stderr,
    async stop() {
      await client.close().catch(() => {});
      if (!(await waitForExit(pid, 10_000))) {
        process.kill(pid, "SIGKILL");
        await waitForExit(pid, 2_000);
      }
      assert.ok(!isAlive(pid), `server ${pid} still running`);
      children.delete(pid);
    },
  };
}

describe("built server with the browser enabled (dist/index.js)", { skip: SKIP }, () => {
  it("lists the browser tools, refuses navigation under the empty default allowlist, and cleans up", TEST, async () => {
    const s = start({ RESEARCH_BROWSER_ENABLE_BROWSER: "1" });
    try {
      await withTimeout(s.ready, 10_000, "initialize");
      const { tools } = await s.client.listTools();
      for (const t of ["browser.open_session", "browser.navigate", "browser.snapshot", "browser.click", "browser.type", "browser.scroll", "browser.screenshot", "browser.pause_for_human", "browser.resume_session", "browser.close_session"]) {
        assert.ok(tools.some((x) => x.name === t), t);
      }
      const opened = await s.call("browser.open_session");
      assert.equal(opened.status, "success", JSON.stringify(opened) + s.stderr());
      const browserProcs = descendants(s.pid);
      if (existsSync("/proc")) assert.ok(browserProcs.length > 0, "a browser process runs under the server");

      const nav = await s.call("browser.navigate", { session_id: opened.session_id, url: "https://example.org/" });
      assert.equal(nav.status, "policy_denied");
      assert.equal(nav.error.code, "host_allowlist_empty");

      const snap = await s.call("browser.snapshot", { session_id: opened.session_id });
      assert.equal(snap.status, "success");

      const closed = await s.call("browser.close_session", { session_id: opened.session_id });
      assert.equal(closed.status, "success");
      for (const pid of browserProcs) assert.ok(await waitForExit(pid, 5_000), `browser process ${pid} survived close_session`);
      assert.match(s.stderr(), /RESEARCH_BROWSER_ALLOWED_HOSTS is empty/);
    } finally {
      await s.stop();
    }
  });

  it("closes open browser sessions when the client disconnects", TEST, async () => {
    const s = start({ RESEARCH_BROWSER_ENABLE_BROWSER: "1" });
    let browserProcs: number[] = [];
    try {
      await withTimeout(s.ready, 10_000, "initialize");
      const opened = await s.call("browser.open_session");
      assert.equal(opened.status, "success");
      browserProcs = descendants(s.pid);
    } finally {
      await s.stop();
    }
    for (const pid of browserProcs) assert.ok(await waitForExit(pid, 5_000), `browser process ${pid} outlived the server`);
  });

  it("refuses to start with an invalid browser setting", TEST, async () => {
    const s = start({ RESEARCH_BROWSER_ENABLE_BROWSER: "sometimes" });
    await assert.rejects(withTimeout(s.ready, 10_000, "initialize"));
    assert.ok(await waitForExit(s.pid, 5_000));
    children.delete(s.pid);
    assert.match(s.stderr(), /fatal: RESEARCH_BROWSER_ENABLE_BROWSER/);
  });
});

describe("built browser modules against a local fixture (dist/browser)", { skip: SKIP }, () => {
  let actions!: Actions;
  let session!: Session;
  let egress!: Egress;
  let evidence!: Evidence;
  let handoff!: Handoff;
  let security!: Security;
  let server: http.Server;
  let port: number;

  before(async () => {
    actions = await fromDist<Actions>("browser/actions.js");
    session = await fromDist<Session>("browser/session.js");
    egress = await fromDist<Egress>("egress-proxy.js");
    evidence = await fromDist<Evidence>("evidence.js");
    handoff = await fromDist<Handoff>("handoff.js");
    security = await fromDist<Security>("security.js");
    server = http.createServer((req, res) => {
      if (req.url === "/captcha") {
        res.writeHead(200, { "content-type": "text/html" });
        res.end('<title>Check</title><iframe src="https://challenges.cloudflare.com/turnstile"></iframe>');
        return;
      }
      res.writeHead(200, { "content-type": "text/html" });
      res.end('<title>Built</title><p>Built browser path.</p><a href="/x">Link</a>');
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    port = (server.address() as AddressInfo).port;
  });
  after(() => {
    server.closeAllConnections();
    server.close();
  });

  it("navigates, snapshots and pauses on a challenge", TEST, async () => {
    const agent = new actions.BrowserAgent(
      {
        ...session.DEFAULT_BROWSER_CONFIG,
        egress: {
          ...egress.DEFAULT_EGRESS_POLICY,
          allowedSchemes: new Set(["http:"]),
          allowedPorts: new Set([port]),
          allowedHosts: security.parseHostAllowlist("fixture.test"),
          isAddressAllowed: (ip: string) => (ip === "127.0.0.1" ? { allowed: true as const } : security.classifyAddress(ip)),
        },
      },
      { resolve: async () => [{ address: "127.0.0.1", family: 4 as const }], log: () => {}, now: () => new Date(), evidence: evidence.NO_EVIDENCE, handoff: new handoff.HandoffStore() },
    );
    try {
      const opened = await agent.openSession();
      const id = opened.session_id!;
      const nav = await agent.navigate(id, `http://fixture.test:${port}/`);
      assert.equal(nav.status, "success", JSON.stringify(nav));
      const snap = await agent.snapshot(id);
      assert.equal(snap.title, "Built");
      assert.ok((snap.elements as { name: string }[]).some((e) => e.name === "Link"));
      const blocked = await agent.navigate(id, `http://fixture.test:${port}/captcha`);
      assert.equal(blocked.status, "human_verification_required");
      assert.equal(blocked.session_state, "BLOCKED");
    } finally {
      await agent.closeAll();
    }
  });
});
