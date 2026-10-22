// Smoke test for the BUILT server: runs `node dist/index.js` as a child process and
// drives it over stdio with the MCP SDK's StdioClientTransport. Run after
// `npm run build` with `npm run test:smoke`. It needs no network: every fetch it
// makes is refused before DNS.
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { after, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SERVER = join(ROOT, "dist", "index.js");
const EXPECTED_TOOLS = ["research.fetch_public_page", "research.inspect_challenge", "research.pause_for_human", "research.resume", "research.search"];
const TEST = { timeout: 30_000 };

// Every child this file starts. The exit hook is the last line of defence: even if
// a test is cancelled mid-flight, no server process outlives the test runner.
const children = new Set<number>();
process.on("exit", () => {
  for (const pid of children) {
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      // already gone
    }
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

function withTimeout<T>(promise: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${what} timed out after ${ms} ms`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/**
 * Spawns a stdio MCP server (dist/index.js unless `args` says otherwise) and starts
 * the initialize handshake. `stop()` must run in a finally block: it closes the
 * client (stdin EOF, then SIGTERM, then SIGKILL inside the SDK), escalates to
 * SIGKILL itself if the process is still there, and fails if it survives.
 */
function start(opts: { env?: Record<string, string>; args?: string[] } = {}) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: opts.args ?? [SERVER],
    // The transport passes only PATH, HOME and similar plus `env`, so no allowlist,
    // provider key or other credential leaks in from the shell running the tests.
    env: opts.env ?? {},
    cwd: ROOT,
    stderr: "pipe",
  });
  let stderr = "";
  transport.stderr?.on("data", (chunk) => (stderr += String(chunk)));
  const client = new Client({ name: "dist-smoke", version: "0.0.0" });
  // connect() spawns the child synchronously, then performs initialize.
  const ready = client.connect(transport);
  ready.catch(() => {}); // callers observe it through withTimeout
  const pid = transport.pid;
  assert.ok(pid, "server process did not spawn");
  children.add(pid);
  return {
    client,
    pid,
    ready,
    stderr: () => stderr,
    async stop() {
      await client.close().catch(() => {});
      if (!(await waitForExit(pid, 5_000))) {
        process.kill(pid, "SIGKILL");
        await waitForExit(pid, 2_000);
      }
      assert.ok(!isAlive(pid), `server process ${pid} is still running`);
      children.delete(pid);
    },
  };
}

async function fetchVia(client: Client, args: Record<string, unknown>) {
  const r = await withTimeout(client.callTool({ name: "research.fetch_public_page", arguments: args }), 5_000, "tools/call");
  return r.structuredContent as { status: string; error?: { code: string } };
}

after(() => {
  const leftover = [...children].filter(isAlive);
  for (const pid of leftover) process.kill(pid, "SIGKILL");
  assert.deepEqual(leftover, [], "server processes were left running");
});

describe("built server over stdio (dist/index.js)", () => {
  it("has been built", () => {
    assert.ok(existsSync(SERVER), "dist/index.js is missing: run `npm run build` first");
  });

  it("answers initialize and tools/list with the five research tools", TEST, async () => {
    const s = start();
    try {
      await withTimeout(s.ready, 10_000, "initialize");
      assert.equal(s.client.getServerVersion()?.name, "research-browser-mcp");
      const { tools } = await withTimeout(s.client.listTools(), 5_000, "tools/list");
      assert.deepEqual(tools.map((t) => t.name).sort(), EXPECTED_TOOLS);
    } finally {
      await s.stop();
    }
  });

  it("denies fetching when no hosts are configured, and says so on stderr", TEST, async () => {
    const s = start();
    try {
      await withTimeout(s.ready, 10_000, "initialize");
      const r = await fetchVia(s.client, { url: "https://example.org/", allowed_hosts: ["example.org"] });
      assert.equal(r.status, "policy_denied");
      assert.equal(r.error?.code, "host_allowlist_empty");
    } finally {
      await s.stop();
    }
    assert.match(s.stderr(), /RESEARCH_BROWSER_ALLOWED_HOSTS is empty/);
  });

  it("reads the allowlist from RESEARCH_BROWSER_ALLOWED_HOSTS", TEST, async () => {
    const s = start({ env: { RESEARCH_BROWSER_ALLOWED_HOSTS: "example.org" } });
    try {
      await withTimeout(s.ready, 10_000, "initialize");
      // Neither request reaches the network: the allowlist refuses one, the address policy the other.
      assert.equal((await fetchVia(s.client, { url: "https://example.com/" })).error?.code, "host_not_allowlisted");
      assert.equal((await fetchVia(s.client, { url: "https://127.0.0.1/" })).error?.code, "address_loopback");
    } finally {
      await s.stop();
    }
    assert.doesNotMatch(s.stderr(), /is empty/);
  });

  it("refuses to start with an invalid allowlist entry and leaves no process behind", TEST, async () => {
    const s = start({ env: { RESEARCH_BROWSER_ALLOWED_HOSTS: "example.org, *" } });
    try {
      await assert.rejects(withTimeout(s.ready, 10_000, "initialize"));
    } finally {
      await s.stop();
    }
    assert.match(s.stderr(), /Invalid host allowlist entry at position 2/);
  });

  it("times out a server that never answers and kills it even though it ignores SIGTERM", TEST, async () => {
    // A stand-in for a hung server: it never answers initialize and ignores SIGTERM.
    const s = start({ args: ["-e", "process.on('SIGTERM', () => {}); setInterval(() => {}, 1000);"] });
    try {
      await assert.rejects(withTimeout(s.ready, 1_000, "initialize"), /timed out/);
    } finally {
      await s.stop();
    }
    assert.equal(isAlive(s.pid), false);
  });

  it("still stops the server when the test body throws", TEST, async () => {
    const s = start();
    await assert.rejects(
      (async () => {
        try {
          await withTimeout(s.ready, 10_000, "initialize");
          throw new Error("simulated failure");
        } finally {
          await s.stop();
        }
      })(),
      /simulated failure/,
    );
    assert.equal(isAlive(s.pid), false);
  });
});
