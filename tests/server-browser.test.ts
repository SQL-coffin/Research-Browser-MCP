import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { chromium } from "playwright-core";
import { BrowserAgent } from "../src/browser/actions.js";
import { DEFAULT_BROWSER_CONFIG } from "../src/browser/session.js";
import { DEFAULT_EGRESS_POLICY } from "../src/egress-proxy.js";
import { EVIDENCE_DIR_ENV, FileEvidenceStore } from "../src/evidence.js";
import { DEFAULT_FETCH_POLICY } from "../src/fetcher.js";
import { HandoffStore } from "../src/handoff.js";
import {
  ALLOWED_HOSTS_ENV,
  BROWSER_ENV,
  browserConfigFromEnv,
  CHROMIUM_PATH_ENV,
  CHROMIUM_SANDBOX_ENV,
  createServer,
  FORM_SUBMIT_HOSTS_ENV,
  HEADED_ENV,
  type ServerOptions,
} from "../src/index.js";
import { classifyAddress, isHostAllowlistEmpty, isUrlHostListed, ORIGIN_ONLY, parseHostAllowlist } from "../src/security.js";

const SKIP = !process.env.CI && !hasChromium() && "Chromium not installed for playwright-core";
function hasChromium(): boolean {
  try {
    return existsSync(chromium.executablePath());
  } catch {
    return false;
  }
}

const clients: Client[] = [];
async function connect(opts: ServerOptions = {}) {
  const server = createServer(opts);
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test", version: "0" });
  await Promise.all([server.connect(a), client.connect(b)]);
  clients.push(client);
  const raw = (name: string, args: Record<string, unknown>) => client.callTool({ name, arguments: args });
  const call = async (name: string, args: Record<string, unknown>) => (await raw(name, args)).structuredContent as Record<string, any>;
  return { client, call, raw };
}
after(async () => {
  for (const c of clients) await c.close();
});

const BROWSER_TOOLS = [
  "browser.click",
  "browser.close_session",
  "browser.navigate",
  "browser.open_session",
  "browser.pause_for_human",
  "browser.resume_session",
  "browser.screenshot",
  "browser.scroll",
  "browser.snapshot",
  "browser.type",
];

describe("browserConfigFromEnv", () => {
  const policy = { ...DEFAULT_FETCH_POLICY, allowedHosts: parseHostAllowlist("example.org") };

  it("is off unless enabled explicitly", () => {
    assert.equal(browserConfigFromEnv({}, policy, ORIGIN_ONLY), null);
    assert.equal(browserConfigFromEnv({ [BROWSER_ENV]: "0" }, policy, ORIGIN_ONLY), null);
    assert.equal(browserConfigFromEnv({ [BROWSER_ENV]: "false" }, policy, ORIGIN_ONLY), null);
  });

  it("rejects a value that is not a clear boolean", () => {
    assert.throws(() => browserConfigFromEnv({ [BROWSER_ENV]: "yes please" }, policy, ORIGIN_ONLY), new RegExp(BROWSER_ENV));
    assert.throws(() => browserConfigFromEnv({ [BROWSER_ENV]: "1", [HEADED_ENV]: "maybe" }, policy, ORIGIN_ONLY), new RegExp(HEADED_ENV));
  });

  it("takes the network policy from the fetch policy: same allowlist, schemes, ports and address check", () => {
    const config = browserConfigFromEnv({ [BROWSER_ENV]: "1" }, policy, ORIGIN_ONLY)!;
    assert.equal(config.egress.allowedHosts, policy.allowedHosts);
    assert.equal(config.egress.allowedSchemes, policy.allowedSchemes);
    assert.equal(config.egress.allowedPorts, policy.allowedPorts);
    assert.equal(config.egress.isAddressAllowed, policy.isAddressAllowed);
    assert.deepEqual([...config.egress.allowedMethods], ["GET", "HEAD"]);
    assert.ok(isHostAllowlistEmpty(config.egress.formSubmitHosts));
    assert.equal(config.headless, true);
    assert.equal(config.chromiumSandbox, false);
  });

  it("reads headed mode, sandbox, Chromium path and form-submit hosts", () => {
    const config = browserConfigFromEnv(
      { [BROWSER_ENV]: "true", [HEADED_ENV]: "1", [CHROMIUM_SANDBOX_ENV]: "1", [CHROMIUM_PATH_ENV]: "/opt/chrome/chrome", [FORM_SUBMIT_HOSTS_ENV]: "example.org" },
      policy,
      ORIGIN_ONLY,
    )!;
    assert.equal(config.headless, false);
    assert.equal(config.chromiumSandbox, true);
    assert.equal(config.executablePath, "/opt/chrome/chrome");
    assert.ok(isUrlHostListed(new URL("https://example.org/"), config.egress.formSubmitHosts));
  });

  it("rejects a relative Chromium path and invalid form-submit hosts", () => {
    assert.throws(() => browserConfigFromEnv({ [BROWSER_ENV]: "1", [CHROMIUM_PATH_ENV]: "chrome" }, policy, ORIGIN_ONLY), /absolute/);
    assert.throws(() => browserConfigFromEnv({ [BROWSER_ENV]: "1", [FORM_SUBMIT_HOSTS_ENV]: "*.example.org" }, policy, ORIGIN_ONLY), new RegExp(FORM_SUBMIT_HOSTS_ENV));
  });

  it("the allowlist variable is still the only source of reachable hosts", () => {
    assert.equal(ALLOWED_HOSTS_ENV, "RESEARCH_BROWSER_ALLOWED_HOSTS");
  });
});

describe("MCP surface without the browser", () => {
  it("registers no browser tools unless a browser agent is configured", async () => {
    const { client } = await connect();
    const { tools } = await client.listTools();
    assert.ok(!tools.some((t) => t.name.startsWith("browser.")));
  });
});

describe("MCP browser tools", { skip: SKIP }, () => {
  let server: http.Server;
  let port: number;
  let root: string;
  let agent: BrowserAgent;
  let mcp: Awaited<ReturnType<typeof connect>>;

  before(async () => {
    root = mkdtempSync(join(tmpdir(), "rbmcp-mcp-browser-"));
    server = http.createServer((req, res) => {
      if (req.url === "/captcha") {
        res.writeHead(403, { "content-type": "text/html" });
        res.end('<title>Check</title><div class="h-captcha"></div>');
        return;
      }
      res.writeHead(200, { "content-type": "text/html" });
      res.end('<title>MCP page</title><p>Hello from the fixture.</p><a href="/b?secret=1">Go</a><input aria-label="Search">');
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    port = (server.address() as AddressInfo).port;
    const handoff = new HandoffStore();
    agent = new BrowserAgent(
      {
        ...DEFAULT_BROWSER_CONFIG,
        egress: {
          ...DEFAULT_EGRESS_POLICY,
          allowedSchemes: new Set(["http:"]),
          allowedPorts: new Set([port]),
          allowedHosts: parseHostAllowlist("fixture.test"),
          isAddressAllowed: (ip) => (ip === "127.0.0.1" ? { allowed: true } : classifyAddress(ip)),
        },
      },
      {
        resolve: async (h) => (h === "fixture.test" ? [{ address: "127.0.0.1", family: 4 }] : []),
        log: () => {},
        now: () => new Date(),
        evidence: new FileEvidenceStore(root),
        handoff,
      },
    );
    mcp = await connect({ browser: agent, handoff });
  });
  after(async () => {
    await agent.closeAll();
    server.closeAllConnections();
    server.close();
    rmSync(root, { recursive: true, force: true });
  });

  it("lists the browser tools next to the research tools, with no policy arguments", async () => {
    const { tools } = await mcp.client.listTools();
    const names = tools.map((t) => t.name);
    for (const t of BROWSER_TOOLS) assert.ok(names.includes(t), t);
    for (const t of tools.filter((x) => x.name.startsWith("browser."))) {
      const props = Object.keys(t.inputSchema.properties ?? {});
      assert.ok(!props.some((p) => /^hosts?$|allow|proxy|policy|header|cookie|timeout|sandbox|executable/i.test(p)), `${t.name}: ${props.join(",")}`);
    }
  });

  it("drives a session end to end: open, navigate, snapshot, type, scroll, screenshot, close", async () => {
    const opened = await mcp.call("browser.open_session", {});
    assert.equal(opened.status, "success");
    const session_id = opened.session_id as string;

    const nav = await mcp.call("browser.navigate", { session_id, url: `http://fixture.test:${port}/` });
    assert.equal(nav.status, "success", JSON.stringify(nav));
    assert.equal(nav.title, "MCP page");
    assert.equal(nav.evidence[0].evidence_status, "persisted");

    const snap = await mcp.call("browser.snapshot", { session_id });
    assert.equal(snap.status, "success");
    assert.equal(snap.untrusted_content, true);
    assert.match(snap.text, /Hello from the fixture/);
    const search = snap.elements.find((e: { name: string }) => e.name === "Search");
    assert.doesNotMatch(JSON.stringify(snap), /secret=1/);

    const typed = await mcp.call("browser.type", { session_id, index: search.index, text: "query" });
    assert.equal(typed.status, "success");
    const scrolled = await mcp.call("browser.scroll", { session_id, direction: "down" });
    assert.equal(scrolled.status, "success");

    const shot = await mcp.raw("browser.screenshot", { session_id });
    const content = shot.content as { type: string; mimeType?: string; data?: string }[];
    const image = content.find((c) => c.type === "image");
    assert.equal(image?.mimeType, "image/png");
    assert.ok(Buffer.from(image!.data!, "base64").subarray(0, 4).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47])));
    assert.equal((shot.structuredContent as Record<string, unknown>).status, "success");

    const closed = await mcp.call("browser.close_session", { session_id });
    assert.equal(closed.status, "success");
    assert.equal(agent.sessionCount, 0);
  });

  it("returns the pause instead of content when a challenge appears", async () => {
    const { session_id } = await mcp.call("browser.open_session", {});
    const nav = await mcp.call("browser.navigate", { session_id, url: `http://fixture.test:${port}/captcha` });
    assert.equal(nav.status, "human_verification_required");
    assert.equal(nav.session_state, "BLOCKED");
    const shot = await mcp.raw("browser.screenshot", { session_id });
    assert.ok(!(shot.content as { type: string }[]).some((c) => c.type === "image"));
    const resumed = await mcp.call("browser.resume_session", { session_id, host_event_ref: "i-solved-it" });
    assert.equal(resumed.session_state, "BLOCKED");
    await mcp.call("browser.close_session", { session_id });
  });

  it("validates tool input at the schema", async () => {
    const r = await mcp.raw("browser.click", { session_id: "not-a-uuid", index: 0 });
    assert.equal(r.isError, true);
  });

  it("denies a non-allowlisted URL through the tool", async () => {
    const { session_id } = await mcp.call("browser.open_session", {});
    const r = await mcp.call("browser.navigate", { session_id, url: "http://example.org/" });
    assert.equal(r.status, "policy_denied");
    await mcp.call("browser.close_session", { session_id });
  });
});

describe("evidence wiring for the fetch tool", () => {
  it("persists fetched bodies through the configured store", async () => {
    const root = mkdtempSync(join(tmpdir(), "rbmcp-mcp-fetch-"));
    const srv = http.createServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/html" });
      res.end("<title>F</title><p>fetched</p>");
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const port = (srv.address() as AddressInfo).port;
    try {
      const { call } = await connect({
        fetchPolicy: {
          ...DEFAULT_FETCH_POLICY,
          allowedSchemes: new Set(["http:"]),
          allowedPorts: new Set([port]),
          allowedHosts: parseHostAllowlist("fixture.test"),
          isAddressAllowed: (ip) => (ip === "127.0.0.1" ? { allowed: true } : classifyAddress(ip)),
        },
        fetchDeps: { resolve: async () => [{ address: "127.0.0.1", family: 4 }], log: () => {}, now: () => new Date() },
        evidence: new FileEvidenceStore(root),
      });
      const r = await call("research.fetch_public_page", { url: `http://fixture.test:${port}/` });
      assert.equal(r.status, "success", JSON.stringify(r));
      assert.equal(r.evidence_status, "persisted");
      assert.equal(r.evidence_persisted, true);
      assert.ok(existsSync(join(root, "objects", "sha256", r.content_hash.value)));
      assert.equal(EVIDENCE_DIR_ENV, "RESEARCH_BROWSER_EVIDENCE_DIR");
    } finally {
      srv.close();
      rmSync(root, { recursive: true, force: true });
    }
  });
});
