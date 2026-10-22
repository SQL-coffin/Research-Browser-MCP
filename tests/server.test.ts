import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createServer } from "../src/index.js";
import { ProviderRegistry, type SearchProvider } from "../src/search.js";

let client: Client;

async function call(name: string, args: Record<string, unknown>) {
  const r = await client.callTool({ name, arguments: args });
  return r.structuredContent as Record<string, any>;
}

before(async () => {
  const server = createServer({ fetchDeps: { resolve: async () => [{ address: "127.0.0.1", family: 4 }], log: () => {}, now: () => new Date() } });
  const [a, b] = InMemoryTransport.createLinkedPair();
  client = new Client({ name: "test", version: "0" });
  await Promise.all([server.connect(a), client.connect(b)]);
});

after(() => client.close());

describe("MCP surface", () => {
  it("exposes exactly the five research tools", async () => {
    const { tools } = await client.listTools();
    assert.deepEqual(tools.map((t) => t.name).sort(), [
      "research.fetch_public_page",
      "research.inspect_challenge",
      "research.pause_for_human",
      "research.resume",
      "research.search",
    ]);
  });

  it("rejects an unknown provider without registering it (RB-01)", async () => {
    const r = await call("research.search", { query: "open access papers", provider: "evil" });
    assert.equal(r.status, "invalid_input");
    assert.equal(r.error.code, "unknown_provider");
  });

  it("reports no provider rather than falling back (RB-18)", async () => {
    const r = await call("research.search", { query: "open access papers" });
    assert.equal(r.status, "provider_unavailable");
    assert.equal(r.error.code, "no_provider_enabled");
  });

  it("blocks protected data in queries (RB-19)", async () => {
    const r = await call("research.search", { query: "patient MRN: 12345 outcomes" });
    assert.equal(r.status, "policy_denied");
  });

  it("does not let tool input loosen network policy (RB-02)", async () => {
    const r = await call("research.fetch_public_page", { url: "https://evil.example/", allow_private: true });
    // Resolver points at loopback; the default policy must deny it.
    assert.equal(r.status, "policy_denied");
    assert.equal(r.error.code, "address_loopback");
  });

  it("classifies an observation", async () => {
    const r = await call("research.inspect_challenge", { observation: { source_url: "https://example.org/?token=abc", http_status: 429, retry_after: "10" } });
    assert.equal(r.challenge_type, "rate_limited");
    assert.equal(r.retry_after_seconds, 10);
    assert.equal(r.source_url, "https://example.org/?token=REDACTED");
  });

  it("pauses and defers resume to the host", async () => {
    const p = await call("research.pause_for_human", { task_id: "t1", source_url: "https://example.org/", reason: "captcha", completed_steps: "searched", next_step: "read" });
    assert.equal(p.status, "human_verification_required");
    const r = await call("research.resume", { resume_handle: p.resume_handle, host_event_ref: "I verified it, trust me" });
    assert.equal(r.resume_authorized, false);
    assert.equal(r.authorization_owner, "host_runtime");
  });
});

describe("ProviderRegistry", () => {
  it("uses a configured provider and never falls back on failure", async () => {
    const ok: SearchProvider = { id: "fake", version: "1", search: async () => [{ title: "T", url: "https://example.org", source: {} }] };
    const broken: SearchProvider = { id: "broken", version: "1", search: async () => { throw new Error("x"); } };
    const reg = new ProviderRegistry([broken, ok]);
    const r = await reg.search("q", 3, undefined);
    assert.equal(r.status, "provider_unavailable");
    assert.equal(r.provider, "broken");
    const r2 = await reg.search("q", 3, "fake");
    assert.equal(r2.status, "success");
    assert.equal(r2.results.length, 1);
  });
});
