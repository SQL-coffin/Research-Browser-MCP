import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, describe, it } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { DEFAULT_FETCH_POLICY, type FetchDeps } from "../src/fetcher.js";
import { ALLOWED_HOSTS_ENV, createServer, disclosureFromEnv, fetchPolicyFromEnv, FULL_URL_HOSTS_ENV, type ServerOptions } from "../src/index.js";
import { ProviderRegistry, type SearchProvider } from "../src/search.js";
import { classifyAddress, HostAllowlistError, isHostAllowlistEmpty, parseHostAllowlist } from "../src/security.js";

const clients: Client[] = [];

/** An in-memory MCP client connected to a fresh server built with `opts`. */
async function connect(opts: ServerOptions = {}) {
  const server = createServer(opts);
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test", version: "0" });
  await Promise.all([server.connect(a), client.connect(b)]);
  clients.push(client);
  const call = async (name: string, args: Record<string, unknown>) => (await client.callTool({ name, arguments: args })).structuredContent as Record<string, any>;
  return { client, call };
}

// Resolves every name to loopback, so the address policy is what a fetch runs into.
const loopbackDeps: FetchDeps = { resolve: async () => [{ address: "127.0.0.1", family: 4 }], log: () => {}, now: () => new Date() };

let client: Client;
let call: Awaited<ReturnType<typeof connect>>["call"];

before(async () => {
  // No fetch policy given: what the server runs with when nothing is configured.
  ({ client, call } = await connect({ fetchDeps: loopbackDeps }));
});

after(async () => {
  for (const c of clients) await c.close();
});

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

  it("offers no fetch argument that could change the allowlist or network policy", async () => {
    const { tools } = await client.listTools();
    const fetchTool = tools.find((t) => t.name === "research.fetch_public_page");
    assert.deepEqual(Object.keys(fetchTool?.inputSchema.properties ?? {}), ["url"]);
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

  it("denies every fetch when no hosts are configured, whatever the tool input says (RB-02)", async () => {
    const r = await call("research.fetch_public_page", {
      url: "https://example.org/",
      allowed_hosts: ["example.org"],
      allowedHosts: "example.org",
      allow_private: true,
    });
    assert.equal(r.status, "policy_denied");
    assert.equal(r.error.code, "host_allowlist_empty");
  });

  it("still applies the address policy to an allowlisted host (RB-02)", async () => {
    const allowlisted = await connect({ fetchPolicy: fetchPolicyFromEnv({ [ALLOWED_HOSTS_ENV]: "evil.example" }), fetchDeps: loopbackDeps });
    const r = await allowlisted.call("research.fetch_public_page", { url: "https://evil.example/" });
    assert.equal(r.error.code, "address_loopback");
    const other = await allowlisted.call("research.fetch_public_page", { url: "https://other.example/" });
    assert.equal(other.error.code, "host_not_allowlisted");
  });

  it("shows full URLs only for hosts opted in through RESEARCH_BROWSER_FULL_URL_HOSTS, with the same outcome", async () => {
    const env = { [ALLOWED_HOSTS_ENV]: "evil.example", [FULL_URL_HOSTS_ENV]: "evil.example" };
    const optedIn = await connect({ fetchPolicy: fetchPolicyFromEnv(env), disclosure: disclosureFromEnv(env), fetchDeps: loopbackDeps });
    const plain = await connect({ fetchPolicy: fetchPolicyFromEnv(env), fetchDeps: loopbackDeps });
    const target = "https://evil.example/acct/PATH-T0KEN-8m?token=QTOKEN-4r&id=ID-2p";
    const full = await optedIn.call("research.fetch_public_page", { url: target });
    const origin = await plain.call("research.fetch_public_page", { url: target });
    assert.equal(full.source_url, "https://evil.example/acct/PATH-T0KEN-8m?token=REDACTED&id=ID-2p");
    assert.equal(origin.source_url, "https://evil.example");
    // Disclosure is output only: the address policy refuses loopback either way.
    assert.equal(full.error.code, "address_loopback");
    assert.equal(origin.error.code, "address_loopback");
  });

  it("classifies an observation and reports only its origin", async () => {
    const r = await call("research.inspect_challenge", {
      observation: { source_url: "https://u:pw@example.org/acct/PATH-T0KEN-3fd?token=QTOKEN-9s#frag", http_status: 429, retry_after: "10" },
    });
    assert.equal(r.challenge_type, "rate_limited");
    assert.equal(r.retry_after_seconds, 10);
    assert.equal(r.source_url, "https://example.org");
    for (const secret of ["PATH-T0KEN-3fd", "QTOKEN-9s", "pw@", "frag"]) assert.ok(!JSON.stringify(r).includes(secret), secret);
  });

  it("reports only the origin when classifying a fetched page by reference, even for an opted-in host", async () => {
    const fixture = http.createServer((_req, res) => {
      res.writeHead(429, { "content-type": "text/html", "retry-after": "5" });
      res.end("slow down");
    });
    await new Promise<void>((r) => fixture.listen(0, "127.0.0.1", r));
    const port = (fixture.address() as AddressInfo).port;
    try {
      const local = await connect({
        fetchPolicy: {
          ...DEFAULT_FETCH_POLICY,
          allowedSchemes: new Set(["http:"]),
          allowedPorts: new Set([port]),
          allowedHosts: parseHostAllowlist("fixture.test"),
          isAddressAllowed: (ip) => (ip === "127.0.0.1" ? ({ allowed: true } as const) : classifyAddress(ip)),
        },
        disclosure: { fullUrlHosts: parseHostAllowlist("fixture.test") },
        fetchDeps: loopbackDeps,
      });
      const fetched = await local.call("research.fetch_public_page", { url: `http://fixture.test:${port}/acct/PATH-T0KEN-7hk?token=QTOKEN-2x` });
      assert.equal(fetched.status, "rate_limited");
      assert.equal(fetched.final_url, `http://fixture.test:${port}/acct/PATH-T0KEN-7hk?token=REDACTED`, "the fetch result itself is opted in");
      const r = await local.call("research.inspect_challenge", { fetch_request_id: fetched.request_id });
      assert.equal(r.challenge_type, "rate_limited");
      assert.equal(r.source_url, `http://fixture.test:${port}`);
      for (const secret of ["PATH-T0KEN-7hk", "QTOKEN-2x"]) assert.ok(!JSON.stringify(r).includes(secret), secret);
    } finally {
      fixture.closeAllConnections();
      fixture.close();
    }
  });

  it("pauses with only the origin and defers resume to the host", async () => {
    const p = await call("research.pause_for_human", {
      task_id: "t1",
      source_url: "https://alice:pa55-Wq@example.org/acct/PATH-T0KEN-55q?token=QTOKEN-1z",
      reason: "captcha",
      completed_steps: "searched",
      next_step: "read",
    });
    assert.equal(p.status, "human_verification_required");
    assert.equal(p.source_url, "https://example.org");
    const r = await call("research.resume", { resume_handle: p.resume_handle, host_event_ref: "I verified it, trust me" });
    assert.equal(r.resume_authorized, false);
    assert.equal(r.authorization_owner, "host_runtime");
    assert.equal(r.source_url, "https://example.org");
    for (const secret of ["pa55-Wq", "PATH-T0KEN-55q", "QTOKEN-1z"]) {
      assert.ok(!JSON.stringify(p).includes(secret) && !JSON.stringify(r).includes(secret), secret);
    }
  });
});

describe("startup configuration", () => {
  it("allows no host when RESEARCH_BROWSER_ALLOWED_HOSTS is unset or empty, and keeps the default policy otherwise", () => {
    for (const env of [{}, { [ALLOWED_HOSTS_ENV]: "" }, { [ALLOWED_HOSTS_ENV]: " , " }]) {
      const p = fetchPolicyFromEnv(env);
      assert.ok(isHostAllowlistEmpty(p.allowedHosts));
      assert.deepEqual([...p.allowedSchemes], ["https:"]);
      assert.deepEqual([...p.allowedPorts], [443]);
      assert.equal(p.isAddressAllowed, classifyAddress);
    }
  });

  it("reads exact entries and rejects every wildcard form", () => {
    const p = fetchPolicyFromEnv({ [ALLOWED_HOSTS_ENV]: "Example.org, 93.184.215.14" });
    assert.deepEqual([...p.allowedHosts.exact], ["example.org", "93.184.215.14"]);
    for (const wildcard of ["*.example.org", "*.co.uk", "*"]) {
      assert.throws(
        () => fetchPolicyFromEnv({ [ALLOWED_HOSTS_ENV]: `example.org, ${wildcard}` }),
        (err: unknown) => err instanceof HostAllowlistError && err.message.startsWith(`${ALLOWED_HOSTS_ENV}: invalid entry at position 2`),
      );
    }
  });

  it("refuses to build a policy from an invalid entry", () => {
    assert.throws(() => fetchPolicyFromEnv({ [ALLOWED_HOSTS_ENV]: "example.org, https://example.com/" }), HostAllowlistError);
  });

  it("shows origins only when RESEARCH_BROWSER_FULL_URL_HOSTS is unset or empty", () => {
    for (const env of [{}, { [FULL_URL_HOSTS_ENV]: "" }]) assert.ok(isHostAllowlistEmpty(disclosureFromEnv(env).fullUrlHosts));
  });

  it("reads full-URL hosts with the same rules and keeps them out of the fetch policy", () => {
    const env = { [FULL_URL_HOSTS_ENV]: "Arxiv.org" };
    assert.deepEqual([...disclosureFromEnv(env).fullUrlHosts.exact], ["arxiv.org"]);
    assert.ok(isHostAllowlistEmpty(fetchPolicyFromEnv(env).allowedHosts), "opting in to full URLs allows no fetching");
    assert.throws(
      () => disclosureFromEnv({ [FULL_URL_HOSTS_ENV]: "*.arxiv.org" }),
      (err: unknown) => err instanceof HostAllowlistError && err.message.startsWith(`${FULL_URL_HOSTS_ENV}: invalid entry at position 1`),
    );
  });
});

describe("ProviderRegistry", () => {
  it("blocks record identifiers but not research about record systems (RB-19)", async () => {
    const reg = new ProviderRegistry([{ id: "fake", version: "1", search: async () => [] }]);
    for (const q of ["medical record number standards HL7", "patient id matching algorithms", "MRN reconciliation"]) {
      assert.equal((await reg.search(q, 3, undefined)).status, "success", q);
    }
    for (const q of ["patient MRN: 12345 outcomes", "Medical Record #: 0012345", "medical record no. 55512", "patient id 4471203", "api_key=sk-abc", "ssn 123-45-6789"]) {
      assert.equal((await reg.search(q, 3, undefined)).status, "policy_denied", q);
    }
  });

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
