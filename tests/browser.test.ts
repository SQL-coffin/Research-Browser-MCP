import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, afterEach, before, describe, it } from "node:test";
import { chromium } from "playwright-core";
import { BrowserAgent, type BrowserResult } from "../src/browser/actions.js";
import { DEFAULT_BROWSER_CONFIG, type BrowserConfig, type BrowserDeps } from "../src/browser/session.js";
import { DEFAULT_EGRESS_POLICY } from "../src/egress-proxy.js";
import { FileEvidenceStore, NO_EVIDENCE } from "../src/evidence.js";
import type { ResolvedAddress } from "../src/fetcher.js";
import { HandoffStore, type HostEventVerifier, type TrustedHumanEvent } from "../src/handoff.js";
import { TOOL_VERSION } from "../src/result.js";
import { classifyAddress, parseHostAllowlist } from "../src/security.js";

// Real Chromium against local fixtures. 127.0.0.1 is the only "public" address
// here, as in the fetcher tests. Local runs without a Chromium build may skip;
// under CI the suite must run.
function hasChromium(): boolean {
  try {
    return existsSync(chromium.executablePath());
  } catch {
    return false;
  }
}
const SKIP = !process.env.CI && !hasChromium() && "Chromium not installed for playwright-core";

const fixtureOnly = (ip: string) => (ip === "127.0.0.1" ? ({ allowed: true } as const) : classifyAddress(ip));

type Handler = (req: http.IncomingMessage, res: http.ServerResponse) => void;
const routes = new Map<string, Handler>();
let hits: { method: string; path: string; cookie: string | undefined }[] = [];
let server: http.Server;
let port: number;

const page = (body: string, status = 200, headers: http.OutgoingHttpHeaders = {}): Handler => (_req, res) => {
  res.writeHead(status, { "content-type": "text/html; charset=utf-8", ...headers });
  res.end(body);
};

const dns: Record<string, ResolvedAddress[]> = {
  "fixture.test": [{ address: "127.0.0.1", family: 4 }],
  "private.test": [{ address: "10.0.0.7", family: 4 }],
  "other.test": [{ address: "127.0.0.1", family: 4 }],
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
        allowedPorts: new Set([port]),
        allowedHosts: parseHostAllowlist("fixture.test private.test"),
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
      ...deps,
    },
  );
  agents.push(agent);
  return agent;
}

const url = (path: string, host = "fixture.test") => `http://${host}:${port}${path}`;

async function open(agent: BrowserAgent): Promise<string> {
  const r = await agent.openSession();
  assert.equal(r.status, "success", JSON.stringify(r));
  return r.session_id!;
}

function expect(r: BrowserResult, status: string, code?: string) {
  assert.equal(r.status, status, JSON.stringify(r, null, 1));
  if (code) assert.equal(r.error?.code, code, JSON.stringify(r.error));
}

const CAPTCHA_PAGE = `<html><head><title>Just a moment</title></head><body><div class="g-recaptcha" data-sitekey="x"></div><p>Verify you are human</p></body></html>`;

before(async () => {
  server = http.createServer((req, res) => {
    const path = (req.url ?? "").split("?")[0]!;
    hits.push({ method: req.method ?? "", path, cookie: req.headers.cookie });
    const handler = routes.get(path);
    if (handler) handler(req, res);
    else page("<title>404</title>not found", 404)(req, res);
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as AddressInfo).port;

  routes.set("/", page(`<html><head><title>Home</title></head><body><h1>Welcome</h1><p>Plain public page.</p><a href="/next?token=abc">Next page</a></body></html>`));
  routes.set("/next", page(`<title>Next</title><p>Second page</p>`));
  routes.set("/form", page(`<title>Form</title>
    <form method="post" action="/submit"><label for="q">Query</label><input id="q" name="q" value="prefilled-secret-value">
    <input type="password" id="pw" aria-label="Password"><input id="otp" autocomplete="one-time-code" aria-label="Code">
    <button type="submit">Send</button></form>
    <button id="js" onclick="fetch('/beacon', {method: 'POST', body: 'x'})">Ping</button>
    <input id="mirror" aria-label="Mirror" oninput="document.title = 'typed:' + this.value.length">
    <a href="#" onclick="window.open('/next'); return false;">Popup</a>`));
  routes.set("/submit", page("<title>Submitted</title>"));
  routes.set("/beacon", page("ok"));
  routes.set("/set-state", page(`<title>Set</title><script>localStorage.setItem("k", "v"); document.cookie = "js=1; path=/";</script>`, 200, { "set-cookie": "sid=abc; Path=/; HttpOnly" }));
  routes.set("/read-state", page(`<title>Read</title><script>document.title = "ls:" + (localStorage.getItem("k") || "none");</script>`));
  routes.set("/redirect-out", (_req, res) => {
    res.writeHead(302, { location: url("/", "other.test") });
    res.end();
  });
  routes.set("/redirect-private", (_req, res) => {
    res.writeHead(302, { location: url("/", "private.test") });
    res.end();
  });
  routes.set("/captcha", page(CAPTCHA_PAGE, 403));
  routes.set("/captcha-then-clear", page(`<title>Just a moment</title><body><div class="g-recaptcha"></div><script>setTimeout(() => { document.title = "Article"; document.body.innerHTML = "<p>The article</p>"; }, 1500);</script></body>`));
  routes.set("/rate", page("<title>Slow down</title>too many", 429, { "retry-after": "120" }));
  routes.set("/denied", page("<title>Forbidden</title>Access denied", 403));
  routes.set("/long", page(`<title>Long</title><div style="height:5000px">${"word ".repeat(5000)}</div>`));
  routes.set("/hang", () => {
    /* never responds */
  });
  routes.set("/spin", page(`<title>Spin</title><p>spin</p><button onclick="while (true) {}">Spin</button>`));
  routes.set("/many", page(`<title>Many</title>${Array.from({ length: 50 }, (_, i) => `<a href="/n${i}">link ${i}</a>`).join("")}`));
});

after(async () => {
  for (const a of agents) await a.closeAll();
  server.closeAllConnections();
  server.close();
});

afterEach(() => {
  hits = [];
});

describe("browser sessions", { skip: SKIP }, () => {
  it("opens an isolated session and closes it, stopping the browser and its proxy", async () => {
    const agent = makeAgent();
    const r = await agent.openSession();
    expect(r, "success");
    assert.equal(r.session_state, "ACTIVE");
    assert.equal(agent.sessionCount, 1);
    const closed = await agent.closeSession(r.session_id!);
    expect(closed, "success");
    assert.equal(closed.session_state, "CLOSED");
    assert.equal(agent.sessionCount, 0);
    const again = await agent.navigate(r.session_id!, url("/"));
    expect(again, "invalid_input", "unknown_session");
  });

  it("does not share cookies or storage between sessions", async () => {
    const agent = makeAgent();
    const a = await open(agent);
    const b = await open(agent);
    expect(await agent.navigate(a, url("/set-state")), "success");
    hits = [];
    const read = await agent.navigate(b, url("/read-state"));
    expect(read, "success");
    assert.equal(read.title, "ls:none");
    assert.equal(hits.find((h) => h.path === "/read-state")?.cookie, undefined, "session B sent no cookie from session A");
    const readA = await agent.navigate(a, url("/read-state"));
    assert.equal(readA.title, "ls:v", "session A keeps its own storage");
  });

  it("enforces the session limit", async () => {
    const agent = makeAgent({ maxSessions: 1 });
    await open(agent);
    expect(await agent.openSession(), "policy_denied", "session_limit_reached");
  });

  it("closes idle sessions", async () => {
    const agent = makeAgent({ idleTimeoutMs: 50 });
    await open(agent);
    await new Promise((r) => setTimeout(r, 120));
    await agent.reapExpired();
    assert.equal(agent.sessionCount, 0);
  });

  it("closes everything on shutdown", async () => {
    const agent = makeAgent();
    await open(agent);
    await open(agent);
    await agent.closeAll();
    assert.equal(agent.sessionCount, 0);
  });
});

describe("browser navigation and network policy", { skip: SKIP }, () => {
  it("navigates an allowlisted page and reports origin-only URLs and the body hash", async () => {
    const agent = makeAgent();
    const id = await open(agent);
    const r = await agent.navigate(id, url("/?token=abc"));
    expect(r, "success");
    assert.equal(r.http_status, 200);
    assert.equal(r.title, "Home");
    assert.equal(r.url, `http://fixture.test:${port}`);
    assert.equal(r.challenge?.challenge_type, "none");
    const hash = r.content_hash as { basis: string; value: string };
    assert.equal(hash.basis, "decoded_body_bytes");
    assert.equal(hash.value, createHash("sha256").update(`<html><head><title>Home</title></head><body><h1>Welcome</h1><p>Plain public page.</p><a href="/next?token=abc">Next page</a></body></html>`).digest("hex"));
    assert.doesNotMatch(JSON.stringify(logs), /token=abc/);
  });

  it("refuses a host that is not allowlisted before the browser is involved", async () => {
    const agent = makeAgent();
    const id = await open(agent);
    const r = await agent.navigate(id, url("/", "other.test"));
    expect(r, "policy_denied", "host_not_allowlisted");
    assert.deepEqual(hits, []);
  });

  it("refuses non-http(s) schemes and embedded credentials", async () => {
    const agent = makeAgent();
    const id = await open(agent);
    for (const target of ["file:///etc/passwd", "javascript:alert(1)", "data:text/html,hi", "chrome://settings"]) {
      expect(await agent.navigate(id, target), "policy_denied", "scheme_not_allowed");
    }
    expect(await agent.navigate(id, `http://u:p@fixture.test:${port}/`), "policy_denied", "url_credentials");
  });

  it("refuses a redirect to a host that is not allowlisted", async () => {
    const agent = makeAgent();
    const id = await open(agent);
    const r = await agent.navigate(id, url("/redirect-out"));
    expect(r, "policy_denied", "host_not_allowlisted");
    assert.deepEqual(
      hits.map((h) => h.path),
      ["/redirect-out"],
    );
  });

  it("refuses a redirect to a host that resolves to a private address", async () => {
    const agent = makeAgent();
    const id = await open(agent);
    const r = await agent.navigate(id, url("/redirect-private"));
    expect(r, "policy_denied", "address_private");
  });

  it("refuses an allowlisted name that resolves to a private address", async () => {
    const agent = makeAgent();
    const id = await open(agent);
    expect(await agent.navigate(id, url("/", "private.test")), "policy_denied", "address_private");
  });

  it("blocks subresources to loopback literals and other hosts, and reports them", async () => {
    routes.set("/subresources", page(`<title>Sub</title><img src="http://127.0.0.1:${port}/direct.png"><img src="${url("/x.png", "other.test")}"><script>fetch("http://localhost:${port}/direct2").catch(() => {});</script><p>sub</p>`));
    const agent = makeAgent();
    const id = await open(agent);
    const r = await agent.navigate(id, url("/subresources"));
    expect(r, "success");
    await new Promise((res) => setTimeout(res, 300));
    assert.deepEqual(
      hits.map((h) => h.path),
      ["/subresources"],
      "no request other than the page itself reached the server",
    );
  });

  it("reports a navigation timeout and keeps the session usable", async () => {
    const agent = makeAgent({ navigationTimeoutMs: 1_000 });
    const id = await open(agent);
    expect(await agent.navigate(id, url("/hang")), "timeout", "navigation_timeout");
    expect(await agent.navigate(id, url("/")), "success");
  });

  it("closes a session whose page hangs past the hard deadline", async () => {
    const agent = makeAgent({ actionTimeoutMs: 500, navigationTimeoutMs: 1_000 });
    const id = await open(agent);
    expect(await agent.navigate(id, url("/spin")), "success");
    const snap = await agent.snapshot(id);
    const spin = (snap.elements as { index: number; name: string }[]).find((e) => e.name === "Spin")!;
    // The click itself returns (the handler runs after it), but the page's
    // renderer is now stuck, so the next action cannot finish.
    await agent.click(id, spin.index);
    const r = await agent.snapshot(id);
    assert.ok(r.status === "timeout", JSON.stringify(r));
    assert.equal(r.session_state, "CLOSED");
    assert.equal(agent.sessionCount, 0);
  });
});

describe("page state and actions", { skip: SKIP }, () => {
  it("indexes interactive elements without exposing field values, and marks content untrusted", async () => {
    const agent = makeAgent();
    const id = await open(agent);
    await agent.navigate(id, url("/form"));
    const r = await agent.snapshot(id);
    expect(r, "success");
    assert.equal(r.untrusted_content, true);
    assert.match(String(r.content_notice), /untrusted/i);
    const els = r.elements as { index: number; tag: string; type: string | null; name: string; submits_form: boolean }[];
    assert.deepEqual(
      els.map((e) => e.index),
      els.map((_, i) => i + 1),
    );
    assert.ok(els.find((e) => e.name === "Query" && e.type === "text"));
    assert.ok(els.find((e) => e.name === "Send" && e.submits_form));
    assert.doesNotMatch(JSON.stringify(r), /prefilled-secret-value/);
    assert.equal((r.content_hash as { basis: string }).basis, "rendered_dom_utf8");
  });

  it("discloses link targets as origins only", async () => {
    const agent = makeAgent();
    const id = await open(agent);
    await agent.navigate(id, url("/"));
    const r = await agent.snapshot(id);
    const link = (r.elements as { name: string; href: string | null }[]).find((e) => e.name === "Next page");
    assert.equal(link?.href, `http://fixture.test:${port}`);
    assert.doesNotMatch(JSON.stringify(r), /token=abc/);
  });

  it("bounds text and element counts", async () => {
    const agent = makeAgent({ maxTextChars: 100, maxElements: 10 });
    const id = await open(agent);
    await agent.navigate(id, url("/long"));
    const long = await agent.snapshot(id);
    assert.equal(long.text_truncated, true);
    assert.ok(String(long.text).length <= 100);
    await agent.navigate(id, url("/many"));
    const many = await agent.snapshot(id);
    assert.equal((many.elements as unknown[]).length, 10);
    assert.equal(many.elements_truncated, true);
  });

  it("clicks a link by index and follows it", async () => {
    const agent = makeAgent();
    const id = await open(agent);
    await agent.navigate(id, url("/"));
    const snap = await agent.snapshot(id);
    const link = (snap.elements as { index: number; name: string }[]).find((e) => e.name === "Next page")!;
    const r = await agent.click(id, link.index);
    expect(r, "success");
    assert.equal(r.navigated, true);
    assert.equal(r.title, "Next");
    expect(await agent.click(id, link.index), "invalid_input", "unknown_element");
  });

  it("rejects an index that is not in the latest snapshot", async () => {
    const agent = makeAgent();
    const id = await open(agent);
    await agent.navigate(id, url("/"));
    expect(await agent.click(id, 1), "invalid_input", "unknown_element");
  });

  it("does not submit forms by default", async () => {
    const agent = makeAgent();
    const id = await open(agent);
    await agent.navigate(id, url("/form"));
    const snap = await agent.snapshot(id);
    const send = (snap.elements as { index: number; name: string }[]).find((e) => e.name === "Send")!;
    expect(await agent.click(id, send.index), "policy_denied", "form_submission_disabled");
    assert.ok(!hits.some((h) => h.path === "/submit"));
  });

  it("blocks non-GET requests a page makes on its own", async () => {
    const agent = makeAgent();
    const id = await open(agent);
    await agent.navigate(id, url("/form"));
    const snap = await agent.snapshot(id);
    const ping = (snap.elements as { index: number; name: string }[]).find((e) => e.name === "Ping")!;
    const r = await agent.click(id, ping.index);
    expect(r, "success");
    await new Promise((res) => setTimeout(res, 200));
    assert.ok(!hits.some((h) => h.method === "POST"), JSON.stringify(hits));
  });

  it("allows form submission only on hosts opted in by the operator", async () => {
    const agent = makeAgent({}, {}, { formSubmitHosts: parseHostAllowlist("fixture.test") });
    const id = await open(agent);
    await agent.navigate(id, url("/form"));
    const snap = await agent.snapshot(id);
    const send = (snap.elements as { index: number; name: string }[]).find((e) => e.name === "Send")!;
    const r = await agent.click(id, send.index);
    expect(r, "success");
    assert.ok(hits.some((h) => h.method === "POST" && h.path === "/submit"));
  });

  it("types into text fields but never into password, one-time-code or non-text fields, and never echoes the text", async () => {
    const agent = makeAgent();
    const id = await open(agent);
    await agent.navigate(id, url("/form"));
    const snap = await agent.snapshot(id);
    const els = snap.elements as { index: number; name: string }[];
    const by = (n: string) => els.find((e) => e.name === n)!.index;
    const typed = await agent.type(id, by("Mirror"), "hello world");
    expect(typed, "success");
    assert.equal(typed.characters, 11);
    assert.equal(typed.title, "typed:11");
    expect(await agent.type(id, by("Password"), "hunter2"), "policy_denied", "password_field_not_allowed");
    expect(await agent.type(id, by("Code"), "123456"), "policy_denied", "sensitive_field_not_allowed");
    expect(await agent.type(id, by("Ping"), "x"), "invalid_input", "not_editable");
    expect(await agent.type(id, by("Mirror"), "x".repeat(5_000)), "invalid_input", "text_too_long");
    assert.doesNotMatch(JSON.stringify(logs), /hello world|hunter2|123456/);
    assert.ok(!hits.some((h) => h.path === "/submit"), "typing never submits");
  });

  it("closes popups", async () => {
    const agent = makeAgent();
    const id = await open(agent);
    await agent.navigate(id, url("/form"));
    const snap = await agent.snapshot(id);
    const popup = (snap.elements as { index: number; name: string }[]).find((e) => e.name === "Popup")!;
    const r = await agent.click(id, popup.index);
    expect(r, "success");
    assert.ok(r.warnings.includes("popup_closed"), JSON.stringify(r.warnings));
  });

  it("scrolls the page", async () => {
    const agent = makeAgent();
    const id = await open(agent);
    await agent.navigate(id, url("/long"));
    const r = await agent.scroll(id, { direction: "down", pixels: 600 });
    expect(r, "success");
    assert.equal((r.position as { scroll_y: number }).scroll_y, 600);
    const up = await agent.scroll(id, { direction: "up", pixels: 200 });
    assert.equal((up.position as { scroll_y: number }).scroll_y, 400);
  });

  it("takes a PNG screenshot whose hash covers the returned bytes", async () => {
    const agent = makeAgent();
    const id = await open(agent);
    await agent.navigate(id, url("/"));
    const { result, png } = await agent.screenshot(id);
    expect(result, "success");
    assert.ok(png);
    assert.deepEqual([...png.subarray(0, 4)], [0x89, 0x50, 0x4e, 0x47]);
    assert.equal((result.content_hash as { value: string }).value, createHash("sha256").update(png).digest("hex"));
  });
});

describe("challenges: detect, record, pause; never bypass", { skip: SKIP }, () => {
  class Host implements HostEventVerifier {
    readonly events = new Map<string, TrustedHumanEvent>();
    async verify(ref: string) {
      return this.events.get(ref) ?? null;
    }
  }
  const event = (sessionId: string, pauseId: string, sourceUrl: string, decision: TrustedHumanEvent["decision"] = "verified_and_continue"): TrustedHumanEvent => ({
    event_id: `ev-${Math.random()}`,
    task_id: sessionId,
    pause_id: pauseId,
    source_url: sourceUrl,
    decision,
    issued_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 60_000).toISOString(),
    policy_version: "0.1.0",
    tool_version: TOOL_VERSION,
  });

  it("pauses on a CAPTCHA page and refuses every action until resumed", async () => {
    const agent = makeAgent();
    const id = await open(agent);
    const r = await agent.navigate(id, url("/captcha"));
    expect(r, "human_verification_required", "paused_captcha");
    assert.equal(r.session_state, "BLOCKED");
    assert.equal(r.challenge?.challenge_type, "captcha");
    assert.ok(r.handoff?.pause_id);
    assert.equal(r.handoff?.task_id, id);
    assert.equal(r.handoff?.source_url, `http://fixture.test:${port}`);
    assert.doesNotMatch(JSON.stringify(r), /resume_handle/, "the resume handle stays on the server");
    expect(await agent.snapshot(id), "human_verification_required", "session_paused");
    const shot = await agent.screenshot(id);
    expect(shot.result, "human_verification_required", "session_paused");
    assert.equal(shot.png, null, "a challenge page is never returned as an image");
    expect(await agent.navigate(id, url("/")), "human_verification_required", "session_paused");
  });

  it("without a trusted host verifier, resume is deferred and the session stays paused", async () => {
    const agent = makeAgent();
    const id = await open(agent);
    await agent.navigate(id, url("/captcha"));
    const r = await agent.resume(id, "model-says-solved");
    expect(r, "human_verification_required", "host_verification_required");
    assert.equal(r.session_state, "BLOCKED");
    expect(await agent.snapshot(id), "human_verification_required", "session_paused");
  });

  it("rejects a host event for a different pause and stays paused", async () => {
    const host = new Host();
    const agent = makeAgent({}, { handoff: new HandoffStore({ verifier: host }) });
    const id = await open(agent);
    await agent.navigate(id, url("/captcha"));
    host.events.set("ref", event(id, "some-other-pause", url("/captcha")));
    const r = await agent.resume(id, "ref");
    expect(r, "policy_denied", "event_task_mismatch");
    assert.equal(r.session_state, "BLOCKED");
  });

  it("resumes on an accepted host event once the page no longer shows a challenge", async () => {
    const host = new Host();
    const agent = makeAgent({}, { handoff: new HandoffStore({ verifier: host }) });
    const id = await open(agent);
    const blocked = await agent.navigate(id, url("/captcha-then-clear"));
    expect(blocked, "human_verification_required");
    // The page clears itself after 1.5 s, standing in for a person in the window.
    await new Promise((res) => setTimeout(res, 2_000));
    host.events.set("ref", event(id, blocked.handoff!.pause_id, url("/captcha-then-clear")));
    const r = await agent.resume(id, "ref");
    expect(r, "success");
    assert.equal(r.session_state, "ACTIVE");
    assert.equal(r.next_state, "READY_TO_RESUME");
    const snap = await agent.snapshot(id);
    expect(snap, "success");
    assert.match(String(snap.text), /The article/);
  });

  it("pauses again if the challenge is still there after an accepted event", async () => {
    const host = new Host();
    const agent = makeAgent({}, { handoff: new HandoffStore({ verifier: host }) });
    const id = await open(agent);
    const blocked = await agent.navigate(id, url("/captcha"));
    host.events.set("ref", event(id, blocked.handoff!.pause_id, url("/captcha")));
    const r = await agent.resume(id, "ref");
    expect(r, "human_verification_required", "paused_captcha");
    assert.equal(r.session_state, "BLOCKED");
    assert.notEqual(r.handoff?.pause_id, blocked.handoff?.pause_id);
  });

  it("closes the session when the person cancels", async () => {
    const host = new Host();
    const agent = makeAgent({}, { handoff: new HandoffStore({ verifier: host }) });
    const id = await open(agent);
    const blocked = await agent.navigate(id, url("/captcha"));
    host.events.set("ref", event(id, blocked.handoff!.pause_id, url("/captcha"), "cancel"));
    const r = await agent.resume(id, "ref");
    assert.equal(r.session_state, "CLOSED");
    assert.equal(agent.sessionCount, 0);
  });

  it("treats a rate limit and an access block as pauses too", async () => {
    const agent = makeAgent();
    const a = await open(agent);
    const rate = await agent.navigate(a, url("/rate"));
    expect(rate, "rate_limited", "paused_rate_limited");
    assert.equal(rate.challenge?.retry_after_seconds, 120);
    assert.equal(rate.session_state, "BLOCKED");
    const b = await open(agent);
    const denied = await agent.navigate(b, url("/denied"));
    expect(denied, "blocked", "paused_robots_or_policy_block");
    assert.equal(denied.session_state, "BLOCKED");
  });

  it("lets the agent ask for a person explicitly", async () => {
    const agent = makeAgent();
    const id = await open(agent);
    await agent.navigate(id, url("/"));
    const r = await agent.pauseForHuman(id);
    expect(r, "human_verification_required", "paused_unknown");
    assert.equal(r.session_state, "BLOCKED");
    assert.ok(r.handoff);
  });

  it("logs the pause by origin and challenge type only", async () => {
    const agent = makeAgent();
    const id = await open(agent);
    logs.length = 0;
    await agent.navigate(id, url("/captcha?session=zzz"));
    const entry = logs.find((l) => l.event === "browser_blocked");
    assert.equal(entry?.origin, `http://fixture.test:${port}`);
    assert.doesNotMatch(JSON.stringify(logs), /session=zzz/);
  });
});

describe("browser evidence", { skip: SKIP }, () => {
  let root: string;
  before(() => {
    root = mkdtempSync(join(tmpdir(), "rbmcp-browser-evidence-"));
  });
  after(() => rmSync(root, { recursive: true, force: true }));

  it("persists the response body, DOM and screenshot; each object hashes to its declared value", async () => {
    const agent = makeAgent({}, { evidence: new FileEvidenceStore(join(root, "a")) });
    const id = await open(agent);
    const nav = await agent.navigate(id, url("/"));
    const snap = await agent.snapshot(id);
    const { result: shot } = await agent.screenshot(id);
    for (const [r, basis] of [
      [nav, "decoded_body_bytes"],
      [snap, "rendered_dom_utf8"],
      [shot, "screenshot_png_bytes"],
    ] as const) {
      const ev = r.evidence?.[0];
      assert.equal(ev?.evidence_status, "persisted", JSON.stringify(r.evidence));
      assert.equal(ev?.evidence_persisted, true);
      assert.equal(ev?.content_hash.basis, basis);
      const bytes = readFileSync(join(root, "a", "objects", "sha256", ev!.content_hash.value));
      assert.equal(createHash("sha256").update(bytes).digest("hex"), ev!.content_hash.value);
      const record = JSON.parse(readFileSync(join(root, "a", "records", `${ev!.evidence_id}.json`), "utf8"));
      assert.equal(record.session_id, id);
      assert.equal(record.source_origin, `http://fixture.test:${port}`);
    }
  });

  it("records the challenge page for the person without returning it", async () => {
    const agent = makeAgent({}, { evidence: new FileEvidenceStore(join(root, "b")) });
    const id = await open(agent);
    const r = await agent.navigate(id, url("/captcha"));
    expect(r, "human_verification_required");
    const kinds = (r.evidence ?? []).map((e) => e.kind);
    assert.ok(kinds.includes("browser_screenshot") && kinds.includes("browser_dom"), JSON.stringify(kinds));
    assert.ok((r.evidence ?? []).every((e) => e.evidence_persisted));
  });

  it("reports evidence as disabled when no store is configured", async () => {
    const agent = makeAgent();
    const id = await open(agent);
    const r = await agent.navigate(id, url("/"));
    assert.equal(r.evidence?.[0]?.evidence_status, "disabled");
    assert.equal(r.evidence?.[0]?.evidence_persisted, false);
  });
});

describe("browser over HTTPS (CONNECT tunnel)", { skip: SKIP || (!process.env.CI && !hasOpenssl() && "openssl not available") }, () => {
  let dir: string;
  let tlsServer: https.Server;
  let tlsPort: number;
  let spki: string;
  const tlsHits: string[] = [];

  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "rb-browser-tls-"));
    execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=fixture.test", "-addext", "subjectAltName=DNS:fixture.test", "-keyout", join(dir, "key.pem"), "-out", join(dir, "cert.pem")], { stdio: "ignore" });
    const cert = readFileSync(join(dir, "cert.pem"));
    spki = createHash("sha256")
      .update(new X509Certificate(cert).publicKey.export({ type: "spki", format: "der" }))
      .digest("base64");
    tlsServer = https.createServer({ key: readFileSync(join(dir, "key.pem")), cert }, (req, res) => {
      tlsHits.push(`${req.method} ${req.url}`);
      res.writeHead(200, { "content-type": "text/html" });
      res.end(req.url === "/post" ? `<title>Post</title><script>fetch("/beacon", { method: "POST", body: "x" }).catch(() => {});</script>` : "<title>Secure</title><p>over tls</p>");
    });
    await new Promise<void>((r) => tlsServer.listen(0, "127.0.0.1", r));
    tlsPort = (tlsServer.address() as AddressInfo).port;
  });
  after(() => {
    tlsServer.closeAllConnections();
    tlsServer.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it("loads an allowlisted HTTPS page through the tunnel", async () => {
    const agent = makeAgent({}, { testTrustedSpki: [spki] }, { allowedPorts: new Set([port, tlsPort]) });
    const id = await open(agent);
    const r = await agent.navigate(id, `https://fixture.test:${tlsPort}/`);
    expect(r, "success");
    assert.equal(r.title, "Secure");
  });

  it("blocks a POST inside the tunnel, where only the browser can see the method", async () => {
    const agent = makeAgent({}, { testTrustedSpki: [spki] }, { allowedPorts: new Set([port, tlsPort]) });
    const id = await open(agent);
    expect(await agent.navigate(id, `https://fixture.test:${tlsPort}/post`), "success");
    await new Promise((res) => setTimeout(res, 300));
    assert.ok(tlsHits.includes("GET /post"));
    assert.ok(!tlsHits.some((h) => h.startsWith("POST")), JSON.stringify(tlsHits));
  });

  it("fails closed on an untrusted certificate", async () => {
    const agent = makeAgent({}, {}, { allowedPorts: new Set([port, tlsPort]) });
    const id = await open(agent);
    const r = await agent.navigate(id, `https://fixture.test:${tlsPort}/`);
    expect(r, "policy_denied", "tls_verification_failed");
  });

  it("refuses a tunnel to a private address", async () => {
    const agent = makeAgent({}, { testTrustedSpki: [spki] }, { allowedPorts: new Set([port, tlsPort]) });
    const id = await open(agent);
    const r = await agent.navigate(id, `https://private.test:${tlsPort}/`);
    expect(r, "policy_denied", "address_private");
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
