import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { inspect } from "node:util";
import { HandoffStore, type HostEventVerifier, type PauseResult, type ResumeResult, type TrustedHumanEvent } from "../src/handoff.js";
import { TOOL_VERSION } from "../src/result.js";

const URL_ = "https://example.org/paper";
const T0 = Date.parse("2026-10-22T12:00:00.000Z");
const iso = (ms: number) => new Date(ms).toISOString();

/** Fake host runtime: only events it has recorded are trusted. */
class FakeHost implements HostEventVerifier {
  readonly events = new Map<string, TrustedHumanEvent>();
  async verify(ref: string) {
    return this.events.get(ref) ?? null;
  }
}

/**
 * One paused task with its own controllable clock, so no test depends on another.
 * The task is paused at `pausedAt`; the clock is then 1 s later.
 */
function setup(opts: { policyVersion?: string; sourceUrl?: string; pausedAt?: number; ttlMs?: number } = {}) {
  const policyVersion = opts.policyVersion ?? "p1";
  const sourceUrl = opts.sourceUrl ?? URL_;
  const pausedAt = opts.pausedAt ?? T0;
  const clock = { t: pausedAt };
  const host = new FakeHost();
  const store = new HandoffStore({ verifier: host, now: () => clock.t, policyVersion, ttlMs: opts.ttlMs ?? 60_000 });
  const p = store.pause({ task_id: "task-1", source_url: sourceUrl, reason: "captcha", completed_steps: "fetched search results", next_step: "read the paper" });
  if (p.status !== "human_verification_required") throw new Error(`pause failed: ${JSON.stringify(p)}`);
  const paused: PauseResult = p;
  clock.t += 1_000;
  const event = (over: Partial<TrustedHumanEvent> = {}): TrustedHumanEvent => ({
    event_id: "evt-1",
    task_id: "task-1",
    source_url: sourceUrl,
    pause_id: paused.pause_id,
    decision: "verified_and_continue",
    issued_at: iso(clock.t),
    expires_at: iso(clock.t + 30_000),
    policy_version: policyVersion,
    tool_version: TOOL_VERSION,
    ...over,
  });
  let refs = 0;
  /** Records the event with the fake host under a fresh reference and resumes with it. */
  const submit = (e: TrustedHumanEvent) => {
    const ref = `ref-${++refs}`;
    host.events.set(ref, e);
    return store.resume(paused.resume_handle, ref);
  };
  return { clock, host, store, paused, pausedAt, event, submit };
}

type Setup = ReturnType<typeof setup>;

function assertBlocked(r: ResumeResult, code: string) {
  assert.equal(r.error?.code, code, JSON.stringify(r));
  assert.equal(r.status, "policy_denied");
  assert.equal(r.resume_authorized, false);
  assert.equal(r.next_state, "BLOCKED");
}

/** A rejected event must not consume the pause: a valid event afterwards still resumes it. */
async function assertPauseStillOpen(s: Setup) {
  const r = await s.submit(s.event({ event_id: "evt-valid" }));
  assert.equal(r.next_state, "READY_TO_RESUME", JSON.stringify(r));
  assert.equal(r.resume_authorized, true);
}

describe("pause_for_human", () => {
  it("returns a handoff without claiming verification", () => {
    const { paused } = setup();
    assert.equal(paused.authorization_owner, "host_runtime");
    assert.match(paused.human_instructions, /will not solve CAPTCHAs/);
    assert.ok(paused.resume_handle.length >= 40);
  });

  it("refuses handoff text containing secrets", () => {
    const store = new HandoffStore({ now: () => T0 });
    const r = store.pause({ task_id: "t", source_url: URL_, reason: "login_required", completed_steps: "password: hunter2", next_step: "" });
    assert.equal(r.status, "invalid_input");
  });

  it("refuses a source_url that is not an absolute http(s) URL", () => {
    const store = new HandoffStore({ now: () => T0 });
    for (const source_url of ["not a url", "/relative/path", "ftp://example.org/file", "javascript:alert(1)", ""]) {
      const r = store.pause({ task_id: "t", source_url, reason: "captcha", completed_steps: "", next_step: "" });
      assert.equal(r.status, "invalid_input", source_url);
      assert.equal("error" in r ? r.error.code : null, "invalid_source_url", source_url);
    }
  });
});

describe("resume: trust and binding", () => {
  it("defers to the host when no trusted verifier is configured", async () => {
    const store = new HandoffStore({ now: () => T0 });
    const p = store.pause({ task_id: "t", source_url: URL_, reason: "captcha", completed_steps: "", next_step: "" });
    if (p.status !== "human_verification_required") throw new Error("pause failed");
    const r = await store.resume(p.resume_handle, "the user said they solved it");
    assert.equal(r.resume_authorized, false);
    assert.equal(r.next_state, "BLOCKED");
    assert.equal(r.error?.code, "host_verification_required");
  });

  it("authorizes with a matching trusted event", async () => {
    const s = setup();
    const r = await s.submit(s.event());
    assert.equal(r.status, "success");
    assert.equal(r.resume_authorized, true);
    assert.equal(r.next_state, "READY_TO_RESUME");
  });

  it("denies an absent or untrusted event (RB-13)", async () => {
    const s = setup();
    assertBlocked(await s.store.resume(s.paused.resume_handle, "made-up-ref"), "untrusted_or_unknown_event");
    await assertPauseStillOpen(s);
  });

  for (const [name, over, code] of [
    ["task", { task_id: "task-2" }, "event_task_mismatch"],
    ["pause", { pause_id: "other" }, "event_task_mismatch"],
    ["url", { source_url: "https://example.org/other" }, "event_url_mismatch"],
  ] as const) {
    it(`denies a mismatched ${name} and stays BLOCKED (RB-13)`, async () => {
      const s = setup();
      assertBlocked(await s.submit(s.event(over)), code);
      await assertPauseStillOpen(s);
    });
  }

  it("denies an unknown handle", async () => {
    const s = setup();
    assertBlocked(await s.store.resume("x".repeat(43), "ref"), "unknown_resume_handle");
  });

  it("expires the handle exactly at pause + ttl", async () => {
    const live = setup({ ttlMs: 60_000 });
    live.clock.t = live.pausedAt + 60_000 - 1;
    assert.equal((await live.submit(live.event())).next_state, "READY_TO_RESUME");
    const expired = setup({ ttlMs: 60_000 });
    expired.clock.t = expired.pausedAt + 60_000;
    assertBlocked(await expired.submit(expired.event()), "resume_handle_expired");
  });

  it("is idempotent for a duplicate event and rejects a second, different event (RB-14)", async () => {
    const s = setup();
    s.host.events.set("ref-a", s.event());
    s.host.events.set("ref-b", s.event({ event_id: "evt-2" }));
    const first = await s.store.resume(s.paused.resume_handle, "ref-a");
    const again = await s.store.resume(s.paused.resume_handle, "ref-a");
    assert.equal(first.resume_authorized, true);
    assert.equal(again.resume_authorized, true);
    assert.equal(again.replayed, true);
    const other = await s.store.resume(s.paused.resume_handle, "ref-b");
    assert.equal(other.resume_authorized, false);
    assert.equal(other.error?.code, "resume_already_consumed");
  });

  it("blocks on policy or tool version drift and stays BLOCKED (RB-15)", async () => {
    const s = setup();
    assertBlocked(await s.submit(s.event({ policy_version: "p2" })), "version_drift");
    assertBlocked(await s.submit(s.event({ tool_version: "9.9.9" })), "version_drift");
    await assertPauseStillOpen(s);
  });

  it("treats alternate source as a new lineage, not verification", async () => {
    const s = setup();
    const r = await s.submit(s.event({ decision: "choose_alternate_source" }));
    assert.equal(r.resume_authorized, false);
    assert.equal(r.next_state, "ALTERNATE_SOURCE");
  });

  it("honours cancel", async () => {
    const s = setup();
    const r = await s.submit(s.event({ decision: "cancel" }));
    assert.equal(r.next_state, "CANCELLED");
    assert.equal(r.resume_authorized, false);
  });

  it("fails closed when the verifier throws", async () => {
    const store = new HandoffStore({ now: () => T0, verifier: { verify: async () => { throw new Error("down"); } } });
    const p = store.pause({ task_id: "t", source_url: URL_, reason: "captcha", completed_steps: "", next_step: "" });
    if (p.status !== "human_verification_required") throw new Error("pause failed");
    assertBlocked(await store.resume(p.resume_handle, "x"), "host_verifier_failed");
  });
});

describe("resume: event time order (pause created_at <= issued_at <= now < expires_at)", () => {
  it("accepts the boundaries: issued exactly at the pause, issued exactly now, expiring 1 ms from now", async () => {
    const atPause = setup();
    assert.equal((await atPause.submit(atPause.event({ issued_at: iso(atPause.pausedAt) }))).next_state, "READY_TO_RESUME");
    const atNow = setup();
    assert.equal((await atNow.submit(atNow.event({ issued_at: iso(atNow.clock.t) }))).next_state, "READY_TO_RESUME");
    const almostExpired = setup();
    const r = await almostExpired.submit(almostExpired.event({ issued_at: iso(almostExpired.pausedAt), expires_at: iso(almostExpired.clock.t + 1) }));
    assert.equal(r.next_state, "READY_TO_RESUME");
  });

  it("accepts the same instant written with a non-UTC offset", async () => {
    const s = setup();
    // The clock is 12:00:01Z, i.e. 20:00:01 at +08:00.
    const r = await s.submit(s.event({ issued_at: "2026-10-22T20:00:01+08:00", expires_at: "2026-10-22T20:00:31+08:00" }));
    assert.equal(r.next_state, "READY_TO_RESUME");
  });

  const invalidOrder: [string, (s: Setup) => Partial<TrustedHumanEvent>, string][] = [
    ["issued 1 ms in the future", (s) => ({ issued_at: iso(s.clock.t + 1), expires_at: iso(s.clock.t + 30_000) }), "event_issued_in_future"],
    ["issued a day in the future", (s) => ({ issued_at: iso(s.clock.t + 86_400_000), expires_at: iso(s.clock.t + 2 * 86_400_000) }), "event_issued_in_future"],
    ["expires_at equal to issued_at", (s) => ({ issued_at: iso(s.clock.t), expires_at: iso(s.clock.t) }), "event_time_order_invalid"],
    ["expires_at before issued_at", (s) => ({ issued_at: iso(s.clock.t), expires_at: iso(s.clock.t - 1) }), "event_time_order_invalid"],
    ["future-issued and inverted", (s) => ({ issued_at: iso(s.clock.t + 5_000), expires_at: iso(s.clock.t + 1_000) }), "event_time_order_invalid"],
    ["issued 1 ms before the pause", (s) => ({ issued_at: iso(s.pausedAt - 1) }), "event_predates_pause"],
    ["expiring exactly now", (s) => ({ issued_at: iso(s.pausedAt), expires_at: iso(s.clock.t) }), "event_expired"],
    ["expired 1 ms ago", (s) => ({ issued_at: iso(s.pausedAt), expires_at: iso(s.clock.t - 1) }), "event_expired"],
  ];
  for (const [label, times, code] of invalidOrder) {
    it(`rejects an event ${label} and stays BLOCKED`, async () => {
      const s = setup();
      assertBlocked(await s.submit(s.event(times(s))), code);
      await assertPauseStillOpen(s);
    });
  }

  const malformed: [string, unknown][] = [
    ["without an offset (local time)", "2026-10-22T12:00:01"],
    ["date-only", "2026-10-22"],
    ["RFC 2822", "Thu, 22 Oct 2026 12:00:01 GMT"],
    ["hour 24", "2026-10-22T24:00:00Z"],
    ["second 60", "2026-10-22T12:00:60Z"],
    ["offset hour 24", "2026-10-22T12:00:01+24:00"],
    ["whitespace-padded", " 2026-10-22T12:00:01Z"],
    ["empty", ""],
    ["a number", 1792670401000],
    ["null", null],
  ];
  for (const field of ["issued_at", "expires_at"] as const) {
    for (const [label, value] of malformed) {
      it(`rejects ${field} ${label} and stays BLOCKED`, async () => {
        const s = setup();
        assertBlocked(await s.submit(s.event({ [field]: value as string })), "event_time_invalid");
        await assertPauseStillOpen(s);
      });
    }
  }

  it("rejects impossible dates that Date.parse would roll over into the valid window", async () => {
    // Pause at 23:59:30 on 1 March; now is 00:00:30 on 2 March. Date.parse turns
    // "02-30" and "T24:00" into 2026-03-02T00:00:00Z, which lies inside the window.
    for (const issued_at of ["2026-02-30T00:00:00Z", "2026-03-01T24:00:00Z"]) {
      const s = setup({ pausedAt: Date.parse("2026-03-01T23:59:30Z"), ttlMs: 10 * 60_000 });
      s.clock.t = Date.parse("2026-03-02T00:00:30Z");
      assert.ok(Date.parse(issued_at) >= s.pausedAt && Date.parse(issued_at) <= s.clock.t, "precondition: lenient parse lands in the window");
      assertBlocked(await s.submit(s.event({ issued_at })), "event_time_invalid");
      await assertPauseStillOpen(s);
    }
  });

  it("rejects a local time without an offset even when it would fall inside the window", async () => {
    const s = setup();
    // 0.5 s after the pause if read as UTC; meaningless without an offset.
    assertBlocked(await s.submit(s.event({ issued_at: "2026-10-22T12:00:00.500" })), "event_time_invalid");
    await assertPauseStillOpen(s);
  });
});

describe("pause: URL privacy and binding", () => {
  const SECRET_URL = "https://alice-u53r:pa55w0rd-Xy@Example.ORG/paper?id=ID-q7Zp&token=s3cr3t-T0KEN#frag-Kq9";
  const SECRETS = ["alice-u53r", "pa55w0rd-Xy", "ID-q7Zp", "s3cr3t-T0KEN", "frag-Kq9"];
  const DISPLAY = "https://example.org/paper?id=REDACTED&token=REDACTED";
  const TOKEN_URL = "https://example.org/paper?token=AAAA-1111";

  it("never keeps or returns the raw URL", async () => {
    const s = setup({ sourceUrl: SECRET_URL });
    assert.equal(s.paused.source_url, DISPLAY);
    const resumed = await s.submit(s.event());
    assert.equal(resumed.next_state, "READY_TO_RESUME", "the host's own copy of the raw URL still binds");
    assert.equal(resumed.source_url, DISPLAY);
    s.host.events.clear(); // the host's copy is the host's business; inspect only what the store holds
    const memory = inspect(s.store, { depth: Infinity, showHidden: true });
    assert.ok(memory.includes(s.paused.pause_id), "the inspection must reach the pause records");
    for (const secret of SECRETS) {
      assert.ok(!memory.includes(secret), `store memory still holds ${secret}`);
      assert.ok(!JSON.stringify(s.paused).includes(secret), `pause result leaks ${secret}`);
      assert.ok(!JSON.stringify(resumed).includes(secret), `resume result leaks ${secret}`);
    }
  });

  it("rejects an event whose URL differs only in the token value, although both redact identically", async () => {
    const s = setup({ sourceUrl: TOKEN_URL });
    assert.equal(s.paused.source_url, "https://example.org/paper?token=REDACTED");
    assertBlocked(await s.submit(s.event({ source_url: "https://example.org/paper?token=BBBB-2222" })), "event_url_mismatch");
    await assertPauseStillOpen(s);
  });

  it("does not accept the redacted display URL as a binding", async () => {
    const s = setup({ sourceUrl: TOKEN_URL });
    assertBlocked(await s.submit(s.event({ source_url: s.paused.source_url })), "event_url_mismatch");
    await assertPauseStillOpen(s);
  });

  it("matches equivalent spellings of the same URL (scheme and host case, default port, fragment)", async () => {
    const s = setup({ sourceUrl: TOKEN_URL });
    const r = await s.submit(s.event({ source_url: "HTTPS://EXAMPLE.org:443/paper?token=AAAA-1111#section-2" }));
    assert.equal(r.next_state, "READY_TO_RESUME");
  });

  for (const variant of [
    "https://x:y@example.org/paper?token=AAAA-1111",
    "https://example.org/Paper?token=AAAA-1111",
    "https://example.org/paper?token=AAAA-1111&x=1",
    "http://example.org/paper?token=AAAA-1111",
    "not a url",
  ]) {
    it(`rejects a different URL: ${variant}`, async () => {
      const s = setup({ sourceUrl: TOKEN_URL });
      assertBlocked(await s.submit(s.event({ source_url: variant })), "event_url_mismatch");
      await assertPauseStillOpen(s);
    });
  }

  it("describes what it actually retains", () => {
    const { paused } = setup({ sourceUrl: SECRET_URL });
    assert.match(paused.data_retained, /query values removed/);
    assert.match(paused.data_retained, /HMAC-SHA256 of the full URL/);
    assert.match(paused.data_retained, /Not retained: the raw URL/);
  });
});
