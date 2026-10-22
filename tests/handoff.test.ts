import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { HandoffStore, type HostEventVerifier, type TrustedHumanEvent } from "../src/handoff.js";
import { TOOL_VERSION } from "../src/result.js";

const URL_ = "https://example.org/paper";
let clock = 1_000_000;
const now = () => clock;

/** Fake host runtime: only events it has recorded are trusted. */
class FakeHost implements HostEventVerifier {
  readonly events = new Map<string, TrustedHumanEvent>();
  async verify(ref: string) {
    return this.events.get(ref) ?? null;
  }
}

function setup(policyVersion = "p1") {
  const host = new FakeHost();
  const store = new HandoffStore({ verifier: host, now, policyVersion, ttlMs: 60_000 });
  const paused = store.pause({ task_id: "task-1", source_url: URL_, reason: "captcha", completed_steps: "fetched search results", next_step: "read the paper" });
  assert.equal(paused.status, "human_verification_required");
  if (paused.status !== "human_verification_required") throw new Error("unreachable");
  const event = (over: Partial<TrustedHumanEvent> = {}): TrustedHumanEvent => ({
    event_id: "evt-1",
    task_id: "task-1",
    source_url: URL_,
    pause_id: paused.pause_id,
    decision: "verified_and_continue",
    issued_at: new Date(clock + 1).toISOString(),
    expires_at: new Date(clock + 30_000).toISOString(),
    policy_version: policyVersion,
    tool_version: TOOL_VERSION,
    ...over,
  });
  return { host, store, paused, event };
}

describe("pause_for_human", () => {
  it("returns a handoff without claiming verification", () => {
    const { paused } = setup();
    assert.equal(paused.authorization_owner, "host_runtime");
    assert.match(paused.human_instructions, /will not solve CAPTCHAs/);
    assert.ok(paused.resume_handle.length >= 40);
  });

  it("refuses handoff text containing secrets", () => {
    const store = new HandoffStore({ now });
    const r = store.pause({ task_id: "t", source_url: URL_, reason: "login_required", completed_steps: "password: hunter2", next_step: "" });
    assert.equal(r.status, "invalid_input");
  });
});

describe("resume", () => {
  it("defers to the host when no trusted verifier is configured", async () => {
    const store = new HandoffStore({ now });
    const p = store.pause({ task_id: "t", source_url: URL_, reason: "captcha", completed_steps: "", next_step: "" });
    assert.equal(p.status, "human_verification_required");
    if (p.status !== "human_verification_required") return;
    const r = await store.resume(p.resume_handle, "the user said they solved it");
    assert.equal(r.resume_authorized, false);
    assert.equal(r.next_state, "BLOCKED");
    assert.equal(r.error?.code, "host_verification_required");
  });

  it("authorizes with a matching trusted event", async () => {
    const { host, store, paused, event } = setup();
    host.events.set("ref-1", event());
    const r = await store.resume(paused.resume_handle, "ref-1");
    assert.equal(r.status, "success");
    assert.equal(r.resume_authorized, true);
    assert.equal(r.next_state, "READY_TO_RESUME");
  });

  it("denies an absent or untrusted event (RB-13)", async () => {
    const { store, paused } = setup();
    const r = await store.resume(paused.resume_handle, "made-up-ref");
    assert.equal(r.resume_authorized, false);
    assert.equal(r.error?.code, "untrusted_or_unknown_event");
  });

  for (const [name, over, code] of [
    ["task", { task_id: "task-2" }, "event_task_mismatch"],
    ["pause", { pause_id: "other" }, "event_task_mismatch"],
    ["url", { source_url: "https://example.org/other" }, "event_url_mismatch"],
    ["stale event", { issued_at: new Date(0).toISOString() }, "event_stale_or_expired"],
    ["expired event", { expires_at: new Date(0).toISOString() }, "event_stale_or_expired"],
  ] as const) {
    it(`denies a mismatched ${name} (RB-13)`, async () => {
      const { host, store, paused, event } = setup();
      host.events.set("ref", event(over));
      const r = await store.resume(paused.resume_handle, "ref");
      assert.equal(r.resume_authorized, false);
      assert.equal(r.error?.code, code);
    });
  }

  it("denies an unknown or expired handle", async () => {
    const { host, store, paused, event } = setup();
    host.events.set("ref", event());
    assert.equal((await store.resume("x".repeat(43), "ref")).error?.code, "unknown_resume_handle");
    clock += 120_000;
    assert.equal((await store.resume(paused.resume_handle, "ref")).error?.code, "resume_handle_expired");
  });

  it("is idempotent for a duplicate event and rejects a second, different event (RB-14)", async () => {
    const { host, store, paused, event } = setup();
    host.events.set("ref-a", event());
    host.events.set("ref-b", event({ event_id: "evt-2" }));
    const first = await store.resume(paused.resume_handle, "ref-a");
    const again = await store.resume(paused.resume_handle, "ref-a");
    assert.equal(first.resume_authorized, true);
    assert.equal(again.resume_authorized, true);
    assert.equal(again.replayed, true);
    const other = await store.resume(paused.resume_handle, "ref-b");
    assert.equal(other.resume_authorized, false);
    assert.equal(other.error?.code, "resume_already_consumed");
  });

  it("blocks on policy or tool version drift (RB-15)", async () => {
    const { host, store, paused, event } = setup();
    host.events.set("p", event({ policy_version: "p2" }));
    host.events.set("t", event({ event_id: "e2", tool_version: "9.9.9" }));
    assert.equal((await store.resume(paused.resume_handle, "p")).error?.code, "version_drift");
    assert.equal((await store.resume(paused.resume_handle, "t")).error?.code, "version_drift");
  });

  it("treats alternate source as a new lineage, not verification", async () => {
    const { host, store, paused, event } = setup();
    host.events.set("alt", event({ decision: "choose_alternate_source" }));
    const r = await store.resume(paused.resume_handle, "alt");
    assert.equal(r.resume_authorized, false);
    assert.equal(r.next_state, "ALTERNATE_SOURCE");
  });

  it("honours cancel", async () => {
    const { host, store, paused, event } = setup();
    host.events.set("c", event({ decision: "cancel" }));
    const r = await store.resume(paused.resume_handle, "c");
    assert.equal(r.next_state, "CANCELLED");
    assert.equal(r.resume_authorized, false);
  });

  it("fails closed when the verifier throws", async () => {
    const store = new HandoffStore({ now, verifier: { verify: async () => { throw new Error("down"); } } });
    const p = store.pause({ task_id: "t", source_url: URL_, reason: "captcha", completed_steps: "", next_step: "" });
    if (p.status !== "human_verification_required") throw new Error("unreachable");
    const r = await store.resume(p.resume_handle, "x");
    assert.equal(r.resume_authorized, false);
    assert.equal(r.error?.code, "host_verifier_failed");
  });
});
