import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { ChallengeType } from "./security.js";
import { redactUrl } from "./security.js";
import { newRequestId, TOOL_VERSION, toolError, type Status, type ToolError } from "./result.js";

/**
 * Human-verification handoff. This service never manufactures proof that a human
 * verified anything: it records a pause, issues an opaque resume handle, and on
 * resume either (a) defers authorization to the host runtime, or (b) when the
 * host has configured a trusted event verifier, checks the event's binding to the
 * task, pause and URL, its time order, and the policy and tool versions.
 *
 * A rejected event leaves the pause BLOCKED and unconsumed. Pause records never
 * hold the raw source URL (see PauseRecord).
 */

export type HumanDecision = "verified_and_continue" | "choose_alternate_source" | "cancel";

/** A human-feedback event as attested by the host runtime's trusted channel. */
export interface TrustedHumanEvent {
  event_id: string;
  task_id: string;
  /** The challenged URL as the host recorded it; compared by canonical form, never by its redacted display. */
  source_url: string;
  pause_id: string;
  decision: HumanDecision;
  /** RFC 3339 with an explicit offset, e.g. "2026-10-22T12:00:00Z". */
  issued_at: string;
  /** RFC 3339 with an explicit offset; must be later than issued_at. */
  expires_at: string;
  policy_version: string;
  tool_version: string;
}

/**
 * Implemented by the integrating host. Returns the event only if it arrived
 * through a trusted channel; returns null for unknown or untrusted references.
 */
export interface HostEventVerifier {
  verify(eventRef: string): Promise<TrustedHumanEvent | null>;
}

export interface PauseInput {
  task_id: string;
  source_url: string;
  reason: ChallengeType;
  completed_steps: string;
  next_step: string;
}

interface PauseRecord {
  pause_id: string;
  task_id: string;
  /** For display only: scheme, host and path; userinfo, fragment and query values removed. */
  display_url: string;
  /** HMAC-SHA256 of the canonical URL; the only form compared with an event's URL. */
  url_binding: Buffer;
  reason: ChallengeType;
  created_at: number;
  expires_at: number;
  policy_version: string;
  /** Set only by an accepted event (for idempotent replays); rejected events leave it null. */
  consumedBy: { event_id: string; outcome: ResumeResult } | null;
}

export interface PauseResult {
  status: "human_verification_required";
  request_id: string;
  task_id: string;
  pause_id: string;
  source_url: string;
  reason: ChallengeType;
  resume_handle: string;
  expires_at: string;
  human_instructions: string;
  data_retained: string;
  authorization_owner: "host_runtime";
}

export interface ResumeResult {
  status: Status;
  request_id: string;
  resume_authorized: boolean;
  /** What the host should do next. The service never dispatches work itself. */
  next_state: "BLOCKED" | "READY_TO_RESUME" | "ALTERNATE_SOURCE" | "CANCELLED";
  task_id?: string;
  source_url?: string;
  authorization_owner: "host_runtime" | "verified_host_event";
  replayed?: boolean;
  error?: ToolError;
}

export interface HandoffOptions {
  policyVersion: string;
  ttlMs: number;
  verifier: HostEventVerifier | null;
  now: () => number;
  maxRecords: number;
}

export const DEFAULT_HANDOFF_OPTIONS: HandoffOptions = {
  policyVersion: "0.1.0",
  ttlMs: 60 * 60 * 1000,
  verifier: null,
  now: Date.now,
  maxRecords: 1000,
};

const SECRET_LIKE = /(password|passwd|cookie|authorization|bearer\s|token=|captcha[_ ]?(answer|solution)|session[_-]?id)/i;

/**
 * Canonical form compared for URL binding: the WHATWG serialisation (scheme and
 * host lower-cased, default port dropped) without the fragment, which is never
 * sent to a server. The paused URL and the event's URL both go through this, so
 * equivalent spellings match while any difference in userinfo, path or query,
 * including a different token value, does not.
 */
function canonicalBindingUrl(raw: string): string | null {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") return null;
  url.hash = "";
  return url.href;
}

const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|[+-](\d{2}):(\d{2}))$/;
const DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/**
 * Strict RFC 3339 timestamp with an explicit offset, as epoch ms. Date.parse alone
 * accepts offset-less local times, date-only and RFC 2822 strings, and rolls
 * 2026-02-30 or T24:00 over into a later day, so the fields are checked first.
 */
function parseRfc3339(value: unknown): number | null {
  if (typeof value !== "string") return null;
  const m = RFC3339.exec(value);
  if (!m) return null;
  const [year, month, day, hour, minute, second] = m.slice(1, 7).map(Number) as [number, number, number, number, number, number];
  const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  const days = month === 2 && leap ? 29 : DAYS_IN_MONTH[month - 1];
  if (days === undefined || day < 1 || day > days || hour > 23 || minute > 59 || second > 59) return null;
  if (m[7] !== undefined && (Number(m[7]) > 23 || Number(m[8]) > 59)) return null;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : ms;
}

/**
 * The time order a trusted event must satisfy, on this store's clock:
 *   pause created_at <= issued_at <= now < expires_at  (hence issued_at < expires_at)
 * The pause's own expiry is checked separately (resume_handle_expired).
 */
function eventTimeError(event: TrustedHumanEvent, pausedAt: number, now: number): [code: string, message: string] | null {
  const issued = parseRfc3339(event.issued_at);
  const expires = parseRfc3339(event.expires_at);
  if (issued === null || expires === null) return ["event_time_invalid", "Event timestamps must be RFC 3339 with an explicit offset"];
  if (expires <= issued) return ["event_time_order_invalid", "Event expires_at must be later than issued_at"];
  if (issued > now) return ["event_issued_in_future", "Event is issued in the future of this service's clock"];
  if (issued < pausedAt) return ["event_predates_pause", "Event was issued before the task was paused"];
  if (now >= expires) return ["event_expired", "Event has expired"];
  return null;
}

export class HandoffStore {
  private readonly records = new Map<string, PauseRecord>();
  private readonly opts: HandoffOptions;
  /** Per-store random key for URL bindings; never returned or persisted. */
  private readonly bindingKey = randomBytes(32);

  constructor(opts: Partial<HandoffOptions> = {}) {
    this.opts = { ...DEFAULT_HANDOFF_OPTIONS, ...opts };
  }

  pause(input: PauseInput): PauseResult | { status: "invalid_input"; request_id: string; error: ToolError } {
    const request_id = newRequestId();
    if (SECRET_LIKE.test(`${input.completed_steps}\n${input.next_step}`)) {
      return { status: "invalid_input", request_id, error: toolError("invalid_input", "secret_in_handoff", "Handoff text must not contain credentials, cookies, tokens or CAPTCHA answers") };
    }
    const canonical = canonicalBindingUrl(input.source_url);
    if (canonical === null) {
      return { status: "invalid_input", request_id, error: toolError("invalid_input", "invalid_source_url", "source_url must be an absolute http(s) URL") };
    }
    this.evict();
    const now = this.opts.now();
    const handle = randomBytes(32).toString("base64url");
    const record: PauseRecord = {
      pause_id: newRequestId(),
      task_id: input.task_id,
      // The raw URL is not stored: it may carry tokens, credentials or signed query values.
      display_url: redactUrl(canonical, "log"),
      url_binding: this.bindUrl(canonical),
      reason: input.reason,
      created_at: now,
      expires_at: now + this.opts.ttlMs,
      policy_version: this.opts.policyVersion,
      consumedBy: null,
    };
    this.records.set(handle, record);
    return {
      status: "human_verification_required",
      request_id,
      task_id: record.task_id,
      pause_id: record.pause_id,
      source_url: record.display_url,
      reason: record.reason,
      resume_handle: handle,
      expires_at: new Date(record.expires_at).toISOString(),
      human_instructions:
        `The page reported "${record.reason}". A person must review it through the host application. ` +
        "This service will not solve CAPTCHAs, sign in, or bypass access controls. " +
        "The person may verify and continue, choose an alternate public source, or cancel. Access is not guaranteed after verification.",
      data_retained:
        "Held in memory until the resume handle expires or is evicted: task_id, pause_id, reason, timestamps, policy version, " +
        "a display URL (scheme, host and path; userinfo, fragment and query values removed) and an HMAC-SHA256 of the full URL " +
        "under a per-store random key, used only to match the host's event. Not retained: the raw URL, completed_steps, next_step, " +
        "credentials, cookies and page content.",
      authorization_owner: "host_runtime",
    };
  }

  async resume(handle: string, hostEventRef: string): Promise<ResumeResult> {
    const request_id = newRequestId();
    const deny = (code: string, message: string, extra: Partial<ResumeResult> = {}): ResumeResult => ({
      status: "policy_denied",
      request_id,
      resume_authorized: false,
      next_state: "BLOCKED",
      authorization_owner: "host_runtime",
      error: toolError("policy_denied", code, message),
      ...extra,
    });

    const record = this.records.get(handle);
    if (!record) return deny("unknown_resume_handle", "Resume handle is unknown or has been evicted");
    const now = this.opts.now();
    if (now >= record.expires_at) return deny("resume_handle_expired", "Resume handle has expired; pause again");

    const binding = { task_id: record.task_id, source_url: record.display_url };

    if (!this.opts.verifier) {
      // Without a trusted channel the event reference is just a claim. Report it and
      // leave authorization with the host; never treat it as proof.
      return {
        status: "human_verification_required",
        request_id,
        resume_authorized: false,
        next_state: "BLOCKED",
        authorization_owner: "host_runtime",
        ...binding,
        error: toolError("human_verification_required", "host_verification_required", "No trusted host event verifier is configured; the host runtime must authorize this resume"),
      };
    }

    let event: TrustedHumanEvent | null;
    try {
      event = await this.opts.verifier.verify(hostEventRef);
    } catch {
      return deny("host_verifier_failed", "Host event verifier failed; resume not authorized", binding);
    }
    if (!event) return deny("untrusted_or_unknown_event", "Host event is unknown or not from a trusted channel", binding);

    if (record.consumedBy) {
      if (record.consumedBy.event_id === event.event_id) return { ...record.consumedBy.outcome, request_id, replayed: true };
      return deny("resume_already_consumed", "This pause was already resolved by a different event", binding);
    }
    if (event.task_id !== record.task_id || event.pause_id !== record.pause_id) {
      return deny("event_task_mismatch", "Host event does not match this task or pause", binding);
    }
    // Compare bindings, never redacted strings: two URLs that differ only in a token
    // value redact identically but must not authorize each other.
    const eventUrl = canonicalBindingUrl(event.source_url);
    if (eventUrl === null || !timingSafeEqual(this.bindUrl(eventUrl), record.url_binding)) {
      return deny("event_url_mismatch", "Host event does not match the challenged URL", binding);
    }
    const timeError = eventTimeError(event, record.created_at, now);
    if (timeError) return deny(timeError[0], timeError[1], binding);
    if (event.policy_version !== record.policy_version || event.tool_version !== TOOL_VERSION || this.opts.policyVersion !== record.policy_version) {
      return deny("version_drift", "Policy or tool version changed while blocked; explicit review or replan is required", binding);
    }

    let outcome: ResumeResult;
    switch (event.decision) {
      case "verified_and_continue":
        outcome = { status: "success", request_id, resume_authorized: true, next_state: "READY_TO_RESUME", authorization_owner: "verified_host_event", ...binding };
        break;
      case "choose_alternate_source":
        // An alternate source is a new evidence lineage, not verification of this URL.
        outcome = { status: "success", request_id, resume_authorized: false, next_state: "ALTERNATE_SOURCE", authorization_owner: "verified_host_event", ...binding };
        break;
      case "cancel":
        outcome = { status: "blocked", request_id, resume_authorized: false, next_state: "CANCELLED", authorization_owner: "verified_host_event", ...binding, error: toolError("blocked", "cancelled_by_human", "Task was cancelled by the human reviewer") };
        break;
    }
    record.consumedBy = { event_id: event.event_id, outcome };
    return outcome;
  }

  private bindUrl(canonicalUrl: string): Buffer {
    return createHmac("sha256", this.bindingKey).update(canonicalUrl).digest();
  }

  private evict(): void {
    const now = this.opts.now();
    for (const [h, r] of this.records) if (now >= r.expires_at) this.records.delete(h);
    while (this.records.size >= this.opts.maxRecords) {
      const oldest = this.records.keys().next().value;
      if (oldest === undefined) break;
      this.records.delete(oldest);
    }
  }
}
