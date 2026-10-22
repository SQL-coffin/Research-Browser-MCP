import { randomBytes } from "node:crypto";
import type { ChallengeType } from "./security.js";
import { redactUrl } from "./security.js";
import { newRequestId, TOOL_VERSION, toolError, type Status, type ToolError } from "./result.js";

/**
 * Human-verification handoff. This service never manufactures proof that a human
 * verified anything: it records a pause, issues an opaque resume handle, and on
 * resume either (a) defers authorization to the host runtime, or (b) when the
 * host has configured a trusted event verifier, checks the event's binding.
 */

export type HumanDecision = "verified_and_continue" | "choose_alternate_source" | "cancel";

/** A human-feedback event as attested by the host runtime's trusted channel. */
export interface TrustedHumanEvent {
  event_id: string;
  task_id: string;
  source_url: string;
  pause_id: string;
  decision: HumanDecision;
  issued_at: string;
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
  source_url: string;
  reason: ChallengeType;
  created_at: number;
  expires_at: number;
  policy_version: string;
  /** event_id -> outcome, for idempotent replays. */
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

export class HandoffStore {
  private readonly records = new Map<string, PauseRecord>();
  private readonly opts: HandoffOptions;

  constructor(opts: Partial<HandoffOptions> = {}) {
    this.opts = { ...DEFAULT_HANDOFF_OPTIONS, ...opts };
  }

  pause(input: PauseInput): PauseResult | { status: "invalid_input"; request_id: string; error: ToolError } {
    const request_id = newRequestId();
    if (SECRET_LIKE.test(`${input.completed_steps}\n${input.next_step}`)) {
      return { status: "invalid_input", request_id, error: toolError("invalid_input", "secret_in_handoff", "Handoff text must not contain credentials, cookies, tokens or CAPTCHA answers") };
    }
    this.evict();
    const now = this.opts.now();
    const handle = randomBytes(32).toString("base64url");
    const record: PauseRecord = {
      pause_id: newRequestId(),
      task_id: input.task_id,
      source_url: input.source_url,
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
      source_url: redactUrl(record.source_url),
      reason: record.reason,
      resume_handle: handle,
      expires_at: new Date(record.expires_at).toISOString(),
      human_instructions:
        `The page reported "${record.reason}". A person must review it through the host application. ` +
        "This service will not solve CAPTCHAs, sign in, or bypass access controls. " +
        "The person may verify and continue, choose an alternate public source, or cancel. Access is not guaranteed after verification.",
      data_retained: "task_id, source_url, reason and timestamps, in memory until expiry; no credentials, cookies or page content.",
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
    if (now > record.expires_at) return deny("resume_handle_expired", "Resume handle has expired; pause again");

    const binding = { task_id: record.task_id, source_url: redactUrl(record.source_url) };

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
    if (event.source_url !== record.source_url) return deny("event_url_mismatch", "Host event does not match the challenged URL", binding);
    const issued = Date.parse(event.issued_at);
    const expires = Date.parse(event.expires_at);
    if (Number.isNaN(issued) || Number.isNaN(expires) || issued < record.created_at || now > expires) {
      return deny("event_stale_or_expired", "Host event predates the pause or has expired", binding);
    }
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

  private evict(): void {
    const now = this.opts.now();
    for (const [h, r] of this.records) if (now > r.expires_at) this.records.delete(h);
    while (this.records.size >= this.opts.maxRecords) {
      const oldest = this.records.keys().next().value;
      if (oldest === undefined) break;
      this.records.delete(oldest);
    }
  }
}
