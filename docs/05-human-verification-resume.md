# 05 · Human Verification and Resume Protocol

Version: v0.1 draft

## 1. Principle

The goal is to support a legitimate human verification flow and safe workflow resumption, not to defeat CAPTCHA or other access controls. A challenge is a pause condition. The system must never describe a solver, identity rotation, stealth mode, or hidden session replay as human verification.

## 2. Challenge classes

| Type | Meaning | Default behavior |
|---|---|---|
| `none` | No challenge observed | Continue within normal policy |
| `captcha` | CAPTCHA or human-check page observed | Pause; do not solve or bypass |
| `login_required` | Authentication is required | Pause or use a different authorized public source |
| `rate_limited` | Provider/site imposes a rate limit | Respect retry guidance and budgets; do not rotate identities to evade it |
| `robots_or_policy_block` | Site policy disallows the requested access | Stop; do not attempt bypass |
| `unknown` | Signals are ambiguous | Fail safe and require human review or another source |

## 3. State machine

```text
FETCHING
  | challenge detected
  v
CHALLENGE_REPORTED
  | host runtime appends TaskBlocked / BLOCKED(human_feedback)
  v
BLOCKED
  | trusted human feedback or alternate-source decision is recorded
  v
RESUME_PRECHECK
  | policy, URL, version, budget, and task checks pass
  v
READY_TO_RESUME
  | host runtime dispatches a new permitted tool call
  v
FETCHING or DONE
```

The browser service reports a challenge and provides handoff metadata. The host runtime owns durable task state and is responsible for recording trusted human feedback. The server must not infer that a browser was manually verified simply because it received another request.

## 4. Required binding

Trusted feedback should be bound to:

- `task_id` and a unique event ID;
- the challenged URL or approved source identity;
- challenge type and pause event ID;
- the human actor/channel identity as defined by the host;
- timestamp and expiry policy;
- decision: `verified_and_continue`, `choose_alternate_source`, or `cancel`;
- policy and tool versions used for precheck.

Do not include CAPTCHA answers, passwords, cookies, authorization headers, tokens, browser profiles, or screenshots containing unrelated private data in the event by default.

## 5. Resume checks

Before resuming, the host runtime rechecks:

1. Task is still blocked for the expected challenge.
2. A trusted human-feedback event exists and matches the task and source.
3. The runtime mode still permits research access.
4. Tool and policy versions have not drifted; if they have, require explicit review or replan.
5. The remaining budget and deadlines permit another attempt.
6. No unresolved source conflict or data-scope violation blocks the task.
7. Resume event has not already been consumed.

After the check, the host runtime emits a resume event and dispatches a fresh bounded tool call. A stale or duplicate resume handle must be rejected or handled idempotently.

## 6. Alternate-source path

Human review may select another public, authorized source. The browser should return to the normal provider registry and policy checks; it must not automatically select a source to evade a policy block. An alternate source must be recorded as a new evidence lineage, not as successful verification of the original blocked URL.

## 7. User experience

The handoff should explain the reason, what has already completed, what human action is needed, what data will be retained, and how to cancel or use an alternate source. It must avoid implying that access is guaranteed after verification.

## Browser sessions

A browser session that reaches a challenge page, or whose caller calls `browser.pause_for_human`, is paused through the same `HandoffStore`, with the session id as `task_id`. The resume handle stays on the server: `browser.resume_session` takes only the host event reference. While paused, the session serves no action, snapshot or screenshot. After `verified_and_continue` the page is checked again and a fresh pause is recorded if the challenge is still there; `choose_alternate_source` leaves the session on `about:blank`; `cancel` closes it. In headed mode a person can see and use the window, but the person's traffic is subject to the same allowlist and method rule. See [07 · Browser Agent](07-browser-agent.md#6-human-takeover-and-resume).
