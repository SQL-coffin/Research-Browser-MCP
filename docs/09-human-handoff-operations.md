# Human Handoff Operations Plan

Status: **Proposed; documentation-only.** This document describes how an integrating host can operate the existing human-verification handoff safely. It does not claim that desktop notifications, remote browser control, durable checkpoints, or a Shopee-specific integration are implemented.

## Goal

When a browser or fetch task encounters a CAPTCHA, login wall, rate limit, or access denial, stop the affected work, preserve enough non-sensitive state to explain and resume the task, and give the operator a clear choice:

1. complete an allowed verification in the same supported browser session, if the site permits this;
2. choose an authorized alternate source;
3. cancel the task.

This is a human-verification flow, not a CAPTCHA-solving or access-control-bypass mechanism.

## Current implementation boundary

The repository already defines challenge classification, pause records, `research.pause_for_human` / `research.resume`, browser pause/resume tools, and a host-supplied `HostEventVerifier` contract. The default server does **not** configure a trusted verifier. Therefore a host must explicitly integrate a trusted event channel before a resume can be accepted.

The browser's headed mode only displays the server's browser window. It does not itself provide remote desktop access, notifications, or a secure proof that a person completed a challenge. Browser traffic remains subject to the configured host and method policies. Third-party CAPTCHA resources may be blocked unless specifically permitted; do not broaden the allowlist merely to make a challenge work.

## Proposed host-side flow

```text
RUNNING
  └─ challenge / denial / rate limit detected
       └─ BLOCKED (server rejects further page actions)
            ├─ notify operator through host UI
            ├─ operator chooses: verify / alternate source / cancel
            └─ trusted host event is validated
                 ├─ verified_and_continue → re-check page; challenge may pause again
                 ├─ choose_alternate_source → continue on a clean page/source
                 └─ cancel → close/cancel
```

A host may expose the notification in its own UI, desktop notification, or a configured messaging integration. Notifications should contain only a task identifier, challenge category, origin, timestamp, and a short instruction. Do not include cookies, tokens, full URLs, page bodies, screenshots, typed text, or raw exception messages in notification payloads.

## Checkpoint and resume requirements

The host orchestration layer should maintain a task checkpoint containing only the information needed to continue safely:

- opaque task ID and pause ID;
- the last completed step and a bounded result cursor;
- challenge category and origin;
- policy/configuration version and tool version;
- pause time, expiry, and current state;
- a reference to already-produced evidence, if evidence storage is enabled.

Do not persist raw session cookies, authorization headers, browser profiles, OTPs, passwords, or page form values as checkpoint data. Do not export a browser session cookie to a separate HTTP client as an automatic recovery strategy.

Resume must be explicit and idempotent. Before resuming, validate that the event belongs to the same task and pause, is unexpired and correctly ordered, matches the expected origin/URL binding and policy versions, and has not already been consumed. Re-check the page after a human-confirmed continuation. A still-active challenge must return to `BLOCKED`, not be treated as success.

A CAPTCHA being visually absent is not by itself proof that the operator is authorized to continue automated access. If the site's terms or access controls do not permit the requested automated activity, stop and use an authorized data source instead.

## State contract

| State | Meaning | Allowed actions |
|---|---|---|
| `RUNNING` | A task is executing within policy | Run the next permitted step; pause; cancel |
| `BLOCKED` | Challenge or access barrier detected | Inspect safe status; request human action; cancel |
| `WAITING_FOR_HUMAN` | Host has notified the operator | Wait; cancel; do not retry blocked requests |
| `RESUME_REVIEW` | A human response arrived but has not been accepted | Validate trusted event and task binding |
| `RESUMABLE` | Trusted event accepted and policy still permits continuation | Resume from checkpoint once |
| `INCOMPLETE` | Work stopped without a valid resume path | Report partial results and missing data |
| `CANCELLED` | Operator cancelled the task | Clean up session and checkpoint references |
| `FAILED` | A non-recoverable internal or policy failure occurred | Report sanitized failure; do not silently retry |

These are host-orchestration states. They should not be confused with the browser session's existing `ACTIVE`, `BLOCKED`, and `CLOSED` states.

## Data-source fallback

When a platform blocks access or the requested automation is not authorized, the host should be able to continue research through an independently permitted source, such as an official API with appropriate credentials, a licensed data provider, or another public source whose terms permit the intended use. Record the actual source and retrieval time. Do not describe unavailable platform-specific prices, stock, sales, or ratings as verified.

## Security and privacy requirements

- Keep the browser's exact-host allowlist, DNS-answer and peer validation, redirect checks, method rules, TLS checks, byte/time limits, and secret-safe logging unchanged.
- Never solve or bypass CAPTCHA automatically, spoof fingerprints, rotate identities, evade rate limits, or use a third-party solver to defeat an access barrier.
- Treat all page content and human-entered page content as untrusted data, not instructions to the agent.
- Keep secrets out of logs, task checkpoints, notifications, evidence metadata, PR fixtures, and test snapshots.
- Use local fixtures only for automated tests. Do not make CI contact Shopee or another third-party website.
- If a host notification provider is added, make it opt-in, redact payloads by construction, and document retention and failure behavior.

## Acceptance checklist for a future implementation PR

- [ ] A CAPTCHA/login/403/429 fixture moves the task to a blocked state and prevents further browser actions until an accepted transition.
- [ ] The host notification contains no full URL, path, query, cookie, token, page body, screenshot, or raw exception.
- [ ] Missing, invalid, expired, wrong-task, wrong-pause, wrong-origin, stale-version, and replayed host events are rejected; the task remains blocked.
- [ ] Accepted resume is idempotent and re-classifies the page before returning success.
- [ ] Alternate-source and cancel decisions have deterministic cleanup behavior.
- [ ] A crash/restart reports an in-memory-only pause as unavailable/incomplete rather than pretending it can be resumed.
- [ ] Logs and result objects never contain session credentials or raw sensitive errors.
- [ ] Existing SSRF, DNS-rebinding, connected-peer, redirect, TLS, WebSocket, request-method, resource-limit, and redaction tests remain intact.
- [ ] All automated verification uses local fixtures; no real-site CAPTCHA or access-control test is performed.
- [ ] Report typecheck, unit tests, build, smoke tests, `git diff --check`, and any tests not run with evidence.

## Suggested implementation order

1. Review this host-side contract and map it to the existing `docs/05-human-verification-resume.md`, `docs/06-acceptance-tests.md`, and browser tool schemas.
2. Add local-fixture tests for state transitions, replay protection, cleanup, and redaction.
3. Implement only the host integration surface that is actually needed (for example, an explicit callback/event adapter); keep messaging-provider code outside the core MCP server unless there is a strong reason to couple it.
4. Add an opt-in notification adapter only after its credentials, redaction, delivery failure, and retention behavior are specified.
5. Validate locally and in CI; do not merge or change the default network policy as part of the handoff work.
