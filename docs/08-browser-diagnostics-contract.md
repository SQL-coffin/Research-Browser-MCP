# 08 — Browser diagnostics boundaries: Phase 1 contract

Status: **Phase 1, waiting for review.** This document and the regression tests are committed before any implementation. Production code is unchanged from `125cd65`. Names marked *proposed* are not approved public API.

Baseline: `claude/funny-hamilton-i5tgbw` at `125cd65`. Its ancestor `699de15` is the required baseline. `125cd65` (`fix: accurate, origin-only browser network diagnostics`) landed on that branch after `699de15` and already changes the diagnostics this review covered. Every finding below was re-checked against `125cd65`. Its own contract is [07-browser-agent.md](07-browser-agent.md) §4.

## Invariants (unchanged by anything here)

- Host allowlist, URL policy, every-DNS-answer check, connection pinning and connected-peer check.
- Redirect re-validation, method rules, TLS verification, WebSocket refusal, and byte, time and resource limits.
- CAPTCHA, login and 429 detection stops the session and asks for a person. Nothing solves or evades a challenge.
- Results, proxy events and logs never contain a path, query, fragment, credentials, header, cookie, body, typed text, raw resolver message or raw filesystem error.

## Findings re-checked against 125cd65

| ID | Finding | On 125cd65 | Evidence | Phase 1 action |
|---|---|---|---|---|
| D1 | DNS resolution has no timeout. `connectPinned` starts `connectTimeoutMs` only after `resolveAndValidate`, and `dns.lookup` has none. | **Open** | Runtime: the tests below hang, or report `navigation_timeout` after 8 s instead of failing within the 1 s connect budget. A late answer is still connected to. | Contract + red tests |
| D2 | Every resolver error becomes `dns_resolution_failed`, whatever its `err.code`. | Open, but it is a design choice, not a defect | Code reading (`resolveAndValidate` `catch {}`). Runtime guard: no resolver text leaks for 6 realistic codes. | Guard tests only; finer codes are a proposal (below) |
| D5 | An unrelated origin's proxy error decides the navigation's error. | **Fixed by 125cd65** | Runtime, reproduced on `699de15` (HTTPS redirect denial → `provider_unavailable`). It passes on `125cd65`, which has its own T4 and R2–R10 tests. | None |
| C1 | Truncation of `blocked_requests` / `failed_requests` is silent. | **Fixed by 125cd65** for ≤50 entries (`request_diagnostics_truncated`) | Runtime: the T5 tests cover 30 entries. A new guard covers 60 entries between results, which evicts entries from the 50-entry buffers. | Guard test; a dropped-count field is a proposal |
| C2 | Browser-side refusals reappear in `failed_requests` as `net::ERR_BLOCKED_BY_CLIENT`. | **Fixed by 125cd65** | Runtime: covered by its T3 and R9 tests. | None |
| C3 | A failed subresource shows `502` or `net::ERR_TUNNEL_CONNECTION_FAILED` without the proxy's code. | Documented as intended in 07 §4 (diagnosis table) | Runtime (probe) | Proposal only |
| L3 | `browser_launch_failed` logs Playwright's message, including the executable's absolute path. | **Open** | Runtime: the L3 test. | Contract + red test |
| L2 | Log fields are not pinned to an allowlist. | Open (no test) | Runtime: every event except `browser_launch_failed` already matches the table below. | Contract + test (red only through L3) |

## D1 — DNS resolution is bounded

Input: a proxied request (plain HTTP or CONNECT) to an allowlisted name whose resolver does not settle.

- Resolution and TCP connect together finish within `connectTimeoutMs`.
- On expiry: `status: "timeout"`, `code: dns_timeout` (*proposed*). Plain HTTP gets 504 with `x-research-browser-proxy-error: dns_timeout`, and CONNECT gets 504. Neither carries the denial header. One `error` proxy event is recorded, origin only.
- An answer that arrives after the deadline is discarded. No connection is made, and no `allow` line is logged.
- A navigation whose only failure is this is `timeout` / `dns_timeout`, within roughly the connect budget, not `navigation_timeout` at the navigation deadline.
- Non-goals: changing the resolver, retrying, caching, or the fetch tool's own timeouts.

**Decision needed:** the code name. Option A is `dns_timeout`, which is new and tells a resolver problem apart from an unreachable destination; I recommend it. Option B is to reuse `connect_timeout`, which adds no new code but loses the cause. The tests use one constant, `DNS_TIMEOUT_CODE`, so changing the name is a one-line edit.

## L3 — Launch failures log no raw message

- `browser_launch_failed` logs only `event` and `code`. `code` is a fixed category such as `executable_missing` or `launch_failed` (*proposed values*), never error text.
- The tool result is unchanged: `provider_unavailable` / `browser_launch_failed` with a fixed message.

## L2 — Audit log fields are an allowlist

| `event` | Fields |
|---|---|
| `egress` | `event`, `decision`, `kind` (deny/error), `transport` (allow), `origin`, `code`, `peer` |
| `browser_session_open` | `event`, `session_id`, `headless` |
| `browser_session_close` | `event`, `session_id`, `reason` |
| `browser_disconnected` | `event`, `session_id` |
| `browser_request_blocked` | `event`, `session_id`, `origin`, `code` |
| `browser_request_failed` | `event`, `session_id`, `origin`, `resource_type`, `status`, `error_text` |
| `browser_action` | `event`, `session_id`, `action`, `request_id`, `status`, `code`, `origin`, `duration_ms` |
| `browser_blocked` | `event`, `session_id`, `origin`, `challenge_type`, `signals` |
| `browser_launch_failed` | `event`, `code` |

`origin` is `scheme://host[:port]`, `[non-http-url]`, `[unparseable-url]` or `[invalid-host]`. `error_text` is a `net::ERR_*` token or `request_failed`. The test also checks that its run produced each of these events, apart from `browser_disconnected`.

## Proposals: not tested, need a decision before any test or code

- **D2:** map `EAI_AGAIN` and `ESERVFAIL` to `dns_temporary_failure`, and `ETIMEOUT` to `dns_timeout`. This adds a public code to both the browser and `research.fetch_public_page`, because `resolveAndValidate` is shared. Value: callers can tell retryable failures from permanent ones. Recommendation: defer.
- **C1:** add `diagnostics_dropped: { blocked, failed }` counts next to the warning. Value: callers know how much was lost, not just that something was. Recommendation: defer; the warning plus the audit log is enough for now.
- **C3:** add `proxy_code` to `failed_requests` entries. Plain HTTP replies already carry `x-research-browser-proxy-error`, but CONNECT failures would need correlation by origin and time, which can mis-attribute. Recommendation: defer.

## Backlog (recorded, not in this batch)

| ID | Item | Severity | Evidence |
|---|---|---|---|
| D3 | `dns_no_answer` is hardly reachable in production: `getaddrinfo` throws instead of returning an empty list. | Low | Code reading |
| D4 | Earlier DNS tests were weak (no `err.code`, a conditional `net_error` assertion). | Low | Superseded by the T2 tests in 125cd65 and the D2 guards here |
| C4 | `blocked_requests` concatenates in-browser refusals and proxy denials instead of ordering them by time, so under truncation the in-browser ones are dropped first. | Low | Code reading (`attachDiagnostics`) |
| C5 | A shared 50-entry proxy buffer let errors push out denials. | Fixed by 125cd65 (separate buffers, test F6) | Runtime |
| L4 | Logs and results name the origins of hosts a page tries to reach, even unlisted ones. A host name can carry an identifier. | Info: within the origin-only contract | Code reading |
| L5 | `kind` meant two things in `egress` lines. | Fixed by 125cd65 (`transport`) | Runtime (L2 test) |
| P1 | `admit` returns `proxy_closed` without recording an event. | Low | Code reading |

## Tests

| Test | File | Today on 125cd65 | Why |
|---|---|---|---|
| D1 plain HTTP | `tests/egress-proxy.test.ts` | FAIL: hangs until the 5 s test timeout | No timeout covers resolution |
| D1 CONNECT | same | FAIL: hangs until the 5 s test timeout | Same |
| D1 late answer | same | FAIL: `200` instead of `504` | A late answer is connected to |
| D2 guards ×6 | same | PASS | No resolver text leaks; every code is in the `dns_*` family |
| D1 navigation | `tests/browser-diagnostics.test.ts` | FAIL: `navigation_timeout` instead of `dns_timeout` | The DNS hang uses up the navigation deadline |
| C1 guard (60 entries) | same | PASS | The warning holds past the 50-entry buffers |
| L3 | same | FAIL: the log contains `/nonexistent/rb-secret-dir/chrome` | `err.message` is logged |
| L2 | same | FAIL: only on `browser_launch_failed.message` | Same root cause as L3. Every other event already matches; checked by temporarily allowing `message`. |
