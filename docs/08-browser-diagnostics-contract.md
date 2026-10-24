# 08 — Browser diagnostics boundaries (contract)

Status: **Proposed.** The regression tests below are committed before any implementation and are expected to fail until it lands. Nothing here changes what is allowed or denied: the host allowlist, URL/DNS-answer/peer validation, redirect re-checks, method rules, TLS policy, WebSocket refusal, byte/time limits and the CAPTCHA/human-verification pause stay exactly as they are. Only how failures are classified, counted and logged changes.

Baseline: `claude/funny-hamilton-i5tgbw` at `699de15` (browser diagnostics from `00be3a1`, documented in [07-browser-agent.md](07-browser-agent.md)).

## D1 — DNS resolution is bounded

- In the egress proxy (`connectPinned`), name resolution and the TCP connect together finish within `connectTimeoutMs`. Today the timer starts only after resolution, and `dns.lookup` has no timeout.
- A resolution that does not finish in time is `status: "timeout"`, `code: "dns_timeout"`: HTTP 504 from the proxy, without the denial header, recorded as a proxy `error` event (origin only).
- An answer arriving after the deadline is discarded; no connection is made to it.
- A browser navigation whose only failure is that timeout returns `timeout` / `dns_timeout`, not `navigation_timeout`.

## D2 — Resolver errors are classified by error code

| Resolver `err.code` | `code` | Proxy HTTP status |
|---|---|---|
| `ENOTFOUND`, `ENODATA` | `dns_resolution_failed` (unchanged) | 502 |
| `EAI_AGAIN`, `ESERVFAIL` | `dns_temporary_failure` | 502 |
| `ETIMEOUT` | `dns_timeout` | 504 |
| anything else, or no code | `dns_resolution_failed` (unchanged) | 502 |

The resolver's message text is never copied into results, events, logs or the proxy's response body. `resolveAndValidate` is shared with `research.fetch_public_page`, so its fetch results gain the same two codes; review that as part of this change.

## D5 — Navigation errors are attributed to the navigation

- A proxy connection error decides a navigation's outcome only if its origin is an origin of this navigation (the requested URL or a redirect hop).
- A policy denial in the navigation always wins over a connection error.
- Today `navigationError` takes any proxy error recorded since the navigation started, from any origin, ahead of denials. Reproduced: an earlier page's late DNS failure on another origin turns an HTTPS redirect denial (`policy_denied` / `host_not_allowlisted`) into `provider_unavailable` / `dns_resolution_failed`.

## C1 — Truncation is visible

- Every browser result carries `diagnostics_dropped: { blocked: number, failed: number }`, alongside `blocked_requests` and `failed_requests` (`{ blocked: 0, failed: 0 }` when nothing was dropped).
- It counts the new entries since the previous result that are not listed, whether cut by the 20-per-result cap or evicted from the 50-entry buffers before they were reported.
- So for any run of results, listed entries plus dropped counts equal the number of requests recorded.

## C2 — No double counting

A request the browser-side route refused (it is in `blocked_requests`) is not also reported in `failed_requests`, and is not logged as `browser_request_failed`. Today every such request reappears there as `net::ERR_BLOCKED_BY_CLIENT`, and with more than 20 blocked requests those copies fill the whole `failed_requests` list.

## C3 — Subresource failures carry the proxy's reason

A `failed_requests` entry may include `proxy_code`: the code of the proxy `error` event for the same origin that the failure followed, for example `dns_resolution_failed` or `connect_timeout`. Today that code appears only in the audit log, while the result shows `status: 502` (HTTP) or `net::ERR_TUNNEL_CONNECTION_FAILED` (HTTPS). The entry stays origin-only.

## L2 / L3 — Log fields are an allowlist

Each audit event has a fixed set of fields. Any other field is a contract violation:

| `event` | Fields |
|---|---|
| `egress` | `event`, `decision`, `kind`, `origin`, `code`, `peer` |
| `browser_session_open` | `event`, `session_id`, `headless` |
| `browser_session_close` | `event`, `session_id`, `reason` |
| `browser_disconnected` | `event`, `session_id` |
| `browser_request_blocked` | `event`, `session_id`, `origin`, `code` |
| `browser_request_failed` | `event`, `session_id`, `origin`, `resource_type`, `status`, `error_text`, `proxy_code` |
| `browser_action` | `event`, `session_id`, `action`, `request_id`, `status`, `code`, `origin`, `duration_ms` |
| `browser_blocked` | `event`, `session_id`, `origin`, `challenge_type`, `signals` |
| `browser_launch_failed` | `event`, `code` |

`origin` is always `scheme://host[:port]`, `[non-http-url]` or `[unparseable-url]`. `error_text` is always a `net::ERR_*` token or `request_failed`.

L3: `browser_launch_failed` no longer logs `err.message`. Playwright's launch errors contain the executable's absolute path, which can include a user name. It logs a fixed category `code` instead.

## Tests

| Contract | Test | Today |
|---|---|---|
| D1 | `tests/egress-proxy.test.ts` — "egress proxy diagnostics contract: DNS timeout (D1)": HTTP, CONNECT, late answer | fails (hangs until the 5 s test timeout; the late answer is connected to and returns 200) |
| D1 | `tests/browser.test.ts` — "D1: reports dns_timeout…" | fails: `navigation_timeout` |
| D2 | `tests/egress-proxy.test.ts` — "resolver error classes (D2)" | `EAI_AGAIN`, `ESERVFAIL`, `ETIMEOUT` fail; `ENOTFOUND`, `ENODATA` and the no-code case pass as guards |
| D5 | "D5: a policy denial in the navigation is not reported…" | fails: `provider_unavailable` |
| C1 | "C1: every result carries diagnostics_dropped…" | fails: field missing |
| C2 | "C2: requests listed in blocked_requests are not repeated…" | fails: 3 `ERR_BLOCKED_BY_CLIENT` copies |
| C3 | "C3: a failed subresource carries the proxy's error code…" | fails: no `proxy_code` |
| L3 | "L3: a launch failure is logged without…" | fails: path in `message` |
| L2 | "L2: every browser and egress log event uses only its documented fields" | fails only on `browser_launch_failed.message` (L3); every other event already matches, so after L3 it is a regression guard |
