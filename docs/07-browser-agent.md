# 07 · Browser Agent

Version: v0.1 draft

The `browser.*` tools give an agent a real browser (Playwright driving Chromium) for public pages that need JavaScript, while keeping the fetcher's network policy, output limits and redaction. They are **off by default** and appear only when the operator sets `RESEARCH_BROWSER_ENABLE_BROWSER=1`.

The browser **detects, records and pauses** on CAPTCHAs, login walls, rate limits and access blocks. It never solves, bypasses or works around them, and it does no fingerprint spoofing or stealth.

## 1. Components

| File | Role |
|---|---|
| `src/egress-proxy.ts` | Loopback forward proxy: the browser's only route to the network. Applies the fetch policy to every connection. |
| `src/browser/session.ts` | One session = one Chromium process + one fresh in-memory context + one page + its own proxy. Launch flags, in-browser request checks, cleanup. |
| `src/browser/snapshot.ts` | Read-only page scripts: page text and the indexed list of interactive elements. |
| `src/browser/actions.ts` | `BrowserAgent`: the tool behaviour, session limits and timeouts, the challenge check after every action, pause/resume, evidence. |
| `src/evidence.ts` | Shared content-addressed evidence store, also used by `research.fetch_public_page`. |

## 2. Network path

```text
Chromium ──(--proxy-server, no loopback bypass, per-proxy credentials)──▶ egress proxy (127.0.0.1)
   │ in-browser request handler:                                         │ for each plain-HTTP request and each CONNECT:
   │  URL policy + allowlist + method rule                               │  URL policy (scheme, port, credentials, allowlist)
   │  WebSockets refused                                                 │  every DNS answer → connect to that IP → peer check
   ▼                                                                     ▼
 request aborted (blocked_requests)                                   destination (TLS verified by Chromium)
```

- **Same policy as the fetcher.** The browser's allowlist, schemes, ports and address check are the fetch policy built from `RESEARCH_BROWSER_ALLOWED_HOSTS`. Tool input cannot change them.
- **Every hop.** Redirects, subresources, iframes, `fetch()`/XHR and background requests all go through the proxy, so each one is checked; a redirect to an unlisted or private destination fails like a direct request.
- **Loopback is not bypassed.** Chromium normally skips the proxy for `localhost` and `127.0.0.1`; the session removes that bypass (`<-loopback>`), so those requests reach the proxy and are refused.
- **The proxy is private to its session.** It listens on `127.0.0.1` only and requires random credentials generated per proxy, so neither other local processes nor page content can use it.
- **TLS is not terminated.** HTTPS is a CONNECT tunnel; Chromium verifies the destination certificate itself, and certificate errors are never ignored (`ignoreHTTPSErrors: false`).
- **Method rule.** Only `GET` and `HEAD` are allowed, except on hosts listed in `RESEARCH_BROWSER_FORM_SUBMIT_HOSTS`. The proxy enforces this for plain HTTP; inside an HTTPS tunnel only the browser can see the method, so the in-browser request handler enforces it there.
- **Off:** WebSockets, service workers, downloads, popups (closed when they open), JavaScript dialogs (dismissed), QUIC, and WebRTC UDP that does not go through the proxy.
- **Limits per session:** 10 MiB per plain-HTTP response, 200 MiB relayed in total, 64 connections, 60 s idle per connection, 5 s for name resolution and connect together.

## 3. Sessions

- **Isolation.** Each session is a separate Chromium process with a fresh incognito-style context: no cookies, cache, storage or profile are shared between sessions or kept after close. Playwright's temporary profile directory is deleted when the browser closes.
- **Limits.** At most 2 sessions at once. A session is closed after 5 minutes without an action, after 30 minutes in total, or when an action runs past its hard deadline (navigation timeout + 2 × action timeout), which also covers a page that freezes its renderer. Navigation timeout 20 s, action timeout 10 s.
- **Cleanup.** `browser.close_session`, the reaper, a browser crash, client disconnect, stdin EOF, `SIGINT` and `SIGTERM` all close the page, context, browser process and proxy. The smoke tests check that no browser process outlives its session or the server.
- **One action at a time.** Actions on one session run in order; different sessions run independently.

## 4. Tools

All take a `session_id` (UUID) except `open_session`. None takes a host, header, cookie, proxy, timeout or other policy argument.

| Tool | Input | Notes |
|---|---|---|
| `browser.open_session` | — | Returns `session_id`, `headless`, limits. |
| `browser.navigate` | `url` | Checked before the browser is involved, then on every hop. Returns `http_status`, `title`, `redirect_chain`, `content_hash` (`decoded_body_bytes`), `challenge`. A failed navigation may add a `net_error` token (see [Failed navigations](#failed-navigations)). |
| `browser.snapshot` | — | `title`, visible `text` (≤ 20,000 chars), `elements[]` (≤ 200) with `index`, `tag`, `role`, `type`, `name`, `href`, `disabled`, `in_viewport`, `editable`, `submits_form`; `untrusted_content: true`; `content_hash` (`rendered_dom_utf8`). |
| `browser.click` | `index` | Index from the latest snapshot. Refuses form submission (unless the host is opted in) and file inputs. Reports `navigated`. |
| `browser.type` | `index`, `text` (≤ 2,000) | Replaces the field's text without pressing Enter. Refuses password fields, `autocomplete` credential, one-time-code and payment (`cc-*`) fields, and non-text inputs. The text is never echoed or logged. |
| `browser.scroll` | `direction`, `pixels` or `index` | Returns the scroll position. |
| `browser.screenshot` | `full_page` | PNG as MCP image content, password fields masked, ≤ 5 MiB; `content_hash` (`screenshot_png_bytes`). |
| `browser.pause_for_human` | — | Pauses the session as for a detected challenge. |
| `browser.resume_session` | `host_event_ref` | Resumes only on an accepted trusted host event (see §6). |
| `browser.close_session` | — | Releases everything. |

Every result has `status`, `request_id`, `session_id`, `session_state` (`ACTIVE`, `BLOCKED` or `CLOSED`), `warnings`, `blocked_requests` and `failed_requests` (see [Request diagnostics](#request-diagnostics)) and, unless the status is `success`, `error {code, message, retryable}`. The status values are those of [02 · Tool Contracts](02-tool-contracts.md).

### Page content is untrusted

Text, element names, titles and screenshots are data from the web. Results carry `untrusted_content: true` and a notice. Element names come from ARIA labels, `<label>`s and visible text, never from a form field's value, and are capped at 160 characters. Only the main frame is read: elements inside iframes and shadow roots are not indexed.

### URL privacy

Every URL in a browser result (`url`, `redirect_chain`, link `href`s) follows the same disclosure rule as fetch results: the origin only, unless the host is listed in `RESEARCH_BROWSER_FULL_URL_HOSTS`. `blocked_requests`, `failed_requests`, proxy events, audit logs, handoff records and evidence records are always origin-only. `net_error` holds no URL at all.

### Request diagnostics

Every result reports the session's network problems since the previous result of the same session, background requests between actions included. `browser.open_session` and a result for an unknown session have both arrays empty. While a session is paused (§5), results carry both arrays empty: what the page, or a person in a visible window, requests during the pause is not reported to the caller. Such entries are dropped, and the warning `request_diagnostics_suppressed_while_paused` says so; the audit log still has them.

| Field | Entry | Contains |
|---|---|---|
| `blocked_requests` | `{origin, code}` | Requests refused by policy: by the in-browser check (URL policy, allowlist, method rule, WebSockets) or by the proxy (a `deny` event, see below). `code` is the policy code, e.g. `host_not_allowlisted`, `method_not_allowed`, `address_private`. |
| `failed_requests` | `{origin, resource_type, status?, error_text?}` | Requests that failed in Chromium or got an HTTP status ≥ 400. `resource_type` is Playwright's (`document`, `script`, `fetch`, `image`, …). Each entry has either `status` (a response ≥ 400) or `error_text` (no response: a `net::ERR_*` token, or `request_failed` when Chromium gave none). The main frame's own navigation response is not listed; `browser.navigate` returns it as `http_status`. |

- **At most 20 per list.** `failed_requests` keeps the newest 20. `blocked_requests` lists in-browser refusals first, then proxy denials, and keeps the last 20.
- **Reported once.** An entry appears in one result only. Entries beyond the 20 are dropped, not carried over.
- **`request_diagnostics_truncated`** is added to `warnings` when more than 20 entries were new for either list. The session keeps the newest 50 in-browser refusals and 50 failed requests, and the proxy the newest 50 denials and 50 errors (separately, so errors never push a denial out); losing an unreported entry therefore always means more than 20 were new. `requests_blocked_by_policy` is added whenever `blocked_requests` had new entries.
- **In-browser refusals are not also failures.** A request the in-browser check aborts is listed in `blocked_requests` only, not also in `failed_requests` (as `net::ERR_BLOCKED_BY_CLIENT`). The failure listener recognises these by applying the same check again to the URL and method, which also holds under a flood of requests. A request the *proxy* refuses can be in both: as the denial, and as Chromium saw it (an HTTP status such as `403` over plain HTTP, an error token such as `net::ERR_TUNNEL_CONNECTION_FAILED` over HTTPS).
- **Origins are bounded.** A host name longer than DNS allows (253 characters) is shown as `[invalid-host]`.

### Failed navigations

When Chromium cannot load the page, `error.code` comes from the navigation's **own** requests: the requested origin, plus the origin of every main-frame navigation request that failed during the navigation. That is how a redirect target is seen, because the in-browser check does not see redirect hops. Iframes and other requests of the previous page are not own requests. The first rule that matches wins:

| # | Condition | `status` | `error.code` |
|---|---|---|---|
| 1 | A proxy denial for an own origin (only the proxy can refuse a navigation hop) | `policy_denied` | the denial's code |
| 2 | Chromium's error is a certificate or TLS error (`net::ERR_CERT_*`, `net::ERR_CERTIFICATE_*`, `net::ERR_SSL_*`, `net::ERR_BAD_SSL_*`, `net::ERR_TLS13_DOWNGRADE_DETECTED`, `net::ERR_ECH_FALLBACK_CERTIFICATE_INVALID`) | `policy_denied` | `tls_verification_failed` |
| 3 | A proxy error for an own origin before a connection existed | `provider_unavailable` (`timeout` for `dns_timeout` and `connect_timeout`) | `dns_resolution_failed`, `dns_no_answer`, `dns_timeout`, `connection_failed` or `connect_timeout` |
| 4 | The navigation timeout | `timeout` | `navigation_timeout` |
| 5 | `net::ERR_ABORTED` or a download, which is refused | `blocked` | `navigation_aborted` |
| 6 | A proxy `upstream_error` for an own origin | `provider_unavailable` | `upstream_error` |
| 7 | Any other `net::ERR_*` error | `provider_unavailable` | `navigation_failed` |
| 8 | No network error token, but a new policy denial of any origin | `policy_denied` | the denial's code |

Anything else is a generic browser error, such as `browser_closed`. When Chromium's error has a token, `net_error` is that token (`net::ERR_[A-Z0-9_]+`), never the message. It is read only where Playwright puts it, at the very start of the error message; a message that starts otherwise (for example one quoting the URLs of an interrupted navigation) gives no token, so words in a URL do not become `net_error` or decide a rule. Behind the proxy, Chromium usually reports an HTTPS tunnel that the proxy refused or could not open as `net::ERR_TUNNEL_CONNECTION_FAILED`, whatever the reason; `error.code` names the cause, `net_error` does not.

Over plain HTTP the proxy answers refusals and errors itself, so the navigation gets a response instead of an error. Such a response decides the result when it carries `x-research-browser-denial` (then `policy_denied`) or `x-research-browser-proxy-error` (then `provider_unavailable`, or `timeout` for `dns_timeout` and `connect_timeout`) with a plain code as its value. On plain HTTP these headers can only be the proxy's own, because the proxy removes both from every destination reply. There is no `net_error` in that case. An HTTPS response always comes from the destination, so its headers never decide the result, and a page's own error status (for example a 503 CAPTCHA page) goes to the challenge check as usual.

### Proxy events and audit log

Each session's proxy keeps its newest 50 denials and, separately, its newest 50 errors, each `{seq, origin, code, kind, at}`, and writes each one to the audit log. `seq` increases by one per event, across both kinds.

| `kind` | Codes | When | Reply to Chromium |
|---|---|---|---|
| `deny` | URL policy codes (`host_not_allowlisted`, `port_not_allowed`, …), `address_*` and `peer_*` (non-public DNS answer or peer), `method_not_allowed`, `session_byte_budget_exceeded`, `upgrade_not_allowed` | Before anything is sent to the destination | `403` (`400` for an invalid URL) with `x-research-browser-denial: <code>` |
| `deny` | `response_too_large` | A plain-HTTP response passed 10 MiB | The response is cut off |
| `error` | `dns_resolution_failed`, `dns_no_answer`, `connection_failed` | The name did not resolve or had no address, or the connect failed | `502`; on plain HTTP with `x-research-browser-proxy-error: <code>` (a CONNECT reply carries no header) |
| `error` | `dns_timeout` | The name did not resolve within the connect budget (5 s for resolution and connect together); an answer that arrives later is dropped and never connected to | `504`; on plain HTTP with `x-research-browser-proxy-error: dns_timeout` |
| `error` | `connect_timeout` | No connection within what is left of that 5 s budget | `504`; on plain HTTP with `x-research-browser-proxy-error: connect_timeout` |
| `error` | `upstream_error` | The destination reset or dropped an admitted connection before the response ended (plain HTTP), or before it sent any byte (tunnel). Once per connection; not for a normal close, an idle timeout, the byte limits, the session byte budget or proxy shutdown. Inside a tunnel a reset after the destination has sent data cannot be told from a normal end, so it is not recorded. | `502` with `x-research-browser-proxy-error: upstream_error` (plain HTTP) if no response had started, otherwise the connection is closed |

Only denials carry `x-research-browser-denial`, and only proxy errors carry `x-research-browser-proxy-error`, so a proxy error is never read as a policy refusal. On plain HTTP the proxy removes both headers from destination responses. Over HTTPS the proxy cannot see or change the destination's headers, which is why only plain-HTTP replies are ever read for them.

Audit log lines are JSON objects on stderr, each with `ts` and `tool_version`. The network ones:

| `event` | Fields |
|---|---|
| `egress` | Denial or error: `decision` and `kind` (`deny` or `error`), `origin`, `code`. Allowed connection: `decision: "allow"`, `transport` (`http` or `tunnel`), `origin`, `peer` (the connected IP address). No session id. |
| `browser_request_blocked` | `session_id`, `origin`, `code` |
| `browser_request_failed` | `session_id`, `origin`, `resource_type`, and `status` or `error_text` |
| `browser_action` | `session_id`, `action`, `request_id`, `status`, `code` (on errors), the page's `origin`, `duration_ms` |
The audit log has every entry, even when a result's lists were truncated. **None of these diagnostics, in results, proxy events or logs, contains a path, query, fragment, header, cookie, request or response body, or typed text.** Test T6 in `tests/browser-diagnostics.test.ts` and the P4 tests in `tests/egress-proxy.test.ts` put marker values in those places and check that none reaches a result or log line.

### Diagnosing a failed page

| Cause | What shows it |
|---|---|
| Policy refusal | `policy_denied` with a policy code; an entry in `blocked_requests`; a `browser_request_blocked` line or an `egress` line with `decision: "deny"`. The fix is the configuration, not a retry. |
| DNS or connection problem | `error.code` `dns_resolution_failed`, `dns_no_answer`, `dns_timeout`, `connection_failed` or `connect_timeout`; an `egress` line with `decision: "error"` for that origin; no denial. For subresources, `failed_requests` shows `status` `502`/`504` over plain HTTP, or a `net::ERR_*` token over HTTPS. Over HTTPS a refusal looks the same to Chromium; `blocked_requests` and the `egress` line tell them apart. |
| Connection dropped by the destination | `upstream_error` as `error.code` or in an `egress` line. Over HTTPS only a drop before the destination sent anything is visible. |
| TLS failure | `policy_denied` / `tls_verification_failed`, with a `net_error` such as `net::ERR_CERT_AUTHORITY_INVALID`. The proxy does not see TLS; it logs the tunnel as allowed. |
| HTTP error from the destination | `browser.navigate` succeeds with `http_status` ≥ 400 (a challenge page, such as 401, 403, 429, 451 or a CAPTCHA, pauses the session instead, see the next row); failing subresources are in `failed_requests` with `status`. Over plain HTTP, a `502` or `504` carrying `x-research-browser-proxy-error` came from the proxy, not the destination. |
| Site-side challenge | `human_verification_required`, `rate_limited` or `blocked` with `challenge` and `handoff`, `session_state` `BLOCKED` and a `browser_blocked` log line (see §5). This is the site's answer, not a network failure. |

## 5. Challenge detection and pause

After every action (and before a snapshot or screenshot is returned) the page is classified with the same `classifyChallenge` the fetcher uses, from the main document's HTTP status and `Retry-After`, the title, the first 20,000 characters of the serialised DOM, and the `src` of iframes and scripts (where CAPTCHA widgets usually live).

If the result is anything but `none`:

1. The session becomes `BLOCKED` and its element indexes are dropped.
2. A handoff is recorded in the same `HandoffStore` as `research.pause_for_human`, with the session id as `task_id`. The resume handle stays on the server.
3. When evidence is enabled, a screenshot and the DOM are persisted for the person reviewing the pause. They are **not** returned to the caller.
4. The result has `status` `human_verification_required` (CAPTCHA, login, unknown), `rate_limited` (429, with `retry_after_seconds`) or `blocked` (403/451 access block), the `challenge`, and a `handoff` with `pause_id`, `task_id`, `reason`, `expires_at`, the origin, human instructions and what kind of takeover is possible.

While a session is `BLOCKED`, every action, including `snapshot` and `screenshot`, answers `human_verification_required` / `session_paused`. Only `browser.resume_session` and `browser.close_session` are accepted.

## 6. Human takeover and resume

- **Headless (default).** No one can act inside the browser. The person decides through the host application: verify and continue, choose another source, or cancel.
- **Headed (`RESEARCH_BROWSER_HEADED=1`, needs a display).** The browser window is visible on the server's display, and a person may use it while the session is paused. The person's traffic goes through the same proxy, so the allowlist and the method rule still apply. In particular, CAPTCHA widgets usually load from third-party hosts (for example `challenges.cloudflare.com`, `www.google.com`, `hcaptcha.com`) and post their answers. Unless the operator lists those hosts in `RESEARCH_BROWSER_ALLOWED_HOSTS` (and, for posts, `RESEARCH_BROWSER_FORM_SUBMIT_HOSTS`), the person cannot complete them in this window. That is a deliberate default, not a bug.

`browser.resume_session` takes only a `host_event_ref`. The server looks up the session's resume handle and calls `HandoffStore.resume`, so every rule of [05 · Human Verification](05-human-verification-resume.md) applies: without a host-configured `HostEventVerifier` the session stays `BLOCKED`. With one, the event must match the session (`task_id`), the pause, and the full URL of the challenged page, be inside its time window and carry the current versions. Then:

| Event decision | Session |
|---|---|
| `verified_and_continue` | `ACTIVE`, then the page is checked again; if it still shows a challenge, a new pause is recorded. |
| `choose_alternate_source` | `ACTIVE` on `about:blank`. |
| `cancel` | Closed. |
| rejected event | Stays `BLOCKED`; the pause is not consumed. |

The shipped server does not configure a verifier (there is no trusted channel to configure from the environment). An integrator passes one to `HandoffStore` when building the server.

## 7. Evidence

With `RESEARCH_BROWSER_EVIDENCE_DIR` set, navigation persists the main document's body as decoded by Chromium (`decoded_body_bytes`), `snapshot` persists the serialised DOM (`rendered_dom_utf8`), `screenshot` persists the PNG (`screenshot_png_bytes`), and a pause persists the challenge page's screenshot and DOM. Each result lists its evidence with `content_hash`, `evidence_status` (`disabled`, `persisted`, `failed`), `evidence_persisted` and `evidence_id`. See [04 · Evidence](04-evidence-and-provenance.md).

## 8. Configuration

| Variable | Default | Meaning |
|---|---|---|
| `RESEARCH_BROWSER_ENABLE_BROWSER` | off | `1`/`true` registers the `browser.*` tools. Anything other than `1`, `true`, `0`, `false` or empty stops startup. |
| `RESEARCH_BROWSER_HEADED` | off | Shows the browser window (needs a display). |
| `RESEARCH_BROWSER_CHROMIUM_PATH` | Playwright's build | Absolute path of a Chromium to use instead. |
| `RESEARCH_BROWSER_CHROMIUM_SANDBOX` | off | Turns on Chromium's own sandbox. Needs unprivileged user namespaces or a setuid helper on the host. |
| `RESEARCH_BROWSER_FORM_SUBMIT_HOSTS` | empty | Exact hosts where forms may be submitted and non-GET requests sent. Same entry rules as the allowlist. |
| `RESEARCH_BROWSER_ALLOWED_HOSTS`, `RESEARCH_BROWSER_FULL_URL_HOSTS`, `RESEARCH_BROWSER_EVIDENCE_DIR` | | Shared with the fetcher; see the README. |

Chromium must match the pinned `playwright-core` (1.56.1, Chromium 141): `npx playwright-core install chromium-headless-shell` (headless) or `chromium` (headed).

## 9. Known limits

- **Page JavaScript runs.** That is the point of the browser, and it means a Chromium vulnerability is reachable from any allowlisted page. Chromium's sandbox is off by default (Playwright's default; it needs host support). Run the server in a container or VM with deployment-level egress controls, and turn on `RESEARCH_BROWSER_CHROMIUM_SANDBOX` where the host allows it.
- **Challenge detection is a heuristic.** It looks for known markers and statuses. A challenge that is drawn without them can be missed, and an article about CAPTCHAs on an error page can be flagged.
- **`GET` can still change state** on badly designed sites. The method rule blocks form posts and `fetch` writes, not every side effect.
- **Redirected posts on opted-in hosts.** The in-browser check does not see redirect hops, and the proxy cannot see methods inside HTTPS. So when `RESEARCH_BROWSER_FORM_SUBMIT_HOSTS` lists a host, a POST to that host that it answers with a 307 or 308 redirect is re-sent, with its body, to the redirect target, even if the target is not opted in (the target must still be allowlisted). With the default empty list the first POST is already refused.
- **Log volume.** Every refused or failed request is one audit log line, and a page can make thousands per second, also while its session is paused (until the session's lifetime limit). Memory stays bounded; the log does not.
- **Request origins are chosen by the page.** `blocked_requests` and `failed_requests` show origins of requests the page made, so a page can put words of its choice into host names there. Treat them as untrusted data, like page content.
- **No local DNS check for Chromium.** With a fixed proxy Chromium sends host names to the proxy, and the tests run in a loopback-only network namespace, but there is no test that proves Chromium makes no DNS query of its own (for example for prefetching).
- **Headed mode is not covered by the automated tests** (CI has no display).
- **Not indexed:** elements inside iframes and shadow roots; elements beyond the first 200.
- Only a host-supplied verifier can resume a paused session; see §6.
