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
- **Limits per session:** 10 MiB per plain-HTTP response, 200 MiB relayed in total, 64 connections, 60 s idle per connection, 5 s connect timeout.

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
| `browser.navigate` | `url` | Checked before the browser is involved, then on every hop. Returns `http_status`, `title`, `redirect_chain`, `content_hash` (`decoded_body_bytes`), `blocked_requests`, `failed_requests`, `challenge`; navigation errors may include an origin-free `net_error` token such as `net::ERR_NAME_NOT_RESOLVED`. |
| `browser.snapshot` | — | `title`, visible `text` (≤ 20,000 chars), `elements[]` (≤ 200) with `index`, `tag`, `role`, `type`, `name`, `href`, `disabled`, `in_viewport`, `editable`, `submits_form`; `untrusted_content: true`; `content_hash` (`rendered_dom_utf8`); `blocked_requests` and `failed_requests`. |
| `browser.click` | `index` | Index from the latest snapshot. Refuses form submission (unless the host is opted in) and file inputs. Reports `navigated`. |
| `browser.type` | `index`, `text` (≤ 2,000) | Replaces the field's text without pressing Enter. Refuses password fields, `autocomplete` credential, one-time-code and payment (`cc-*`) fields, and non-text inputs. The text is never echoed or logged. |
| `browser.scroll` | `direction`, `pixels` or `index` | Returns the scroll position. |
| `browser.screenshot` | `full_page` | PNG as MCP image content, password fields masked, ≤ 5 MiB; `content_hash` (`screenshot_png_bytes`); `blocked_requests` and `failed_requests`. |
| `browser.pause_for_human` | — | Pauses the session as for a detected challenge. |
| `browser.resume_session` | `host_event_ref` | Resumes only on an accepted trusted host event (see §6). |
| `browser.close_session` | — | Releases everything. |

Every result has `status`, `request_id`, `session_id`, `session_state` (`ACTIVE`, `BLOCKED` or `CLOSED`), `warnings` and, unless the status is `success`, `error {code, message, retryable}`. The status values are those of [02 · Tool Contracts](02-tool-contracts.md).

### Page content is untrusted

Text, element names, titles and screenshots are data from the web. Results carry `untrusted_content: true` and a notice. Element names come from ARIA labels, `<label>`s and visible text, never from a form field's value, and are capped at 160 characters. Only the main frame is read: elements inside iframes and shadow roots are not indexed.

### URL privacy

Every browser tool result includes `blocked_requests` and `failed_requests` arrays (up to 20 new entries each, since the prior result). A blocked entry contains only `origin` and policy `code`. A failed-request entry contains only `origin`, `resource_type`, and either an HTTP `status` (≥ 400, for subresources) or a sanitized `error_text` token; Chromium errors are reduced to `net::ERR_*` names, never raw error strings. Proxy DNS/connection errors are retained as origin-only diagnostic events, so navigation errors can report the underlying proxy code instead of only `navigation_failed`. Audit logs use the same origin-only fields and never include paths, query strings, headers, cookies, request bodies, or typed text.

Every URL in a browser result (`url`, `redirect_chain`, link `href`s) follows the same disclosure rule as fetch results: the origin only, unless the host is listed in `RESEARCH_BROWSER_FULL_URL_HOSTS`. `blocked_requests`, `failed_requests`, audit logs, handoff records and evidence records are always origin-only.

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
- **No local DNS check for Chromium.** With a fixed proxy Chromium sends host names to the proxy, and the tests run in a loopback-only network namespace, but there is no test that proves Chromium makes no DNS query of its own (for example for prefetching).
- **Headed mode is not covered by the automated tests** (CI has no display).
- **Not indexed:** elements inside iframes and shadow roots; elements beyond the first 200.
- Only a host-supplied verifier can resume a paused session; see §6.
