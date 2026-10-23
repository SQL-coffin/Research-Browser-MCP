# 03 · Security and Threat Model

Version: v0.1 draft

## 1. Protected assets

- Host credentials and provider API keys.
- Local network services, cloud metadata endpoints, and internal administration interfaces.
- Consumer data, including patient records and private case information.
- Evidence provenance, hashes, source URLs, timestamps, and audit metadata.
- Host task state, policy configuration, budgets, and trusted-human verification events.

## 2. Threat actors and failure sources

- Malicious or compromised websites.
- Prompt-injection content embedded in pages, titles, snippets, metadata, or redirects.
- Malicious URLs crafted to target internal addresses or parser weaknesses.
- Untrusted MCP clients sending malformed, oversized, or policy-violating parameters.
- Misconfigured or compromised third-party search providers.
- Accidental secret leakage through logs or outbound requests.

## 3. Required controls

### SSRF and destination control

- Allow only explicitly supported HTTP(S) schemes; default to HTTPS and port 443.
- Reject user-info credentials in URLs.
- Resolve and validate every destination IP. Block loopback, private, link-local, multicast, reserved, unspecified, and cloud metadata ranges for IPv4 and IPv6.
- Re-check DNS answers and actual connected peer address to limit DNS-rebinding and time-of-check/time-of-use issues.
- Revalidate each redirect target before connecting; bound redirect count and detect loops.
- Do not inherit proxy settings or route policies in a way that silently bypasses destination validation.

### Payload and parser limits

- Apply connect and read deadlines.
- Bound wire bytes, decompressed bytes, redirects, content types, and extracted text.
- Reject unsupported binary formats by default.
- Treat parser errors and invalid encodings as failures, never partial success without a warning.

### Credentials and data egress

- Never forward browser cookies, host authentication, Authorization headers, or ambient credentials.
- Redact sensitive query parameters and headers from logs.
- Search queries must not contain protected case or patient data; consumer runtime should enforce data-scope checks before tool invocation.
- Third-party providers remain disabled until the provider's recipient, retention, license, and cost have been reviewed.

### Prompt injection

- Page content, titles, snippets, metadata, and tool errors are untrusted data.
- No page content can register tools, change policy, expand permissions, change budgets, select a hidden provider, or prove an approval.
- Return content in a clearly delimited data field and preserve source provenance.

### Challenge handling

- CAPTCHA, login walls, rate limits, robots restrictions, and policy blocks must not trigger automated circumvention.
- A challenge produces a typed result and a host-runtime handoff.
- Human resume authorization must come from a trusted host event channel and be bound to task and URL, not from model-generated prose.

## 4. Security testing

Use local fixtures and a controlled test network. Include tests for private IPv4/IPv6, DNS rebinding, unsafe redirects, URL credentials, oversized compressed bodies, timeouts, secret redaction, malicious page text, and challenge-state transitions.

## 5. Incident and failure behavior

On policy violation, stop the request and emit a sanitized audit result. Never silently downgrade to a less secure provider. On evidence-sink failure, report that persistence failed rather than claiming evidence was stored. Do not persist page content that contains a detected protected-data payload without an explicit approved retention policy.

## 6. Residual risks

Challenge classification may be wrong or ambiguous; provider snippets may be inaccurate; source content can change after retrieval; no network filter is sufficient without egress controls at the deployment boundary. These limits must be documented and included in acceptance testing.

## 7. Browser agent (optional)

Enabling the browser adds page JavaScript, a real browser engine and interactive actions. Additional threats and the controls in place (details in [07 · Browser Agent](07-browser-agent.md)):

| Threat | Control |
|---|---|
| Page script or subresource reaches an internal or unlisted address (SSRF from inside the page) | All browser traffic goes through a per-session loopback proxy with no loopback bypass; it applies the fetch policy (allowlist, every DNS answer, pinned connect, peer check) to every request and CONNECT tunnel. A request handler inside the browser re-checks every request URL first. |
| Redirect to an unlisted or private host | Each redirect is a new request through the proxy and is checked again. |
| Another local process or page content uses the proxy | The proxy listens on 127.0.0.1 only and requires per-proxy random credentials. |
| Remote side effects (form posts, `fetch` writes, beacons) | Only `GET`/`HEAD` unless the host is in `RESEARCH_BROWSER_FORM_SUBMIT_HOSTS`; enforced by the proxy for plain HTTP and by the in-browser handler inside HTTPS tunnels. Clicking a submit control is refused; typing never presses Enter. |
| Credential capture or entry | Typing into password, one-time-code and payment fields is refused; field values are never returned; password fields are masked in screenshots; typed text is never logged. |
| State leaking between tasks | One Chromium process, fresh in-memory context and proxy per session; nothing persisted; everything released on close, timeout, crash or shutdown. |
| Side channels around the proxy | WebSockets, service workers, downloads, QUIC and non-proxied WebRTC UDP are off; popups are closed; dialogs dismissed. |
| CAPTCHA or access control circumvention | The page is classified after every action; any challenge pauses the session and no content, snapshot or screenshot is served until a trusted host event resumes it. No solving, fingerprint spoofing, stealth or identity rotation exists in the code. |
| Prompt injection through page content | Snapshots and screenshots are marked untrusted; element names never include field values and are length-bounded; tool arguments cannot change policy. |
| Resource exhaustion | Session count, idle and total lifetime limits, per-action and per-navigation timeouts, a hard deadline that closes a frozen session, per-response and per-session byte limits, bounded text, element and screenshot sizes. |

Residual risks specific to the browser: a Chromium vulnerability reachable from an allowlisted page (the Chromium sandbox is off unless `RESEARCH_BROWSER_CHROMIUM_SANDBOX` is set, so run the service in a container or VM); heuristic challenge detection; side effects of `GET` requests; and the absence of a test proving that Chromium performs no DNS query of its own.
