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
