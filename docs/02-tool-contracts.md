# 02 · Tool Contracts

Version: v0.1 draft

Tool names are provisional until schema tests are agreed. Each tool returns structured data and never returns instructions that override the caller's policy.

## 1. Common rules

- All inputs are schema-validated and bounded.
- Provider names must come from startup configuration; caller input cannot register a provider.
- Each invocation should emit a correlation ID, tool version, provider/version, duration, outcome, and sanitized error metadata.
- Never log authorization headers, API keys, cookies, credentials, or full secret-bearing URLs.
- Web output is untrusted content, not executable instructions.
- No tool accepts patient identifiers or records in the MVP contract.

## 2. `research.search`

Input:

| Field | Rule |
|---|---|
| `query` | Required string; bounded length; reject obvious credential or patient-record payloads where detectable |
| `limit` | Optional integer, 1–10; default configured by server |
| `provider` | Optional ID from enabled provider allowlist |

Output: `status`, `results[]`, `provider`, `provider_version`, `retrieved_at`, `warnings`, `request_id`. Each result includes `title`, `url`, `snippet` (if supplied by provider), and source metadata. Search snippets are leads, not independently verified evidence.

## 3. `research.fetch_public_page`

Input: `url` and optional bounded extraction settings allowed by server policy. Callers cannot override network safety controls.

Output: `status`, `source_url`, `final_url`, `title`, `retrieved_at`, `content_type`, `http_status`, `extracted_text`, `content_hash`, `redirect_chain`, `warnings`, `challenge_type`, `request_id`, `evidence_status` (`disabled`, `persisted`, `failed`), `evidence_persisted` (true only after the stored bytes were read back with the declared hash), and `evidence_id` or `evidence_error`.

Rules: HTTPS by default; strict destination-IP validation; bounded redirects, timeouts, response bytes, decompressed bytes, and extracted characters; no JavaScript, forms, credential forwarding, browser sessions, or automatic arbitrary file downloads.

## 4. `research.inspect_challenge`

Input: a fetch-result reference or bounded observation summary; never a credential or cookie.

Output `challenge_type`, `confidence`, `signals`, `source_url`, and `recommended_action`. Supported categories: `none`, `captcha`, `login_required`, `rate_limited`, `robots_or_policy_block`, `unknown`. Detection is advisory and must not trigger bypass attempts.

## 5. Human handoff contract

`research.pause_for_human` accepts a task reference, source URL, reason, completed-step summary, and next-step description. It returns `human_verification_required`, `task_id`, `source_url`, `reason`, and a resume handle. Do not include passwords, cookies, access tokens, CAPTCHA answers, or browser-profile data.

`research.resume` accepts a resume handle and a reference to a trusted host-runtime human-feedback event. The service cannot manufacture or infer proof of human verification. The host runtime must verify event trust, task ID, URL, expiry, policy version, tool version, and idempotency before allowing execution to continue. When the MCP service cannot validate the host event itself, it must treat the event reference as an untrusted claim and leave authorization to the host.

An MCP service can expose the handoff protocol, but durable `BLOCKED` state and trusted human-event validation should remain with the consuming runtime unless an explicit shared state protocol is adopted.

## 6. Shared status vocabulary

- `success`
- `invalid_input`
- `policy_denied`
- `human_verification_required`
- `blocked`
- `rate_limited`
- `provider_unavailable`
- `timeout`
- `content_too_large`
- `extraction_failed`
- `evidence_unavailable`
- `internal_error`

Any non-success status must include a stable error code, a safe message, and a retryable flag. `retryable` never overrides caller budgets or site policy.

## 7. Browser tools (optional)

Registered only when `RESEARCH_BROWSER_ENABLE_BROWSER` is on: `browser.open_session`, `browser.navigate`, `browser.snapshot`, `browser.click`, `browser.type`, `browser.scroll`, `browser.screenshot`, `browser.pause_for_human`, `browser.resume_session`, `browser.close_session`. Inputs are a session UUID plus bounded action arguments (`url`, element `index`, `text` ≤ 2,000 characters, scroll `direction`/`pixels`, `full_page`, `host_event_ref`); none can change hosts, methods, headers, cookies, timeouts or any other policy. Every result has `status`, `request_id`, `session_id`, `session_state`, `warnings` and, on failure, `error`. A page showing a challenge returns a pause with a `handoff` instead of content. Details and fields: [07 · Browser Agent](07-browser-agent.md).
