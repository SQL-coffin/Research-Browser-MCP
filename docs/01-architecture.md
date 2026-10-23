# 01 · Architecture

Version: v0.1 draft

## 1. Purpose

Research Browser MCP is a standalone service for bounded, read-only retrieval of public web research. It exposes a provider-neutral MCP tool surface. It is not an autonomous agent runtime and does not own a consumer's task orchestration, approval store, memory policy, or business-specific decisions.

## 2. Context

```text
MCP Client / Agent Runtime
        |  policy-checked tool call
        v
Research Browser MCP Server
  +-- Request Validator
  +-- Provider Registry
  +-- Search Adapter (optional)
  +-- Public Page Fetcher
  +-- Browser Agent (optional) --> Egress Proxy (same policy as the fetcher)
  +-- Challenge Classifier
  +-- Result Normalizer
  +-- Evidence Metadata Writer
        |
        v
Public Search APIs / Public Web Pages
```

The host runtime enforces its own tool registry, mode restrictions, data-scope controls, egress policy, budgets, event log, trusted human feedback, and task state. The MCP server independently validates requests and enforces network safety. Neither layer assumes the other makes validation unnecessary.

## 3. Module responsibilities

| Component | Responsibility | Must not do |
|---|---|---|
| Request Validator | Validate schema, limits, provider IDs, URL policy | Trust model-generated values blindly |
| Provider Registry | Resolve explicitly configured providers and versions | Discover or enable arbitrary providers at runtime |
| Search Adapter | Query an approved search provider | Send protected user/case data |
| Public Page Fetcher | Retrieve bounded public HTML/text | Execute page scripts, submit forms, reuse sessions |
| Browser Agent (optional) | Isolated Chromium sessions on allowlisted hosts; indexed snapshots and bounded actions; pause on challenges | Solve or bypass challenges, share state between sessions, submit forms on hosts not opted in |
| Egress Proxy | The browser's only network route; applies the fetch policy to every request and tunnel | Terminate TLS, accept connections from anything but its own session |
| Challenge Classifier | Classify visible access challenges | Solve or bypass them |
| Result Normalizer | Convert provider results to stable envelopes | Treat page text as instructions |
| Evidence Store (optional) | Write the exact hashed bytes and an origin-only record, once | Overwrite, follow symlinks, store headers or cookies, claim persistence it did not verify |

## 4. Trust boundaries

1. Model/client to MCP server: every argument is untrusted.
2. MCP server to remote provider: outbound egress is explicit, bounded, and logged without secrets.
3. Remote content to client: all returned content is untrusted data.
4. MCP server to host runtime: a challenge can request a pause, but only the host's trusted event channel can authorize resume.

## 5. State ownership

The MCP service may maintain short-lived request state and, if explicitly configured, evidence metadata. The integrating runtime remains the authority for durable task states such as `BLOCKED(human_feedback)`, task checkpoints, trusted-human events, budgets, and resume idempotency. If the service implements its own durable task store, that store must have an explicit documented boundary and must not silently conflict with the host event log.

## 6. Modes and configuration

- Disabled by default until a provider and egress policy are explicitly configured.
- No runtime mode escalation from input arguments or returned page content.
- No hidden fallback to an unreviewed remote provider.
- Configuration should be validated on startup and reported in a redacted diagnostics view.

## 7. Failure model

Failures must be structured: invalid input, policy denied, provider unavailable, rate limited, content too large, challenge encountered, extraction failed, or evidence sink unavailable. Timeouts and unknown outcomes must not be reported as successful retrievals.

## 8. Deployment phases

Phase 0: architecture, threat model, schemas, acceptance tests.
Phase 1: local fixtures, request validation, normalization, public HTTP fetch.
Phase 2: evidence/provenance, safe challenge handoff, provider integration.
Phase 3: consumer integration tests and operational hardening.

Do not use real patient or otherwise protected data during early development or acceptance testing.

## 9. Browser agent

See [07 · Browser Agent](07-browser-agent.md). The browser does not get a separate network policy: its proxy and in-browser request checks use the fetch policy built from `RESEARCH_BROWSER_ALLOWED_HOSTS`. A challenge pauses the session through the same `HandoffStore` as `research.pause_for_human`; the host's trusted event channel remains the only way to resume.
