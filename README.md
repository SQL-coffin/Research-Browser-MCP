# Research Browser MCP

An auditable, read-only research browsing service exposed through the Model Context Protocol (MCP).

## Status

**Phase 0 — design-first.** This repository is currently an architecture/specification starting point. A document in this repository does not imply that a browser adapter, provider, or safety control has already been implemented.

## Goals

- Search and retrieve public research sources with provenance and timestamps.
- Normalize provider results behind a stable tool contract.
- Keep the MCP server separate from any consuming agent runtime; callers remain responsible for their own orchestration and policy enforcement.
- Preserve source evidence and derived observations separately.
- Pause and resume work through a trusted human-verification handoff when a site presents a CAPTCHA, login wall, rate limit, or policy challenge.
- Make failures, budgets, versions, and external data egress visible and testable.

## Non-goals for the MVP

- Accessing private pages or bypassing authentication, CAPTCHA, rate limits, robots rules, or other access controls.
- Running arbitrary page JavaScript, submitting forms, or performing actions that modify a remote website.
- Receiving patient records, credentials, cookies, browser profiles, or unrelated protected data.
- Claiming that an agent's text message is proof that human verification happened.

## Proposed tool surface

The exact schema is to be finalized alongside acceptance tests. The initial candidate tool set is:

- `research.search` — search public sources through an explicitly configured provider.
- `research.fetch_public_page` — retrieve and extract bounded public HTML/text.
- `research.inspect_challenge` — classify observable access challenges without bypassing them.
- `research.pause_for_human` — persist a blocked task and provide a human handoff.
- `research.resume` — continue only after a trusted human-feedback event is recorded by the integrating runtime.

The server must not treat MCP itself as a security boundary. The client/runtime is responsible for registering tools only in allowed modes, controlling data scopes and egress, and enforcing its Policy Gate. The server must still independently validate requests and protect its network boundary.

## Design principles

1. **Read-only by default.** No remote side effects in the MVP.
2. **Public sources only.** Respect access controls and site policies.
3. **Evidence before summaries.** Store immutable source evidence; derived summaries reference the evidence from which they were produced.
4. **Human verification, not CAPTCHA bypass.** Challenges pause the workflow. Resume is bound to a task and URL and requires trusted feedback from the host runtime.
5. **Bounded network access.** Defend against SSRF, DNS rebinding, unsafe redirects, oversized bodies, decompression bombs, and secret leakage.
6. **Untrusted page content.** Web content is data, never a tool instruction or policy override.
7. **Provider isolation.** External providers are opt-in and have explicit egress, retention, licensing, dependency, and cost reviews.
8. **Test before integration.** Security and resume behavior must be tested against local fixtures before connecting to external sites or consuming runtimes.

## Suggested implementation sequence

1. Agree on architecture, threat model, data model, and public tool schemas.
2. Write contract and security tests using local HTTP fixtures.
3. Implement provider-neutral request/response models and result normalization.
4. Implement bounded public HTTP retrieval and source evidence recording.
5. Implement structured challenge detection and a host-runtime human handoff/resume contract.
6. Add optional search providers after egress and retention review.
7. Integrate with consuming runtimes through MCP configuration; do not embed a consuming application's business logic here.

## Documents

- [Architecture](docs/01-architecture.md)
- [Tool contracts](docs/02-tool-contracts.md)
- [Security and threat model](docs/03-security-threat-model.md)
- [Evidence and provenance](docs/04-evidence-and-provenance.md)
- [Human verification and resume protocol](docs/05-human-verification-resume.md)
- [Acceptance tests](docs/06-acceptance-tests.md)

## License

Not yet specified. Add a license before distributing or accepting contributions.
