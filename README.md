# Research Browser MCP

An auditable, read-only research browsing service exposed through the Model Context Protocol (MCP).

## Status

**Phase 1 — bounded fetcher and handoff contract, local fixtures only.** Not yet production-ready; see "Known gaps" below.

Implemented:

- `src/index.ts` — MCP stdio server exposing the five `research.*` tools.
- `src/security.ts` — URL policy, IPv4/IPv6 special-purpose range filtering (including IPv4-mapped, NAT64, 6to4 and cloud metadata), redaction, challenge classification, declared-basis SHA-256.
- `src/fetcher.ts` — read-only fetch with per-hop validation: URL policy → validate **every** DNS answer → connect through a pinned `lookup` that only returns the validated IP (no second DNS query, so no rebinding window) → verify the kernel-reported peer address at `connect`, before any request or TLS bytes are sent → bounded wire bytes, decoded bytes (gzip/deflate/br bombs), redirects, loops, text and total time. TLS verification is always on; no proxy, cookies, or caller headers are used.
- `src/handoff.ts` — pause/resume contract. Without a host-configured `HostEventVerifier`, resume always defers to the host. With one, it checks task, pause, URL, expiry, version drift and idempotency.
- `src/search.ts` — provider allowlist from startup configuration only. No provider is enabled by default.

Development uses npm (`package-lock.json`) and Node.js 22:

```bash
npm ci
npm run typecheck   # strict tsc over src/ and tests/, no emit
npm test            # node:test against local HTTP/HTTPS fixtures; no third-party sites
npm run build && npm start
```

Known gaps:

- Address filtering in the process is not a substitute for deployment-level egress controls (network policy / firewall). It does not cover IPv6 extension or tunnelling formats beyond those listed in `security.ts`.
- The DNS-rebinding tests use an injected resolver and loopback fixtures. They have not been run in a controlled network sandbox with a real authoritative DNS server.
- No durable evidence sink: results report `evidence_persisted: false`. Handoff records are in memory only.
- No search provider is enabled. Robots.txt is not consulted yet.
- Text extraction is regex-based and is not a full HTML parser.

### Continuous integration

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every `pull_request`. It uses Ubuntu 24.04 and Node.js 22, has a read-only `contents: read` token, uses no secrets, and does not use `pull_request_target`. The steps are:

1. `npm ci` installs exactly what `package-lock.json` records.
2. `npm run typecheck` runs strict TypeScript over `src/` and `tests/`.
3. `npm test` runs the full suite inside a fresh network namespace that only has loopback, so a test that tries to reach a real host fails instead of passing. With `CI` set, the HTTPS tests, including the zero-byte ClientHello regression, cannot be skipped: a missing `openssl` fails the run.
4. `npm run build` compiles to `dist/`.

CI does not check the following:

- The built `dist/` server is never started; tests run the TypeScript sources through `tsx`.
- Node.js 20 is not tested, although `engines` still allows it.
- There is no lint or format step, dependency audit, or run on pushes to `main`.

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
