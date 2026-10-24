# Research Browser MCP

An auditable research browsing service exposed through the Model Context Protocol (MCP): a bounded read-only fetcher, and an optional browser agent for pages that need JavaScript. Both use one network policy.

## Status

**An MVP for personal use.** It is a bounded fetcher, an optional browser agent (off by default), an optional evidence store (off by default) and a human-handoff contract, tested against local fixtures only. It is not a production crawler, and neither these notes nor the tests are the result of a completed security audit; see "Known gaps" below.

Implemented:

- `src/index.ts` — MCP stdio server exposing the five `research.*` tools, and the ten `browser.*` tools when the browser is enabled. It reads all configuration from the environment at startup (see [Configuration](#configuration)).
- `src/security.ts` — URL policy, the startup **host allowlist** (exact hosts only), URL disclosure for results, and a destination-address **allowlist**. An address passes only if it is global unicast (IPv4 below `224.0.0.0`, IPv6 inside `2000::/3`) and outside every special-purpose block (private, loopback, link-local, NAT64, 6to4, Teredo, documentation, cloud metadata, …). Anything else, e.g. `4000::1`, is denied as `not_global_unicast`. One policy function judges IP-literal URLs, every DNS answer and the connected peer, always on the canonical address spelling. Also redaction, challenge classification, declared-basis SHA-256.
- `src/fetcher.ts` — read-only fetch with per-hop validation. Every hop, including every redirect, runs:
  - the URL policy: scheme, port, credentials, public name or address, and host allowlist;
  - validation of **every** DNS answer;
  - a connect through a pinned `lookup` that only returns the validated IP, so there is no second DNS query and no rebinding window;
  - a check of the kernel-reported peer address at `connect`, before any request or TLS bytes are sent;
  - bounds on wire bytes, decoded bytes (gzip/deflate/br bombs), redirects, loops, text and total time.

  TLS verification is always on; no proxy, cookies, or caller headers are used.
- `src/handoff.ts` — pause/resume contract. Without a host-configured `HostEventVerifier`, resume always defers to the host. With one, it checks:
  - task, pause and URL binding;
  - the event's time order: RFC 3339 timestamps with an explicit offset, and pause time ≤ `issued_at` ≤ now < `expires_at`;
  - version drift;
  - idempotency.

  Any rejection leaves the task `BLOCKED` and the pause unconsumed. Pause records never keep the raw URL. They keep its origin and an HMAC of the canonical URL; event URLs are compared against that HMAC.
- `src/evidence.ts` — optional content-addressed evidence store (see [Evidence](#evidence)). Off by default.
- `src/egress-proxy.ts` and `src/browser/` — the browser agent: one Chromium process (Playwright) per session, isolated in-memory storage, and a loopback proxy that applies the fetch policy (allowlist, every DNS answer, pinned connect, peer check) to every request the browser makes. Indexed page snapshots, navigate/click/type/scroll/screenshot, CAPTCHA and access-limit detection that pauses the session, and resume only through a trusted host event. Off by default; see [Browser agent](docs/07-browser-agent.md).
- `src/search.ts` — a provider registry fixed when the server is constructed; tool input cannot add a provider. The shipped server registers none and has no setting to enable one, so `research.search` answers `provider_unavailable`.

### Configuration

The server is configured only through its environment at startup; tool calls cannot change any of it.

Both variables take a list of **exact** hosts, separated by commas or whitespace:

| Entry | Matches |
|---|---|
| `example.org` | Exactly `example.org`, compared after normalization: lower case, one trailing dot removed, IDN converted to Punycode (`bücher.example` is `xn--bcher-kva.example`). Not `www.example.org` or any other subdomain, and not the parent domain. |
| `93.184.215.14`, `2606:4700::1111` or `[2606:4700::1111]` | Exactly that IP address, in any spelling. |

**Wildcards are not supported.** `*.example.org`, `*.co.uk`, `*` and every other form containing `*` are rejected. List each host you need by name, `www.` variants included.

If any entry has a wildcard, scheme, port, path, credentials or an invalid name, the server refuses to start. The error names the variable and the entry's position, not its text.

**`RESEARCH_BROWSER_ALLOWED_HOSTS`** lists the hosts `research.fetch_public_page` may fetch.

- **Unset or empty means every fetch is denied** with `host_allowlist_empty`, and the server says so on stderr at startup.
- The allowlist only narrows the other checks. A listed host still needs HTTPS on port 443, a public DNS name, and a public address for every DNS answer and for the connected peer.
- Every redirect hop is checked again, so a redirect to an unlisted host is refused before it is resolved.

**`RESEARCH_BROWSER_FULL_URL_HOSTS`** (optional) lists the trusted research hosts whose URLs `fetch_public_page` and browser results may show with path and query. See [URL privacy](#url-privacy).

- It only changes what results show. It does not add hosts to the allowlist, and it does not change address checks, TLS, redirects or any other network behaviour.

The browser and evidence settings are optional and off by default:

| Variable | Default | Meaning |
|---|---|---|
| `RESEARCH_BROWSER_ENABLE_BROWSER` | off | `1`/`true` registers the `browser.*` tools. The browser reaches exactly the hosts in `RESEARCH_BROWSER_ALLOWED_HOSTS`, under the same checks as the fetcher. |
| `RESEARCH_BROWSER_HEADED` | off | Shows the browser window on the server's display, so a person can look at a paused page. |
| `RESEARCH_BROWSER_FORM_SUBMIT_HOSTS` | empty | Exact hosts where the browser may submit forms or send non-GET requests. Empty: nowhere. |
| `RESEARCH_BROWSER_CHROMIUM_PATH` | Playwright's build | Absolute path of a Chromium to use instead. |
| `RESEARCH_BROWSER_CHROMIUM_SANDBOX` | off | Turns on Chromium's sandbox (needs host support). |
| `RESEARCH_BROWSER_EVIDENCE_DIR` | off | Absolute directory for the evidence store. |

A flag other than `1`, `true`, `0`, `false` or empty, a relative path, or an invalid host entry stops the server at startup.

Example MCP client configuration:

```json
{
  "mcpServers": {
    "research-browser": {
      "command": "node",
      "args": ["/path/to/Research-Browser-MCP/dist/index.js"],
      "env": {
        "RESEARCH_BROWSER_ALLOWED_HOSTS": "en.wikipedia.org, arxiv.org, export.arxiv.org, pubmed.ncbi.nlm.nih.gov",
        "RESEARCH_BROWSER_FULL_URL_HOSTS": "arxiv.org, pubmed.ncbi.nlm.nih.gov"
      }
    }
  }
}
```

### URL privacy

By default every URL the server outputs is shown as its **origin** only (e.g. `https://example.org`), with no path, query, fragment or credentials. This applies to:
- `source_url`, `final_url` and each `redirect_chain[].url` in `fetch_public_page` results;
- audit log lines on stderr;
- `inspect_challenge` reports;
- `pause_for_human` and `resume` outputs and the in-memory handoff records. Resume events are matched against an HMAC-SHA256 of the full canonical URL, never against the shown origin;
- every URL in `browser.*` results (page URL, redirect chain, link targets, blocked and failed requests) and the browser's handoffs;
- evidence records.

Results still carry `title`, `retrieved_at`, `content_hash` and `request_id`. The caller knows which URL it asked for, and `request_id` ties the result to that request.

For hosts listed in `RESEARCH_BROWSER_FULL_URL_HOSTS`, `fetch_public_page` results show the full URL: path and query, without credentials or fragment, and with the values of query parameters whose names look secret-bearing (`token`, `key`, `sig`, `session`, …) masked. This is decided per URL by that URL's own host, so a redirect from an opted-in host to another host shows the other host's origin only. Browser results follow the same rule. Logs, `blocked_requests` and `failed_requests`, challenge reports, handoff records and evidence records stay origin-only even for opted-in hosts.

> **No general-purpose program can reliably tell which path segments or parameter values are secrets.** Masking secret-looking parameter names is a heuristic. Listing a host in `RESEARCH_BROWSER_FULL_URL_HOSTS` means you knowingly accept that a token, session ID or other secret in that host's URLs may appear in results, and in anything that stores or forwards them.

### What is kept

Unless the evidence store is enabled, the service writes no files of its own, and everything below is lost when the process exits. Its audit log lines go to stderr, which the MCP client may store.

- **Handoff records**: at most 1,000. Each holds the task and pause IDs, the challenge reason, timestamps, the policy version, the URL's origin and an HMAC of the full URL. A record stops working when its resume handle expires (1 hour by default). It is removed from memory the next time a task is paused, or when the process exits.
- **The last 100 fetch classifications**, so `inspect_challenge` can take a `fetch_request_id`. Each holds the request ID, the origin and the challenge classification made from the full response. Page content is not kept.

- **Browser sessions** (when enabled): at most 2, each a Chromium process with in-memory cookies and storage and a temporary profile directory that Playwright deletes on close. Closed after 5 minutes idle or 30 minutes in total.

Page content and URLs are returned to the caller and not kept after the request finishes. Response headers are only used to classify challenges.

### Evidence

With `RESEARCH_BROWSER_EVIDENCE_DIR` set to an absolute directory, the service stores what its content hashes cover:

- `research.fetch_public_page`: the decoded response body (after `Content-Encoding` is removed), whose SHA-256 is the result's `content_hash` (`decoded_body_bytes`);
- the browser: the main document body (`decoded_body_bytes`), the serialised DOM of each snapshot (`rendered_dom_utf8`), each screenshot (`screenshot_png_bytes`), and the screenshot and DOM of a page that caused a pause.

Layout: `objects/sha256/<hex>` holds the exact bytes, `records/<evidence_id>.json` holds one record per capture (kind, hash and basis, byte length, media type, origin, request and session IDs, HTTP status, time, tool version). No path, query, headers or cookies are written. Objects are content-addressed and written once: staged in `tmp/`, fsynced, made read-only, hard-linked into place (which fails rather than overwrite), then read back and re-hashed; an existing object is re-hashed before reuse, and a symlink is never followed. Directories are `0700`.

Results say what happened: `evidence_status` is `disabled`, `persisted` or `failed`, `evidence_persisted` is true only after the read-back check, and a failure adds `evidence_error` and the warning `evidence_not_persisted` without failing the fetch. A body that was not read (a disallowed content type on an error status) is never stored. There is no retention, deletion or encryption tooling; the operator owns the directory.

Development uses npm (`package-lock.json`) and **Node.js 22 only**: `engines` (`^22`), `.nvmrc`, `@types/node` 22.x and CI all target the same line.

```bash
npm ci
npx playwright-core install chromium-headless-shell   # the Chromium build for the pinned playwright-core
npm run typecheck   # strict tsc over src/ and tests/, no emit
npm test            # node:test against local HTTP/HTTPS fixtures and real Chromium; no third-party sites
npm run build
npm run test:smoke  # tests the built dist/: stdio smoke tests, fetches and browser sessions against local fixtures
RESEARCH_BROWSER_ALLOWED_HOSTS="example.org" npm start
```

Without a Chromium build, local runs skip the browser tests; under `CI` they must run.

Known gaps:

- Address filtering in the process is not a substitute for deployment-level egress controls (network policy / firewall).
- The IPv6 allowlist is all of `2000::/3` minus the listed special-purpose blocks. Unallocated parts of it are allowed; they are unroutable. A NAT64 gateway that uses a network-specific prefix inside `2000::/3` is not detected. A new IANA special-purpose block inside `2000::/3` needs a code change; one outside it is denied automatically.
- The host allowlist matches exact names only. Every host, `www.` variants and the targets of same-site redirects included, has to be listed by hand. Look-alike names in other scripts are different hosts after Punycode conversion, so they are denied unless listed.
- For hosts opted in to full URLs, results show paths and the values of innocuously named query parameters. Origin-only output is the default precisely because no program can find every secret there.
- Event times are compared with zero clock-skew tolerance, so the host's and this service's clocks must agree.
- The DNS-rebinding tests use an injected resolver and loopback fixtures. They have not been run in a controlled network sandbox with a real authoritative DNS server.
- The evidence store has no retention, deletion, encryption or backup tooling. Handoff records and the classification cache are in memory only (see above).
- The browser runs page JavaScript, with Chromium's sandbox off by default. Its challenge detection is a heuristic; headed mode is not covered by automated tests; elements in iframes and shadow roots are not indexed; a paused session can only be resumed through a host-supplied verifier. See [Browser agent, §9](docs/07-browser-agent.md#9-known-limits).
- No search provider is enabled by default, and none ships with this repository; `research.search` answers `provider_unavailable`. Robots.txt is not consulted yet.
- Text extraction is regex-based and is not a full HTML parser.

### Continuous integration

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every `pull_request`. It uses Ubuntu 24.04 and Node.js 22 (read from `.nvmrc`), has a read-only `contents: read` token, uses no secrets, and does not use `pull_request_target`. The steps are:

1. `npm ci` installs exactly what `package-lock.json` records, then `npx playwright-core install --with-deps chromium-headless-shell` installs the Chromium build the pinned `playwright-core` expects.
2. `npm run typecheck` runs strict TypeScript over `src/` and `tests/`.
3. `npm test` runs the full suite inside a fresh network namespace that only has loopback, so a test that tries to reach a real host fails instead of passing. With `CI` set, the HTTPS and browser tests, including the zero-byte ClientHello regression, cannot be skipped: a missing `openssl` or Chromium fails the run. The browser tests drive real Chromium through the egress proxy against local fixtures.
4. `npm run build` compiles to `dist/`.
5. `npm run test:smoke` tests the built `dist/` only, also inside the loopback-only namespace.
   - `tests/smoke/dist-stdio.test.ts` starts `dist/index.js` with the MCP SDK's `StdioClientTransport` and checks that:
     - `initialize` and `tools/list` succeed and all five tools are listed;
     - fetching is denied by default;
     - both host lists are read from the environment, and the full-URL list changes only how URLs are shown;
     - a server with a wildcard in either list refuses to start.

     Every request has a timeout. Every child process is stopped (stdin EOF, then SIGTERM, then SIGKILL) and verified gone, even when a test fails.
   - `tests/smoke/dist-fetch.test.ts` imports the compiled `dist/fetcher.js` and `dist/index.js` and fetches from local HTTP and HTTPS fixtures. It covers:
     - redirects, gzip, extraction and hashing;
     - origin-only and opted-in URLs;
     - the peer check, the TLS certificate check, and refused redirects;
     - MCP result handling, including `inspect_challenge` by reference.

     The fixtures are reached through the same parameters the unit tests inject. A test checks that the policy `dist/index.js` builds from its environment refuses them.
   - `tests/smoke/dist-browser.test.ts` starts `dist/index.js` with the browser enabled, opens a session, checks that the empty default allowlist refuses navigation, and checks that no browser process outlives `close_session` or the server; an invalid browser setting must stop startup. It also runs the compiled `dist/browser/` modules against a local fixture, including a challenge pause.

CI does not check the following:

- A fetch or browser session against a real third-party site, including a real CAPTCHA page: `dist/` is only exercised against local fixtures.
- The headed browser (no display in CI).
- Node.js versions other than 22, which `engines` does not claim to support.
- Lint or formatting, a dependency audit, or runs on pushes to `main`.

## Goals

- Search and retrieve public research sources with provenance and timestamps.
- Normalize provider results behind a stable tool contract.
- Keep the MCP server separate from any consuming agent runtime; callers remain responsible for their own orchestration and policy enforcement.
- Preserve source evidence and derived observations separately.
- Pause and resume work through a trusted human-verification handoff when a site presents a CAPTCHA, login wall, rate limit, or policy challenge.
- Make failures, budgets, versions, and external data egress visible and testable.

## Non-goals for the MVP

- Accessing private pages or bypassing authentication, CAPTCHA, rate limits, robots rules, or other access controls. No CAPTCHA solving, fingerprint spoofing, stealth mode or identity rotation.
- Performing actions that modify a remote website. The fetcher runs no page JavaScript. The optional browser does, but only on allowlisted hosts; it refuses form submission and non-GET requests unless the operator opts a host in, and refuses password, one-time-code and payment fields.
- Receiving patient records, credentials, cookies, browser profiles, or unrelated protected data.
- Claiming that an agent's text message is proof that human verification happened.

## Proposed tool surface

The exact schema is to be finalized alongside acceptance tests. The initial candidate tool set is:

- `research.search` — search public sources through an explicitly configured provider.
- `research.fetch_public_page` — retrieve and extract bounded public HTML/text.
- `research.inspect_challenge` — classify observable access challenges without bypassing them.
- `research.pause_for_human` — persist a blocked task and provide a human handoff.
- `research.resume` — continue only after a trusted human-feedback event is recorded by the integrating runtime.
- `browser.open_session`, `browser.navigate`, `browser.snapshot`, `browser.click`, `browser.type`, `browser.scroll`, `browser.screenshot`, `browser.pause_for_human`, `browser.resume_session`, `browser.close_session` — the optional browser agent; see [Browser agent](docs/07-browser-agent.md).
  Every browser result includes `blocked_requests` and `failed_requests`: at most 20 new entries each, each reported once, with the warning `request_diagnostics_truncated` when entries were dropped, and both empty while a session is paused. A failed navigation may add a `net_error` token (`net::ERR_*`), and its error code comes from the navigation's own requests. The proxy records DNS, connection and upstream failures as origin-only events. Diagnostics and audit logs never contain paths, queries, headers, cookies, bodies or typed text. See [Browser agent, §4](docs/07-browser-agent.md#request-diagnostics).

The server must not treat MCP itself as a security boundary. The client/runtime is responsible for registering tools only in allowed modes, controlling data scopes and egress, and enforcing its Policy Gate. The server must still independently validate requests and protect its network boundary.

## Design principles

1. **Read-only by default.** No remote side effects unless the operator opts a host in to form submission.
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
- [Browser agent](docs/07-browser-agent.md)

## License

Not yet specified. Add a license before distributing or accepting contributions.
