# Research Browser MCP

An auditable, read-only research browsing service exposed through the Model Context Protocol (MCP).

## Status

**A read-only MVP for personal use.** It is a bounded fetcher and a human-handoff contract, tested against local fixtures only. It is not a production crawler, and neither these notes nor the tests are the result of a completed security audit; see "Known gaps" below.

Implemented:

- `src/index.ts` — MCP stdio server exposing the five `research.*` tools. It reads its host lists from the environment at startup (see [Configuration](#configuration)).
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
- `src/search.ts` — provider allowlist from startup configuration only. No provider is enabled by default.

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

**`RESEARCH_BROWSER_FULL_URL_HOSTS`** (optional) lists the trusted research hosts whose URLs `fetch_public_page` results may show with path and query. See [URL privacy](#url-privacy).

- It only changes what results show. It does not add hosts to the allowlist, and it does not change address checks, TLS, redirects or any other network behaviour.

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
- `pause_for_human` and `resume` outputs and the in-memory handoff records. Resume events are matched against an HMAC-SHA256 of the full canonical URL, never against the shown origin.

Results still carry `title`, `retrieved_at`, `content_hash` and `request_id`. The caller knows which URL it asked for, and `request_id` ties the result to that request.

For hosts listed in `RESEARCH_BROWSER_FULL_URL_HOSTS`, `fetch_public_page` results show the full URL: path and query, without credentials or fragment, and with the values of query parameters whose names look secret-bearing (`token`, `key`, `sig`, `session`, …) masked. This is decided per URL by that URL's own host, so a redirect from an opted-in host to another host shows the other host's origin only. Logs, challenge reports and handoff records stay origin-only even for opted-in hosts.

> **No general-purpose program can reliably tell which path segments or parameter values are secrets.** Masking secret-looking parameter names is a heuristic. Listing a host in `RESEARCH_BROWSER_FULL_URL_HOSTS` means you knowingly accept that a token, session ID or other secret in that host's URLs may appear in results, and in anything that stores or forwards them.

Development uses npm (`package-lock.json`) and **Node.js 22 only**: `engines` (`^22`), `.nvmrc`, `@types/node` 22.x and CI all target the same line.

```bash
npm ci
npm run typecheck   # strict tsc over src/ and tests/, no emit
npm test            # node:test against local HTTP/HTTPS fixtures; no third-party sites
npm run build
npm run test:smoke  # starts dist/index.js and talks to it over stdio
RESEARCH_BROWSER_ALLOWED_HOSTS="example.org" npm start
```

Known gaps:

- Address filtering in the process is not a substitute for deployment-level egress controls (network policy / firewall).
- The IPv6 allowlist is all of `2000::/3` minus the listed special-purpose blocks. Unallocated parts of it are allowed; they are unroutable. A NAT64 gateway that uses a network-specific prefix inside `2000::/3` is not detected. A new IANA special-purpose block inside `2000::/3` needs a code change; one outside it is denied automatically.
- The host allowlist matches exact names only. Every host, `www.` variants and the targets of same-site redirects included, has to be listed by hand. Look-alike names in other scripts are different hosts after Punycode conversion, so they are denied unless listed.
- For hosts opted in to full URLs, results show paths and the values of innocuously named query parameters. Origin-only output is the default precisely because no program can find every secret there.
- Event times are compared with zero clock-skew tolerance, so the host's and this service's clocks must agree.
- The DNS-rebinding tests use an injected resolver and loopback fixtures. They have not been run in a controlled network sandbox with a real authoritative DNS server.
- No durable evidence sink: results report `evidence_persisted: false`. Handoff records are in memory only.
- No search provider is enabled. Robots.txt is not consulted yet.
- Text extraction is regex-based and is not a full HTML parser.

### Continuous integration

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every `pull_request`. It uses Ubuntu 24.04 and Node.js 22 (read from `.nvmrc`), has a read-only `contents: read` token, uses no secrets, and does not use `pull_request_target`. The steps are:

1. `npm ci` installs exactly what `package-lock.json` records.
2. `npm run typecheck` runs strict TypeScript over `src/` and `tests/`.
3. `npm test` runs the full suite inside a fresh network namespace that only has loopback, so a test that tries to reach a real host fails instead of passing. With `CI` set, the HTTPS tests, including the zero-byte ClientHello regression, cannot be skipped: a missing `openssl` fails the run.
4. `npm run build` compiles to `dist/`.
5. `npm run test:smoke` starts the built `dist/index.js` with the MCP SDK's `StdioClientTransport`, also inside the loopback-only namespace. It checks that:
   - `initialize` and `tools/list` succeed and all five tools are listed;
   - fetching is denied by default;
   - both host lists are read from the environment, and the full-URL list changes only how URLs are shown;
   - a server with a wildcard in either list refuses to start.

   Every request has a timeout. Every child process is stopped (stdin EOF, then SIGTERM, then SIGKILL) and verified gone, even when a test fails.

CI does not check the following:

- A real page fetch through `dist/`: no allowlisted host is reachable from the namespace.
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
