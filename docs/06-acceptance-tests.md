# 06 · Acceptance Tests

Version: v0.1 draft

These are required contract tests, not evidence that tests or implementation currently exist. Run them first against local deterministic fixtures, not real patient data.

| ID | Scenario | Expected result |
|---|---|---|
| RB-01 | Tool request contains an unknown provider | Rejected; no provider is dynamically registered |
| RB-02 | URL targets loopback or private IPv4/IPv6 | `policy_denied`; no connection to target |
| RB-03 | URL targets link-local, reserved, multicast, or cloud metadata | `policy_denied`; no request is sent |
| RB-04 | Redirect points to a disallowed or private address | Redirect is rejected before connecting |
| RB-05 | DNS answer changes between validation and connection | Peer-address verification blocks request |
| RB-06 | URL includes username/password or disallowed scheme/port | Rejected before network access |
| RB-07 | Response exceeds wire-byte, decompressed-byte, redirect, or text limits | Bounded failure with no false success |
| RB-08 | Page contains prompt-injection instructions | Content is returned only as untrusted data; policy does not change |
| RB-09 | Response includes secrets in headers/query values | Logs and user-visible diagnostics redact them |
| RB-10 | Site reports a CAPTCHA | Typed challenge result; no automatic solving or bypass |
| RB-11 | Site requires login or disallows access | Pause/blocked result or policy stop; no credential/session reuse |
| RB-12 | Site returns HTTP 429 with retry guidance | Rate-limited result; bounded policy-compliant delay/retry only |
| RB-13 | Trusted-human event is absent or mismatched | Resume denied by host runtime |
| RB-14 | Duplicate resume event is submitted | Idempotent outcome; no duplicated unauthorized work |
| RB-15 | Tool/policy version changes while task is blocked | Drift check blocks or demands explicit review |
| RB-16 | Evidence sink is unavailable | Result does not claim durable evidence was persisted |
| RB-17 | Same URL changes between retrievals | Distinct evidence records with separate hashes/timestamps |
| RB-18 | External provider is disabled or egress not approved | Request denied without fallback to unapproved provider |
| RB-19 | Consumer sends protected case/patient data in a search query | Consumer policy blocks before external egress; server validates any enforceable contract |
| RB-20 | Tool returns schema-invalid output or extraction error | Structured failure; invalid output is not recorded as success evidence |

## Test strategy

- Unit-test validation, normalization, hash-basis declaration, challenge classification, and status mapping.
- Integration-test a fake HTTP server with redirects, compressed payloads, malformed HTML, timeouts, 429s, and prompt-injection strings.
- Use a controlled network sandbox for DNS rebinding and peer-address enforcement.
- Test resume behavior against a fake host-runtime event verifier.
- Assert logs contain no secrets and every call has a correlation ID.
- Keep tests deterministic and avoid contacting third-party websites unless a separately approved smoke test is being run.

## Release gate

No external provider or real user data until all mandatory tests pass, the egress and retention review is complete, and the tool contract is versioned.
