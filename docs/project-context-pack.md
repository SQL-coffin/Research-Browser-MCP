# Research-Browser-MCP — Project Context Pack
Version: 1.1
Updated: 2026-10-24

> Durable handoff notes for ChatGPT, Claude, and collaborating agents. Always verify repository state before acting. This document stores auditable conclusions and evidence, not hidden chain-of-thought.

## Evidence labels
- **Verified**: directly confirmed from GitHub/tool output.
- **User-confirmed**: user has checked the evidence (for example, CI logs).
- **Historical**: prior conversation report; not current verification.
- **Unverified**: must be reproduced.
- **Planned**: proposed, not necessarily implemented.

## Project boundaries
- **Research-Browser-MCP** is a reusable MCP server for controlled browser research and evidence gathering.
- **CAD Copilot** is a separate consumer. Intended flow: CAD Copilot → MCP client → Research-Browser-MCP → public web evidence. Keep repositories, branches, code, and test status separate.
- **VulnCraw** was discussed as a possible integration; this is exploratory, not evidence of an implemented integration. Define API contracts and network boundaries before connecting projects.

## CAPTCHA / access-barrier policy
Detect CAPTCHA, login gates, rate limits, denials, and similar barriers; stop safely, report the state, and request human verification or use an authorized public alternative. Do not automatically solve/bypass CAPTCHA, evade access controls, or use real websites in local-fixture tests. Any human-assisted recovery/session-resume flow must be explicitly designed and tested.

## Historical technology context — re-check before relying
TypeScript strict mode, NodeNext ESM, Node 22, MCP SDK 1.32.1, Playwright Core 1.56.1 / Chromium 141, Zod 4, `node --import tsx --test`, type tooling including `tsgo`. Browser code includes `src/browser/`; egress proxy includes `src/egress-proxy.ts`. Verify current `package.json`, lockfile, runtime and scripts.

## Security invariants
Do not weaken without explicit review:
- Exact host allowlisting; DNS validation and DNS-rebinding protection.
- Validation of the actual connected peer.
- Redirect re-validation/limits, resource/time/size limits, and request-method restrictions where specified.
- TLS policy and WebSocket restrictions.
- Safe stop at CAPTCHA/login/429/access-control barriers.
- Secret-safe logs and tool results.
Diagnostics-only changes must not change allow/deny behavior.

### Privacy contract
Use origin-only URLs (scheme + host + port as needed). Never expose paths/query strings, headers, cookies/tokens, request/response bodies, page content, typed text, or raw sensitive exception messages. Extract controlled error codes such as `net::ERR_NAME_NOT_RESOLVED` instead of echoing full URLs.

## Acceptance / workflow
A prior acceptance document was identified as `docs/07-implementation-acceptance.md`, reportedly with 24 requirements and P0 items for SSRF/peer validation, redirects/resource limits, barrier stopping, trusted recovery, persistence/idempotency, and secret-safe logs. Re-read the actual document before release; historically any P0 FAIL/PARTIAL/NOT RUN blocks release.

Required workflow:
1. Inspect branch, HEAD, worktree, and diff before edits.
2. TDD: write a focused regression test, run it and confirm intended failure, then make the smallest change.
3. Run focused tests, then full validation.
4. Review `git diff --check`, full diff, security invariants, and output redaction.
5. Commit/push only the intended branch and verify the remote ref.
6. Report every command as PASS/FAIL/SKIPPED with evidence. Never claim unrun tests passed.

Intended commands (check they exist in current package scripts): `npm run typecheck`, `npm run build`, `npm test`, `npm run test:smoke`, `git diff --check`. Use `CI=true` and loopback-only network isolation where supported; claim isolation only when actually configured and verified.

## Repository / branch state — 2026-10-24
Repository: `SQL-coffin/Research-Browser-MCP`.

**Verified current branch head:** `claude/funny-hamilton-i5tgbw` at `08c59d0bae7c119834066e06fdffc88fcef6781c`. This is the merge commit for PR #4 and is the correct baseline for the current browser-diagnostics work. Do not use `main` as the baseline unless a new task explicitly requires it.

- Prior diagnostics commit: `00be3a150b070afa5c73b960bd83bd4dec445f02`, message `fix: add origin-only browser network diagnostics`.
- PR #4: https://github.com/SQL-coffin/Research-Browser-MCP/pull/4
- PR #4 merged into `claude/funny-hamilton-i5tgbw`, not `main`. Its change only touched `tests/smoke/dist-browser.test.ts`, passing `LD_LIBRARY_PATH` through to the spawned browser server when present.
- **User-confirmed:** CI run #8 logs were checked and show `npm test` 407/407 and smoke 22/22; typecheck also reported OK in PR #4 description. Preserve run #8 as the evidence source when linking the run in future notes.
- The branch head above was checked via GitHub during this session.

### Browser diagnostics commit
Files changed:
- `src/egress-proxy.ts`
- `src/browser/session.ts`
- `src/browser/actions.ts`
- `tests/egress-proxy.test.ts`
- `tests/browser.test.ts`
- `README.md`
- `docs/07-browser-agent.md`

Intended contract: bounded proxy events (`seq`, origin, code, kind error/deny); distinguish DNS/connect/timeouts from policy denial; expose bounded `blocked_requests`, `failed_requests`, and URL-free `net_error`; origin-only audit logs.

### Diagnostics risks to review (not presumed fixed)
- Ensure all proxy failure paths, including closed/error paths, are recorded.
- Do not mistake a subresource failure for the main navigation error.
- Ensure every `browser.*` result path includes documented diagnostic fields, including invalid-input and missing-session paths.
- Verify event cursors mean “since the last action” and aren't consumed by unrelated calls.
- CONNECT tunnels are opaque to the proxy; individual encrypted HTTPS subresource failures need browser-layer observation.
- Execute DNS/TLS tests against actual fixture/helper APIs.
- Ensure docs describe only behavior actually guaranteed by code.

## Current review / remediation baseline
Use `claude/funny-hamilton-i5tgbw` at `08c59d0bae7c119834066e06fdffc88fcef6781c` as the baseline. Prefer a dedicated fix branch created from that exact SHA (for example, `fix/browser-diagnostics-boundaries`), then open a PR back into `claude/funny-hamilton-i5tgbw`. Do not modify `main` or merge a PR without explicit approval.

A review artifact reportedly contains four reproduced boundary issues plus contract and failing-test drafts. The artifact content has not been accessible to this session; do not guess the four issues. Import/read the report before implementing. Convert each finding into a regression test and prove it fails before fixing.

## Agent delegation
Suggested 8 specialist roles plus one Integration Agent:
1. Egress proxy diagnostics.
2. Browser request failures.
3. Result schema consistency.
4. Proxy tests.
5. Chromium/local-fixture tests and redaction.
6. Documentation.
7. Security audit (SSRF/DNS/peer/TLS/redirects/methods/secrets).
8. Independent review.
9. Integration Agent owns reconciliation, full test run, final diff review and commit/PR.

Subagents must own clear scopes/files. Do not have multiple agents concurrently edit the same critical file without a merge plan.

### Compact subagent prompt
> Work only on the assigned Research-Browser-MCP scope. Inspect branch/worktree first. Use TDD: add a focused regression test and demonstrate the intended failure before implementing the smallest fix. Do not change allow/deny policy or weaken SSRF/DNS/peer/TLS/redirect/resource controls. Do not bypass CAPTCHA or contact real websites; use local fixtures. Never emit URL paths/queries, headers, cookies, bodies, typed text, or sensitive raw errors. Do not overwrite unrelated changes. Report files, exact commands and outputs, risks, and unrun checks. Never claim success without evidence. Integration Agent owns final validation.

## Handoff report template
### Scope
- Goal:
- Repository / branch / base SHA:
- Constraints:

### Changes
- Files:
- Behavior changed:
- Security behavior intentionally unchanged:

### Verification
| Check | Result | Evidence |
|---|---|---|
| typecheck | PASS / FAIL / SKIPPED | exact command/output |
| build | PASS / FAIL / SKIPPED | exact command/output |
| unit tests | PASS / FAIL / SKIPPED | exact command/output |
| smoke tests | PASS / FAIL / SKIPPED | exact command/output |
| diff/security review | PASS / FAIL / SKIPPED | findings |

### Follow-up
- Risks:
- Tests not run and why:
- Next action:
- Commit SHA / PR URL:

## Maintenance
Update this file when verified branch/commit facts, decisions and rationale, reproducible test evidence, API/security contracts, risks, or next actions change. Keep concise, auditable rationale—not hidden reasoning transcripts.
