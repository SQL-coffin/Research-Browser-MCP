# Research-Browser-MCP — working rules for Claude Code

Read this before acting in this repository. It sets how much to verify and who decides what. It adds to `docs/project-context-pack.md`; it does not replace it.

## Where things are recorded

- `docs/project-context-pack.md`: security invariants, privacy contract, required workflow, decisions, verified branch state, evidence labels and the handoff template. Recorded decisions stand: build on them instead of asking for them to be proven again, and say so if new evidence contradicts one.
- The numbered documents in `docs/` define the contracts: architecture, tools, threat model, evidence, human verification, acceptance tests and the browser agent.
- Recorded branch state can be stale. Check the actual branch, HEAD and diff before relying on it.

## Roles

- **Claude (implementer):** writes code and runs tests under the incremental verification rules below.
- **Reviewer:** reviews the current change and its key risks, reusing existing evidence.
- **Owner:** decides project direction and approves merges and other consequential actions.

## Core principle

This is a continuously evolving project, not a series of independent full audits. Do not re-verify unchanged components without a concrete reason. Reuse trustworthy evidence from earlier commits, CI runs, regression tests and reviews unless new changes or new evidence invalidate it. Aim for the most useful verification per unit of engineering time, not the most checks.

Reduce redundant verification, never necessary safeguards. The Context Pack's security invariants and privacy contract apply in full, and a diagnostics-only change must not change allow/deny behavior.

## Change-scoped verification

For every task or PR:

1. Identify the files, functions, contracts and behavior the diff changes.
2. Identify directly affected dependencies and realistic regression paths.
3. For a fix, write a focused regression test, confirm it fails for the intended reason, then make the smallest change.
4. Run the smallest set of tests that adequately verifies the change, for example `node --import tsx --test tests/<file>.test.ts` with `--test-name-pattern`.
5. Reuse existing CI and test results for unchanged components while they still apply.
6. Expand verification only when the diff, a failing test or concrete evidence justifies it.

Full validation is CI's job. `.github/workflows/ci.yml` runs typecheck, build, `npm test` and the smoke tests on every pull request. The tests run with `CI=true`, so browser and HTTPS tests cannot skip, in a loopback-only network. That run is how the "full validation" step of the Context Pack's workflow is met. Run the full suite locally only for broad changes, shared infrastructure changes, release requirements or meaningful regression risk.

## Evidence

- Evidence belongs to the commit and environment that produced it. An earlier run does not verify code it never exercised.
- Outside CI, browser tests skip without Chromium and HTTPS tests skip without openssl. Report them as skipped, never as passed.
- Never claim a test passed on a machine or environment where it did not run.
- For each task, record what was verified (commit, command, result), what is still unverified, and any assumptions or environment limits. Use the Context Pack's evidence labels and handoff template, and update the Context Pack when a decision or verified fact changes.
- If evidence is stale, incomplete or contradicted, re-verify only the affected part.

## Risk-based review

- **P0 — Critical:** stop immediately; a severe security or data-integrity failure is present.
- **P1 — High:** block the affected change; a core security boundary, essential functionality or an important contract is broken.
- **P2 — Medium:** document it and decide whether to fix it now or track it separately.
- **P3 — Low:** record it for later cleanup; do not block unrelated progress.

Write the severity word next to the label, for example "P2 (Medium)". Finding IDs in the docs, such as D1, L3 or P1, are identifiers, not severities.

Do not inflate speculative edge cases into blockers without a credible failure path or supporting evidence.

## Review scope

- Focus on the current diff and directly affected behavior.
- Do not reopen resolved findings unless the change reintroduces them or undermines their evidence.
- Do not make unrelated refactoring or another full security audit a condition of approval.
- Keep confirmed defects, hypotheses and optional improvements apart.
- Conclude briefly: Pass, Pass with conditions, or Changes required.

## Autonomy and reporting

- When requirements are clear, proceed with implementation and targeted tests. Ask only when an ambiguity materially affects correctness, safety or architecture.
- Report what changed, what was actually verified, any remaining material risk and the next concrete action. Skip long progress reports, repeated explanations and redundant test requests.
- Only with the owner's explicit authorization: merging a PR, changing a PR's draft or ready status, pushing to `main`, changing repository permissions, and other consequential repository actions such as force-pushing or deleting branches.
