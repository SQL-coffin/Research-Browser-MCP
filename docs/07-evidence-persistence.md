# 07 · Evidence Persistence Contract

Version: v0.1

This document fixes how `research.fetch_public_page` may persist source evidence. It refines §5 of [Evidence and provenance](04-evidence-and-provenance.md). The implementation lives in `src/evidence.ts` and `src/fetcher.ts`; the required behaviour is pinned by `tests/evidence.test.ts`.

## 1. Off by default

- Persistence is enabled only by the startup variable `RESEARCH_BROWSER_EVIDENCE_DIR`. Tool input can never enable it, choose the directory, or change what is written.
- Unset or empty: no store exists, nothing is written anywhere (including the working directory), and results are byte-for-byte what they are today: `evidence_persisted: false`, no `evidence_id`, no `payload_ref`.
- The value must be an absolute path. A relative path is a configuration error (`EvidenceConfigError`) and the server refuses to start, as with an invalid host allowlist.
- The root directory is never created by the server. A missing root is a storage failure at save time (§4), so a typo cannot silently create a new evidence tree.

## 2. What is persisted

Only a fetch whose result `status` is `success` (2xx, no challenge detected) is persisted. Policy denials, timeouts, size-limit failures, challenge pages, 4xx/5xx and every other non-success result write nothing and report `evidence_persisted: false`.

## 3. Storage format

Under the configured root:

```
<root>/
  records/<evidence_id>.json        EvidenceRecord, UTF-8 JSON
  payloads/sha256/<hex>             decoded body bytes; <hex> is content_hash.value
```

- `records/` and `payloads/sha256/` are created on first use with mode `0700`; files are written with mode `0600` (POSIX).
- `evidence_id` is a fresh UUID for every save. It is distinct from `request_id`, and neither the id nor any file name is derived from the URL.
- The payload is exactly the bytes `content_hash` covers (`basis: "decoded_body_bytes"`): after content-encoding is removed, before text extraction, and the full body even when `extracted_text` was truncated. `sha256(payload file) === content_hash.value` always holds.
- Payloads are content-addressed: two records of identical bytes share one payload file.

`EvidenceRecord` fields (`schema_version: 1`): `evidence_id`, `request_id`, `tool_version`, `source_url`, `final_url`, `redirect_chain`, `retrieved_at`, `status`, `http_status`, `content_type`, `challenge_type`, `content_hash`, `payload_ref` (relative, `payloads/sha256/<hex>`), `payload_bytes`, `text_truncated`, `warnings`. Values equal the corresponding fields of the returned result. Extracted text is not stored; it can be re-derived from the payload.

## 4. Append-only, no overwrite

- A record is never overwritten. Saving an `evidence_id` whose record exists fails with `evidence_exists` and leaves the existing file byte-identical.
- A payload is never overwritten. If `payloads/sha256/<hex>` exists and its bytes hash to `<hex>`, it is reused. If its bytes do not (corruption or tampering), the save fails with `evidence_payload_mismatch` and the file is left as found, for investigation.
- A partially written record is never visible at `records/<evidence_id>.json` (write to a temporary name, then link or rename without replacing).
- Re-fetching the same URL, changed or not, creates a new record.

## 5. Result rules

| Situation | `status` | `evidence_persisted` | `evidence_id` / `payload_ref` | `error` |
|---|---|---|---|---|
| Persistence off | unchanged | `false` | absent | unchanged |
| Not a `success` fetch | unchanged | `false` | absent | unchanged |
| Saved | `success` | `true` | present; equal to the record | absent |
| Save failed (any code, or the store threw) | `evidence_unavailable` | `false` | absent | `{ code: <failure code>, retryable: false }` |

- `evidence_persisted: true` is reported only after the store confirmed the save. A failure never yields `true`.
- `evidence_unavailable` is a status about persistence, not about retrieval. It means this call did not produce a durable evidence record that meets this contract; it does not mean the HTTP fetch failed or that the returned text is unusable. Callers decide what to do with it: retry the save by fetching again, use the content as transient information only, or stop work that depends on citable evidence.
- On a save failure the fetched content is still returned (`extracted_text`, `content_hash`, …), but the status tells the caller that this result is not durable evidence. The operator asked for durable evidence; a quiet `success` would let it be cited as if it were.
- `payload_ref` is relative to the root. The root path never appears in results, errors or logs.

## 6. Sensitive data

- Every URL in a record is the form the result showed (origin only by default; for hosts opted in through `RESEARCH_BROWSER_FULL_URL_HOSTS`, the display form without userinfo or fragment and with secret-looking query values masked). The raw request URL is never stored.
- File and directory names contain only UUIDs and hashes.
- Error messages for storage failures are fixed text: no file-system path, no OS error text, no URL.
- Each save writes one audit line to stderr: `{ event: "evidence", request_id, evidence_id?, outcome }` where `outcome` is `saved` or the failure code. It carries no URL and no path.
- Retention, deletion, encryption at rest and backup of the root directory are the operator's responsibility; the server only appends.
