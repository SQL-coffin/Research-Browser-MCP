# 04 · Evidence and Provenance

Version: v0.1 draft

## 1. Evidence model

Keep raw source evidence distinct from derived observations and summaries. A summary never substitutes for the original source record.

Suggested evidence record:

| Field | Meaning |
|---|---|
| `evidence_id` | Stable unique identifier |
| `source_url` | Requested source URL, safely redacted for display/logs where needed |
| `final_url` | Final URL after validated redirects |
| `retrieved_at` | UTC retrieval timestamp |
| `provider_id` / `provider_version` | Provider identity and version |
| `tool_version` | Server/fetcher version |
| `content_type` / `http_status` | Response metadata |
| `content_hash` | Hash of canonical bytes or normalized extracted text; the hash basis must be declared |
| `payload_ref` | Reference to immutable body/text payload if a configured evidence sink is enabled |
| `redirect_chain` | Ordered validated redirects, with sensitive values redacted |
| `request_id` | Correlation identifier connecting logs and result |
| `warnings` | Truncation, extraction, robots, or validation caveats |

## 2. Immutability and corrections

Evidence should be append-only. Re-fetching a changed page creates a new evidence record; it does not overwrite the earlier record. A canonicalization or extractor change should produce a new derived artifact with its own version and parent evidence reference.

## 3. Hash semantics

Record exactly what is hashed: response bytes, normalized text, or another canonical representation. Do not compare hashes across different bases as if they were equivalent. If a payload is truncated, record that fact and hash the captured representation, not an implied full page.

## 4. Observations and claims

Derived Observation fields should include `observation_id`, statement, source evidence IDs, extractor/model version, creation time, and confidence or uncertainty if applicable. A page's own assertion does not automatically establish truth. Claims should be corroborated according to the consuming application's evidence policy.

## 5. Storage and retention

The server must distinguish between a returned evidence metadata envelope and durable persistence. If there is no configured evidence sink, return metadata and hash only where feasible and state `evidence_persisted: false`. If content is persisted, access, retention, deletion, encryption, and backup rules must be documented for that sink.

## 6. Source changes and conflicts

If the same URL yields different content, create distinct evidence records. Preserve retrieval time, final URL, and tool/provider versions. Consumers may create conflict records when authoritative sources disagree; the browser service must not silently pick a winner.

## 7. Privacy

Do not persist credentials, session identifiers, or protected user data. Query strings and redirect targets may contain secrets; redact them in logs and consider a safe-display URL alongside the actual request URL in restricted storage.
