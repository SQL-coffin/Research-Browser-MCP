import { lookup as dnsLookup } from "node:dns/promises";
import http from "node:http";
import https from "node:https";
import type { LookupFunction, Socket } from "node:net";
import net, { isIP } from "node:net";
import { Transform, type Readable } from "node:stream";
import zlib from "node:zlib";
import {
  canonicalAddress,
  checkAddress,
  classifyChallenge,
  DEFAULT_URL_POLICY,
  redactHeaders,
  discloseUrl,
  ORIGIN_ONLY,
  redactUrl,
  sha256,
  validateUrl,
  type ChallengeResult,
  type ContentHash,
  type UrlDisclosure,
  type UrlPolicy,
} from "./security.js";
import { NO_EVIDENCE, type EvidenceOutcome, type EvidenceSink } from "./evidence.js";
import { newRequestId, stderrAuditLogger, TOOL_VERSION, toolError, type AuditLogger, type Status, type ToolError } from "./result.js";

export interface FetchPolicy extends UrlPolicy {
  maxRedirects: number;
  /** Bytes received on the wire (possibly compressed). */
  maxWireBytes: number;
  /** Bytes after content-encoding is removed. */
  maxDecodedBytes: number;
  maxTextChars: number;
  connectTimeoutMs: number;
  totalTimeoutMs: number;
  allowedContentTypes: ReadonlySet<string>;
}

export const DEFAULT_FETCH_POLICY: FetchPolicy = {
  // Includes isAddressAllowed: the same policy judges URLs, DNS answers and peers.
  ...DEFAULT_URL_POLICY,
  maxRedirects: 5,
  maxWireBytes: 2 * 1024 * 1024,
  maxDecodedBytes: 5 * 1024 * 1024,
  maxTextChars: 100_000,
  connectTimeoutMs: 5_000,
  totalTimeoutMs: 15_000,
  allowedContentTypes: new Set(["text/html", "application/xhtml+xml", "text/plain"]),
};

export interface ResolvedAddress {
  address: string;
  family: 4 | 6;
}

export interface FetchDeps {
  resolve: (hostname: string) => Promise<ResolvedAddress[]>;
  log: AuditLogger;
  now: () => Date;
  /** Extra trust anchors (tests only). Never disables certificate verification. */
  tlsCa?: string | Buffer;
  /** Where retrieved bodies are persisted. Defaults to NO_EVIDENCE (disabled). */
  evidence?: EvidenceSink;
}

export const defaultResolve = async (hostname: string): Promise<ResolvedAddress[]> => {
  const answers = await dnsLookup(hostname, { all: true, verbatim: true });
  return answers.map((a) => ({ address: a.address, family: a.family === 6 ? 6 : 4 }));
};

export const DEFAULT_FETCH_DEPS: FetchDeps = {
  resolve: defaultResolve,
  log: stderrAuditLogger,
  now: () => new Date(),
};

export interface RedirectHop {
  /** As UrlDisclosure allows: the origin unless this hop's host is opted in to full URLs. */
  url: string;
  http_status: number;
  peer_address: string;
}

interface Base {
  request_id: string;
  tool_version: string;
  source_url: string;
  redirect_chain: RedirectHop[];
  warnings: string[];
}

export interface FetchSuccess extends Base {
  status: Exclude<Status, "invalid_input" | "policy_denied" | "timeout" | "content_too_large" | "internal_error">;
  final_url: string;
  title: string | null;
  retrieved_at: string;
  content_type: string;
  http_status: number;
  extracted_text: string;
  text_truncated: boolean;
  content_hash: ContentHash;
  challenge: ChallengeResult;
  challenge_type: ChallengeResult["challenge_type"];
  /** True only when the decoded body bytes were written and read back with the declared hash. */
  evidence_persisted: boolean;
  evidence_status: "disabled" | "persisted" | "failed";
  evidence_id?: string;
  evidence_error?: ToolError;
  error?: ToolError;
}

export interface FetchFailure extends Base {
  status: Status;
  error: ToolError;
}

export type FetchResult = FetchSuccess | FetchFailure;

/** A policy or transport stop with the status and code reported to the caller. */
export class FetchStop extends Error {
  constructor(
    readonly status: Status,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/**
 * DNS layer of the address policy: EVERY answer must pass. A mixed answer (one
 * public, one private) is rejected outright rather than filtered, because some
 * resolvers return the attacker-preferred address first only some of the time.
 */
export function validateDnsAnswers(answers: ResolvedAddress[], policy: UrlPolicy): ResolvedAddress {
  if (answers.length === 0) throw new FetchStop("provider_unavailable", "dns_no_answer", "Host name has no addresses");
  for (const a of answers) {
    const verdict = checkAddress(a.address, policy);
    if (!verdict.allowed) {
      throw new FetchStop("policy_denied", `address_${verdict.reason}`, "Destination resolves to a non-public address");
    }
  }
  return answers[0]!;
}

async function resolveAndValidate(hostname: string, ipLiteral: string | null, policy: UrlPolicy, deps: Pick<FetchDeps, "resolve">): Promise<ResolvedAddress> {
  let answers: ResolvedAddress[];
  if (ipLiteral) {
    answers = [{ address: ipLiteral, family: isIP(ipLiteral) === 6 ? 6 : 4 }];
  } else {
    try {
      answers = await deps.resolve(hostname);
    } catch {
      throw new FetchStop("provider_unavailable", "dns_resolution_failed", "Host name could not be resolved");
    }
  }
  return validateDnsAnswers(answers, policy);
}

/**
 * A `lookup` that ignores the hostname and returns only the already-validated
 * address. The socket therefore connects to exactly the IP we checked, and no
 * second DNS query happens between check and use (closes the rebinding window).
 */
function pinnedLookup(pinned: ResolvedAddress): LookupFunction {
  return ((_hostname: string, options: { all?: boolean }, callback: (...args: unknown[]) => void) => {
    if (options?.all) callback(null, [{ address: pinned.address, family: pinned.family }]);
    else callback(null, pinned.address, pinned.family);
  }) as LookupFunction;
}

/** Second, independent check on the address the kernel actually connected to. */
export function verifyPeer(remoteAddress: string | undefined, pinned: string, policy: UrlPolicy): void {
  const peer = remoteAddress ? canonicalAddress(remoteAddress) : null;
  if (!peer || peer !== canonicalAddress(pinned)) {
    throw new FetchStop("policy_denied", "peer_address_mismatch", "Connected peer does not match the validated address");
  }
  const verdict = checkAddress(peer, policy);
  if (!verdict.allowed) {
    throw new FetchStop("policy_denied", `peer_${verdict.reason}`, "Connected peer address is not public");
  }
}

/**
 * Resolves `hostname` (or takes the IP literal), validates every answer, connects
 * to the validated address only and checks the connected peer before resolving,
 * so no byte is written to a peer the policy rejects. Resolution and connect share
 * `timeoutMs` (dns_timeout, then connect_timeout). Used by the browser egress
 * proxy, which relays the browser's traffic over the returned socket.
 * Throws FetchStop on any policy or connection failure.
 */
export async function connectPinned(
  hostname: string,
  ipLiteral: string | null,
  port: number,
  policy: UrlPolicy,
  deps: Pick<FetchDeps, "resolve">,
  timeoutMs: number,
): Promise<{ socket: Socket; peer: string }> {
  // One budget covers resolution and connect. An answer that arrives after the
  // deadline is dropped: nothing is connected to it.
  const deadline = Date.now() + timeoutMs;
  let dnsTimer: NodeJS.Timeout | undefined;
  const expired = new Promise<never>((_, reject) => {
    dnsTimer = setTimeout(() => reject(new FetchStop("timeout", "dns_timeout", "Host name resolution timed out")), timeoutMs);
  });
  const resolving = resolveAndValidate(hostname, ipLiteral, policy, deps);
  resolving.catch(() => {});
  let pinned: ResolvedAddress;
  try {
    pinned = await Promise.race([resolving, expired]);
  } finally {
    clearTimeout(dnsTimer);
  }
  const remaining = deadline - Date.now();
  if (remaining <= 0) throw new FetchStop("timeout", "connect_timeout", "Connection timed out");
  return new Promise((resolve, reject) => {
    // Connecting to the address itself: no lookup, so nothing can re-resolve the name.
    const socket = net.connect({ host: pinned.address, port, family: pinned.family });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new FetchStop("timeout", "connect_timeout", "Connection timed out"));
    }, remaining);
    socket.prependOnceListener("connect", () => {
      clearTimeout(timer);
      try {
        verifyPeer(socket.remoteAddress, pinned.address, policy);
      } catch (err) {
        socket.destroy();
        reject(err);
        return;
      }
      resolve({ socket, peer: canonicalAddress(socket.remoteAddress!)! });
    });
    socket.once("error", () => {
      clearTimeout(timer);
      socket.destroy();
      reject(new FetchStop("provider_unavailable", "connection_failed", "Connection to the destination failed"));
    });
  });
}

interface HopResponse {
  res: http.IncomingMessage;
  peer: string;
  abort: (err: Error) => void;
}

function requestHop(url: URL, hostname: string, port: number, pinned: ResolvedAddress, policy: FetchPolicy, deps: FetchDeps, signal: AbortSignal): Promise<HopResponse> {
  return new Promise((resolve, reject) => {
    const isHttps = url.protocol === "https:";
    const options: https.RequestOptions = {
      protocol: url.protocol,
      host: hostname,
      port,
      path: `${url.pathname}${url.search}`,
      method: "GET",
      // Fixed header set: nothing from the caller, no cookies, no Authorization.
      headers: {
        "user-agent": `ResearchBrowserMCP/${TOOL_VERSION} (+read-only research fetcher)`,
        accept: "text/html,application/xhtml+xml,text/plain;q=0.9",
        "accept-encoding": "gzip, deflate, br",
        connection: "close",
      },
      // A fresh agent per hop: never pools sockets across hosts, never picks up a
      // proxy from the environment, and always uses our pinned lookup.
      agent: false,
      lookup: pinnedLookup(pinned),
      timeout: policy.connectTimeoutMs,
      signal,
    };
    if (isHttps) {
      options.servername = isIP(hostname) ? "" : hostname;
      options.rejectUnauthorized = true;
      if (deps.tlsCa) options.ca = deps.tlsCa;
    }

    let settled = false;
    const fail = (err: unknown) => {
      if (settled) return;
      settled = true;
      req.destroy();
      reject(err);
    };

    const req = (isHttps ? https : http).request(options);
    req.on("socket", (socket: Socket) => {
      const check = () => {
        try {
          verifyPeer(socket.remoteAddress, pinned.address, policy);
        } catch (err) {
          fail(err);
        }
      };
      // Prepended so it runs before tls.connect's own "connect" listener, which
      // starts the handshake: a rejected peer gets no ClientHello and no request bytes.
      if (socket.remoteAddress) check();
      else socket.prependOnceListener("connect", check);
    });
    req.on("timeout", () => fail(new FetchStop("timeout", "connect_timeout", "Connection timed out")));
    req.on("error", (err) => fail(err));
    req.on("response", (res) => {
      if (settled) {
        res.destroy();
        return;
      }
      try {
        // Re-check at response time as well; cheap, and guards against socket reuse.
        verifyPeer(res.socket.remoteAddress, pinned.address, policy);
      } catch (err) {
        res.destroy();
        fail(err);
        return;
      }
      settled = true;
      resolve({ res, peer: canonicalAddress(res.socket.remoteAddress!)!, abort: (err) => req.destroy(err) });
    });
    req.end();
  });
}

function byteLimiter(limit: number, code: string, message: string, onBytes?: (n: number) => void): Transform {
  let total = 0;
  return new Transform({
    transform(chunk: Buffer, _enc, cb) {
      total += chunk.length;
      onBytes?.(total);
      if (total > limit) cb(new FetchStop("content_too_large", code, message));
      else cb(null, chunk);
    },
  });
}

function decoderFor(encoding: string | undefined): Transform | null | "unsupported" {
  const enc = (encoding ?? "identity").trim().toLowerCase();
  switch (enc) {
    case "":
    case "identity":
      return null;
    case "gzip":
    case "x-gzip":
      return zlib.createGunzip();
    case "deflate":
      return zlib.createInflate();
    case "br":
      return zlib.createBrotliDecompress();
    default:
      return "unsupported";
  }
}

async function readBody(res: http.IncomingMessage, policy: FetchPolicy): Promise<Buffer> {
  const declared = Number(res.headers["content-length"]);
  if (Number.isFinite(declared) && declared > policy.maxWireBytes) {
    throw new FetchStop("content_too_large", "wire_bytes_exceeded", "Declared Content-Length exceeds the wire-byte limit");
  }
  const decoder = decoderFor(res.headers["content-encoding"]);
  if (decoder === "unsupported") {
    throw new FetchStop("extraction_failed", "unsupported_content_encoding", "Unsupported Content-Encoding");
  }

  let stream: Readable = res.pipe(byteLimiter(policy.maxWireBytes, "wire_bytes_exceeded", "Response exceeds the wire-byte limit"));
  const stages: Readable[] = [res, stream];
  if (decoder) {
    stream = stream.pipe(decoder);
    stages.push(stream);
  }
  stream = stream.pipe(byteLimiter(policy.maxDecodedBytes, "decoded_bytes_exceeded", "Decompressed body exceeds the decoded-byte limit"));
  stages.push(stream);

  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let done = false;
    const onError = (err: unknown) => {
      if (done) return;
      done = true;
      for (const s of stages) s.destroy();
      if (err instanceof FetchStop) reject(err);
      else if (err instanceof Error && /incorrect header|invalid|unexpected end/i.test(err.message)) {
        reject(new FetchStop("extraction_failed", "decompression_failed", "Compressed body could not be decoded"));
      } else reject(err);
    };
    for (const s of stages) s.on("error", onError);
    stream.on("data", (c: Buffer) => chunks.push(c));
    stream.on("end", () => {
      if (done) return;
      done = true;
      resolve(Buffer.concat(chunks));
    });
  });
}

function parseContentType(header: string | undefined): { mime: string; charset: string | null } {
  const [mime = "", ...params] = (header ?? "").split(";").map((p) => p.trim());
  const charset = params.find((p) => p.toLowerCase().startsWith("charset="))?.slice(8).replace(/["']/g, "") ?? null;
  return { mime: mime.toLowerCase(), charset };
}

function decodeText(body: Buffer, charset: string | null, html: boolean, warnings: string[]): string {
  let label = charset;
  if (!label && html) {
    const meta = /<meta[^>]+charset=["']?([\w-]+)/i.exec(body.subarray(0, 2048).toString("latin1"));
    label = meta?.[1] ?? null;
  }
  label ??= "utf-8";
  let decoder: TextDecoder;
  try {
    decoder = new TextDecoder(label, { fatal: true });
  } catch {
    warnings.push(`unknown_charset_${label.toLowerCase()}_decoded_as_utf8`);
    decoder = new TextDecoder("utf-8", { fatal: true });
  }
  try {
    return decoder.decode(body);
  } catch {
    warnings.push("invalid_byte_sequence_replaced");
    return new TextDecoder(decoder.encoding).decode(body);
  }
}

const ENTITIES: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };

function decodeEntities(s: string): string {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e: string) => {
    if (e[0] === "#") {
      const cp = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : m;
    }
    return ENTITIES[e.toLowerCase()] ?? m;
  });
}

export function extractHtml(html: string): { title: string | null; text: string } {
  const titleMatch = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(html);
  const title = titleMatch ? decodeEntities(titleMatch[1]!.replace(/\s+/g, " ").trim()) || null : null;
  const text = decodeEntities(
    html
      .replace(/<!--[\s\S]*?-->/g, " ")
      .replace(/<(script|style|noscript|template|svg|iframe|object)\b[\s\S]*?<\/\1\s*>/gi, " ")
      .replace(/<head\b[\s\S]*?<\/head\s*>/i, " ")
      .replace(/<(br|p|div|li|h[1-6]|tr|section|article|header|footer|blockquote|pre)\b[^>]*>/gi, "\n")
      .replace(/<[^>]+>/g, " "),
  )
    .replace(/[ \t\f\v\r]+/g, " ")
    .replace(/ *\n */g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
  return { title, text };
}

/** Tool status for a classified response (shared with the browser). */
export function statusForChallenge(httpStatus: number, challenge: ChallengeResult): Status {
  switch (challenge.challenge_type) {
    case "captcha":
    case "login_required":
    case "unknown":
      return "human_verification_required";
    case "rate_limited":
      return "rate_limited";
    case "robots_or_policy_block":
      return "blocked";
    case "none":
      if (httpStatus >= 200 && httpStatus < 300) return "success";
      return httpStatus >= 500 ? "provider_unavailable" : "blocked";
  }
}

/**
 * Bounded, read-only retrieval of a single public page. Every hop is validated
 * (URL policy -> DNS answers -> pinned connect -> peer check) before any request
 * bytes are sent. Callers cannot loosen the policy through tool input.
 *
 * `disclosure` only decides how URLs appear in the result (origin by default);
 * nothing on the network path reads it.
 */
export async function fetchPublicPage(
  rawUrl: string,
  policy: FetchPolicy = DEFAULT_FETCH_POLICY,
  deps: FetchDeps = DEFAULT_FETCH_DEPS,
  disclosure: UrlDisclosure = ORIGIN_ONLY,
): Promise<FetchResult> {
  const requestId = newRequestId();
  const started = Date.now();
  const redirectChain: RedirectHop[] = [];
  const warnings: string[] = [];
  const base = (): Base => ({
    request_id: requestId,
    tool_version: TOOL_VERSION,
    source_url: discloseUrl(rawUrl, disclosure),
    redirect_chain: redirectChain,
    warnings,
  });

  const controller = new AbortController();
  const deadline = setTimeout(() => controller.abort(), policy.totalTimeoutMs);
  let current = rawUrl;
  const seen = new Set<string>();

  try {
    for (let hop = 0; ; hop++) {
      const check = validateUrl(current, policy);
      if (!check.ok) throw new FetchStop(check.status, check.code, hop === 0 ? check.message : `Redirect target rejected: ${check.message}`);
      const key = check.url.toString();
      if (seen.has(key)) throw new FetchStop("blocked", "redirect_loop", "Redirect loop detected");
      seen.add(key);

      const pinned = await resolveAndValidate(check.hostname, check.ipLiteral, policy, deps);
      if (controller.signal.aborted) throw new FetchStop("timeout", "total_timeout", "Overall deadline exceeded");
      const { res, peer, abort } = await requestHop(check.url, check.hostname, check.port, pinned, policy, deps, controller.signal);
      const httpStatus = res.statusCode ?? 0;

      if (REDIRECT_STATUSES.has(httpStatus)) {
        const location = res.headers.location;
        res.destroy();
        if (!location) throw new FetchStop("extraction_failed", "redirect_without_location", "Redirect response has no Location");
        redirectChain.push({ url: discloseUrl(key, disclosure), http_status: httpStatus, peer_address: peer });
        if (redirectChain.length > policy.maxRedirects) throw new FetchStop("blocked", "too_many_redirects", "Redirect limit exceeded");
        try {
          current = new URL(location, check.url).toString();
        } catch {
          throw new FetchStop("invalid_input", "redirect_unparseable", "Redirect target could not be parsed");
        }
        continue;
      }

      const { mime, charset } = parseContentType(res.headers["content-type"]);
      const headers = redactHeaders(res.headers);
      const isText = policy.allowedContentTypes.has(mime);
      if (!isText && httpStatus >= 200 && httpStatus < 300) {
        abort(new Error("unsupported content type"));
        throw new FetchStop("policy_denied", "content_type_not_allowed", `Content type ${mime || "(none)"} is not allowed`);
      }

      let body: Buffer;
      try {
        body = isText ? await readBody(res, policy) : Buffer.alloc(0);
      } catch (err) {
        abort(err instanceof Error ? err : new Error(String(err)));
        throw err;
      }
      if (!isText) res.destroy();

      const html = mime !== "text/plain";
      const decoded = isText ? decodeText(body, charset, html, warnings) : "";
      const { title, text } = html ? extractHtml(decoded) : { title: null, text: decoded.trim() };
      const truncated = text.length > policy.maxTextChars;
      if (truncated) warnings.push("extracted_text_truncated");

      const challenge = classifyChallenge({ httpStatus, headers, ...(title ? { title } : {}), body: decoded.slice(0, 20_000) });
      const status = statusForChallenge(httpStatus, challenge);
      const retrievedAt = deps.now().toISOString();
      // Hash basis is declared; it covers the full decoded body even if text was truncated.
      const contentHash = sha256(body, "decoded_body_bytes");
      // The stored object is exactly the hashed bytes; the store re-checks the declared hash.
      // A body that was not read (disallowed type on an error status) is never stored as if it were the response.
      const sink = deps.evidence ?? NO_EVIDENCE;
      const evidence: EvidenceOutcome =
        isText || sink === NO_EVIDENCE
          ? await sink.persist(
              body,
              { kind: "http_response_body", media_type: mime || "application/octet-stream", basis: "decoded_body_bytes", source_url: key, request_id: requestId, captured_at: retrievedAt, http_status: httpStatus },
              contentHash,
            )
          : { evidence_status: "failed", evidence_persisted: false, evidence_error: toolError("evidence_unavailable", "evidence_body_not_read", "The response body was not read, so there is nothing to persist") };
      if (evidence.evidence_status === "failed") warnings.push("evidence_not_persisted");
      const result: FetchSuccess = {
        ...base(),
        status: status as FetchSuccess["status"],
        final_url: discloseUrl(key, disclosure),
        title,
        retrieved_at: retrievedAt,
        content_type: mime,
        http_status: httpStatus,
        // Untrusted page content: data only, never instructions.
        extracted_text: truncated ? text.slice(0, policy.maxTextChars) : text,
        text_truncated: truncated,
        content_hash: contentHash,
        challenge,
        challenge_type: challenge.challenge_type,
        evidence_persisted: evidence.evidence_persisted,
        evidence_status: evidence.evidence_status,
        ...(evidence.evidence_status === "persisted" ? { evidence_id: evidence.evidence_id } : {}),
        ...(evidence.evidence_status === "failed" ? { evidence_error: evidence.evidence_error } : {}),
      };
      if (status !== "success") {
        result.error = toolError(status, challenge.challenge_type === "none" ? `http_${httpStatus}` : challenge.challenge_type, challenge.recommended_action);
      }
      // Logs carry origins only: a path or query can hold a secret, and request_id ties the line to the full result.
      deps.log({ event: "fetch", request_id: requestId, origin: redactUrl(rawUrl, "origin"), final_origin: redactUrl(key, "origin"), status, http_status: httpStatus, peer, redirects: redirectChain.length, duration_ms: Date.now() - started });
      return result;
    }
  } catch (err) {
    let stop: FetchStop;
    if (err instanceof FetchStop) stop = err;
    else if (controller.signal.aborted) stop = new FetchStop("timeout", "total_timeout", "Overall deadline exceeded");
    else if (err instanceof Error && "code" in err && typeof err.code === "string" && /^(ERR_TLS|CERT_|UNABLE_TO|DEPTH_ZERO|SELF_SIGNED|ERR_SSL)/.test(err.code)) {
      stop = new FetchStop("policy_denied", "tls_verification_failed", "TLS certificate verification failed");
    } else stop = new FetchStop("provider_unavailable", "connection_failed", "Connection to the destination failed");
    deps.log({ event: "fetch", request_id: requestId, origin: redactUrl(rawUrl, "origin"), status: stop.status, code: stop.code, redirects: redirectChain.length, duration_ms: Date.now() - started });
    return { ...base(), status: stop.status, error: toolError(stop.status, stop.code, stop.message) };
  } finally {
    clearTimeout(deadline);
  }
}
