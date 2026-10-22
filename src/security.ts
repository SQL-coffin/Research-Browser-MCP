import { createHash } from "node:crypto";
import { isIP } from "node:net";

// ---------------------------------------------------------------------------
// IP address policy
// ---------------------------------------------------------------------------

export type AddressVerdict = { allowed: true } | { allowed: false; reason: string };

interface Prefix {
  bytes: number[];
  prefix: number;
}

interface Range extends Prefix {
  reason: string;
}

function v4(cidr: string, reason = ""): Range {
  const [addr, prefix] = cidr.split("/") as [string, string];
  return { bytes: addr.split(".").map(Number), prefix: Number(prefix), reason };
}

function v6(cidr: string, reason = ""): Range {
  const [addr, prefix] = cidr.split("/") as [string, string];
  const bytes = parseIPv6(addr);
  if (!bytes) throw new Error(`bad IPv6 range ${cidr}`);
  return { bytes, prefix: Number(prefix), reason };
}

// Allowlist: an address can only pass if it lies in global unicast space.
// IPv4: everything below 224.0.0.0 (multicast 224/4 and reserved 240/4 are outside).
// IPv6: 2000::/3, the only block IANA allocates as global unicast. The rest of the
// IPv6 space (4000::/3, 8000::/1, ...) is denied without having to be enumerated.
const GLOBAL_UNICAST_V4: Prefix[] = [v4("0.0.0.0/1"), v4("128.0.0.0/2"), v4("192.0.0.0/3")];
const GLOBAL_UNICAST_V6: Prefix[] = [v6("2000::/3")];

// Special-purpose blocks (IANA registries plus cloud metadata endpoints) that are
// denied even inside global unicast space. Entries outside that space are denied
// anyway; they are listed so the denial reason is specific.
const SPECIAL_V4: Range[] = [
  v4("0.0.0.0/8", "unspecified"),
  v4("10.0.0.0/8", "private"),
  v4("100.64.0.0/10", "carrier_grade_nat"), // also covers 100.100.100.200 (Alibaba metadata)
  v4("127.0.0.0/8", "loopback"),
  v4("169.254.0.0/16", "link_local"), // also covers 169.254.169.254 (AWS/GCP/Azure metadata)
  v4("172.16.0.0/12", "private"),
  v4("192.0.0.0/24", "reserved"),
  v4("192.0.2.0/24", "documentation"),
  v4("192.31.196.0/24", "reserved"),
  v4("192.52.193.0/24", "reserved"),
  v4("192.88.99.0/24", "reserved"),
  v4("192.168.0.0/16", "private"),
  v4("192.175.48.0/24", "reserved"),
  v4("198.18.0.0/15", "benchmarking"),
  v4("198.51.100.0/24", "documentation"),
  v4("203.0.113.0/24", "documentation"),
  v4("224.0.0.0/4", "multicast"),
  v4("240.0.0.0/4", "reserved"), // includes 255.255.255.255 broadcast
];

const SPECIAL_V6: Range[] = [
  v6("::/96", "unspecified_or_ipv4_compatible"), // ::, ::1 handled below, ::a.b.c.d
  v6("::1/128", "loopback"),
  v6("64:ff9b::/96", "nat64"),
  v6("64:ff9b:1::/48", "nat64"),
  v6("100::/64", "discard"),
  v6("2001::/23", "reserved"), // includes Teredo 2001::/32
  v6("2001:db8::/32", "documentation"),
  v6("2002::/16", "6to4"),
  v6("3fff::/20", "documentation"),
  v6("5f00::/16", "reserved"),
  v6("fc00::/7", "unique_local"), // includes fd00:ec2::254 (AWS IMDS IPv6)
  v6("fe80::/10", "link_local"),
  v6("fec0::/10", "site_local"),
  v6("ff00::/8", "multicast"),
];

function inRange(bytes: number[], range: Prefix): boolean {
  let bits = range.prefix;
  for (let i = 0; bits > 0; i++, bits -= 8) {
    const mask = bits >= 8 ? 0xff : (0xff << (8 - bits)) & 0xff;
    if (((bytes[i] ?? 0) & mask) !== ((range.bytes[i] ?? 0) & mask)) return false;
  }
  return true;
}

function parseIPv4(addr: string): number[] | null {
  if (isIP(addr) !== 4) return null;
  return addr.split(".").map(Number);
}

/** Expands an IPv6 literal (optionally with embedded IPv4 and zone id) to 16 bytes. */
export function parseIPv6(input: string): number[] | null {
  let addr = input.replace(/^\[|\]$/g, "");
  const zone = addr.indexOf("%");
  if (zone !== -1) addr = addr.slice(0, zone);
  if (isIP(addr) !== 6) return null;

  let tail: number[] = [];
  const lastColon = addr.lastIndexOf(":");
  const maybeV4 = addr.slice(lastColon + 1);
  if (maybeV4.includes(".")) {
    const v4bytes = parseIPv4(maybeV4);
    if (!v4bytes) return null;
    tail = v4bytes;
    addr = addr.slice(0, lastColon + 1) + "0:0";
  }

  const [head = "", rest] = addr.split("::") as [string, string | undefined];
  const headGroups = head ? head.split(":") : [];
  const restGroups = rest ? rest.split(":") : [];
  const missing = 8 - headGroups.length - restGroups.length;
  const groups =
    rest === undefined ? headGroups : [...headGroups, ...Array<string>(missing).fill("0"), ...restGroups];
  if (groups.length !== 8) return null;

  const bytes: number[] = [];
  for (const g of groups) {
    const n = parseInt(g, 16);
    bytes.push((n >> 8) & 0xff, n & 0xff);
  }
  if (tail.length === 4) bytes.splice(12, 4, ...tail);
  return bytes;
}

/** Returns the embedded IPv4 address of an IPv4-mapped IPv6 address (::ffff:a.b.c.d), if any. */
function mappedIPv4(bytes: number[]): number[] | null {
  for (let i = 0; i < 10; i++) if (bytes[i] !== 0) return null;
  if (bytes[10] !== 0xff || bytes[11] !== 0xff) return null;
  return bytes.slice(12);
}

function judge(bytes: number[], globalUnicast: Prefix[], special: Range[]): AddressVerdict {
  // Longest-prefix match so ::1 reports "loopback" rather than the broader ::/96.
  const hit = special.filter((r) => inRange(bytes, r)).sort((a, b) => b.prefix - a.prefix)[0];
  if (hit) return { allowed: false, reason: hit.reason };
  return globalUnicast.some((p) => inRange(bytes, p)) ? { allowed: true } : { allowed: false, reason: "not_global_unicast" };
}

/**
 * Default destination policy: an address is allowed only if it is global unicast
 * (see GLOBAL_UNICAST_*) and outside every special-purpose block. IPv4-mapped IPv6
 * addresses (::ffff:a.b.c.d) are judged by their embedded IPv4 address.
 */
export function classifyAddress(ip: string): AddressVerdict {
  const b4 = parseIPv4(ip);
  if (b4) return judge(b4, GLOBAL_UNICAST_V4, SPECIAL_V4);
  const b6 = parseIPv6(ip);
  if (!b6) return { allowed: false, reason: "not_an_ip_address" };
  const mapped = mappedIPv4(b6);
  if (mapped) return classifyAddress(mapped.join("."));
  return judge(b6, GLOBAL_UNICAST_V6, SPECIAL_V6);
}

/** Canonical textual form used to compare a validated address with the connected peer. */
export function canonicalAddress(ip: string): string | null {
  const b4 = parseIPv4(ip);
  if (b4) return b4.join(".");
  const b6 = parseIPv6(ip);
  if (!b6) return null;
  const mapped = mappedIPv4(b6);
  if (mapped) return mapped.join(".");
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) groups.push((((b6[i] ?? 0) << 8) | (b6[i + 1] ?? 0)).toString(16));
  return groups.join(":");
}

/**
 * Applies an address policy to the canonical spelling of `ip`. The URL, DNS and
 * peer checks all go through here, so one policy sees identical strings at every
 * layer (e.g. "::ffff:7f00:1" and "127.0.0.1" are both judged as "127.0.0.1").
 */
export function checkAddress(ip: string, policy: Pick<UrlPolicy, "isAddressAllowed">): AddressVerdict {
  const canonical = canonicalAddress(ip);
  return canonical === null ? { allowed: false, reason: "not_an_ip_address" } : policy.isAddressAllowed(canonical);
}

// ---------------------------------------------------------------------------
// Host allowlist (startup configuration only)
// ---------------------------------------------------------------------------

export interface HostAllowlist {
  /** Normalized host names and canonical IP addresses; matched exactly. */
  readonly exact: ReadonlySet<string>;
  /** Parents from "*.parent" entries: any strict subdomain matches, the parent itself does not. */
  readonly subdomainsOf: readonly string[];
}

/** The default: nothing may be fetched until hosts are configured at startup. */
export const EMPTY_HOST_ALLOWLIST: HostAllowlist = { exact: new Set(), subdomainsOf: [] };

export class HostAllowlistError extends Error {}

const HOST_LABEL = /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/;

/** A normalized (lower-case, Punycode) host name with at least two labels and no empty or malformed label. */
function isValidHostName(host: string): boolean {
  const labels = host.split(".");
  return host.length <= 253 && labels.length >= 2 && labels.every((label) => HOST_LABEL.test(label));
}

/**
 * Normalizes a configured host name exactly as request URLs are normalized
 * (WHATWG URL: UTS #46 mapping, Punycode, lower case), minus one trailing dot.
 * Returns null unless the result is a valid multi-label host name.
 */
function normalizeHostEntry(entry: string): string | null {
  // A scheme, port, path, userinfo, IPv6 literal or percent-escape means this is not a bare host name.
  if (!entry || /[/\\?#@:%[\]]/.test(entry)) return null;
  let host: string;
  try {
    host = new URL(`https://${entry}/`).hostname.replace(/\.$/, "");
  } catch {
    return null;
  }
  return !isIP(host) && isValidHostName(host) ? host : null;
}

/**
 * Parses the startup host allowlist. Entries are separated by commas or whitespace:
 *   example.org     exactly this host, after normalization (case, trailing dot, IDN to Punycode)
 *   *.example.org   any subdomain of example.org at a label boundary, but not example.org itself
 *   93.184.215.14, 2606:4700::1111 or [2606:4700::1111]   exactly this IP address
 * "*.org" and other single-label parents are rejected. Invalid entries throw
 * HostAllowlistError, which names their positions but not their text, since a
 * misplaced URL could carry credentials.
 */
export function parseHostAllowlist(spec: string): HostAllowlist {
  const exact = new Set<string>();
  const subdomainsOf = new Set<string>();
  const invalid: number[] = [];
  spec
    .split(/[\s,]+/)
    .filter(Boolean)
    .forEach((entry, i) => {
      const ip = entry.replace(/^\[(.*)\]$/, "$1");
      if (entry.startsWith("*.")) {
        const parent = normalizeHostEntry(entry.slice(2));
        if (parent) subdomainsOf.add(parent);
        else invalid.push(i + 1);
      } else if (isIP(ip)) {
        exact.add(canonicalAddress(ip)!);
      } else {
        const host = normalizeHostEntry(entry);
        if (host) exact.add(host);
        else invalid.push(i + 1);
      }
    });
  if (invalid.length > 0) {
    throw new HostAllowlistError(
      `Invalid host allowlist entr${invalid.length === 1 ? "y" : "ies"} at position ${invalid.join(", ")}. ` +
        'Use bare host names ("example.org"), "*.example.org" for subdomains, or IP addresses; no scheme, port, path or credentials.',
    );
  }
  return { exact, subdomainsOf: [...subdomainsOf] };
}

export function isHostAllowlistEmpty(allowlist: HostAllowlist): boolean {
  return allowlist.exact.size === 0 && allowlist.subdomainsOf.length === 0;
}

/** `host` must be a normalized host name (as validateUrl produces) or a canonical IP address. */
export function isHostAllowlisted(host: string, allowlist: HostAllowlist): boolean {
  if (allowlist.exact.has(host)) return true;
  // Wildcards cover host names only, and match only below a label boundary.
  return !isIP(host) && allowlist.subdomainsOf.some((parent) => host.endsWith(`.${parent}`));
}

// ---------------------------------------------------------------------------
// URL policy
// ---------------------------------------------------------------------------

export const MAX_URL_LENGTH = 2048;

export interface UrlPolicy {
  allowedSchemes: ReadonlySet<string>;
  allowedPorts: ReadonlySet<number>;
  /** Hosts that may be fetched. Set only from startup configuration; empty denies everything. */
  allowedHosts: HostAllowlist;
  /**
   * The single destination-address policy. It judges IP-literal hosts here and,
   * in the fetcher, every DNS answer and the connected peer.
   */
  isAddressAllowed: (ip: string) => AddressVerdict;
}

export const DEFAULT_URL_POLICY: UrlPolicy = {
  allowedSchemes: new Set(["https:"]),
  allowedPorts: new Set([443]),
  allowedHosts: EMPTY_HOST_ALLOWLIST,
  isAddressAllowed: classifyAddress,
};

const BLOCKED_HOST_SUFFIXES = [".localhost", ".local", ".internal", ".home.arpa", ".lan", ".intranet", ".corp"];

export type UrlCheck =
  | { ok: true; url: URL; hostname: string; port: number; ipLiteral: string | null }
  | { ok: false; status: "invalid_input" | "policy_denied"; code: string; message: string };

const DEFAULT_PORTS: Record<string, number> = { "https:": 443, "http:": 80 };

export function validateUrl(raw: string, policy: UrlPolicy = DEFAULT_URL_POLICY): UrlCheck {
  if (raw.length > MAX_URL_LENGTH) {
    return { ok: false, status: "invalid_input", code: "url_too_long", message: "URL exceeds maximum length" };
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, status: "invalid_input", code: "url_unparseable", message: "URL could not be parsed" };
  }
  if (!policy.allowedSchemes.has(url.protocol)) {
    return { ok: false, status: "policy_denied", code: "scheme_not_allowed", message: `Scheme ${url.protocol} is not allowed` };
  }
  if (url.username || url.password) {
    return { ok: false, status: "policy_denied", code: "url_credentials", message: "URLs with embedded credentials are not allowed" };
  }
  const port = url.port ? Number(url.port) : DEFAULT_PORTS[url.protocol];
  if (port === undefined || !policy.allowedPorts.has(port)) {
    return { ok: false, status: "policy_denied", code: "port_not_allowed", message: `Port ${url.port || "(default)"} is not allowed` };
  }
  // WHATWG URL already canonicalises odd IPv4 notations (0x7f.1, 2130706433) to dotted quads.
  const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
  if (!hostname) {
    return { ok: false, status: "invalid_input", code: "missing_host", message: "URL has no host" };
  }
  // The allowlist is checked last: it can only narrow what the checks above allow.
  const bare = hostname.replace(/^\[|\]$/g, "");
  if (isIP(bare)) {
    const verdict = checkAddress(bare, policy);
    if (!verdict.allowed) {
      return { ok: false, status: "policy_denied", code: `address_${verdict.reason}`, message: "Destination address is not public" };
    }
    return allowlistDenial(canonicalAddress(bare)!, policy.allowedHosts) ?? { ok: true, url, hostname: bare, port, ipLiteral: bare };
  }
  if (hostname === "localhost" || BLOCKED_HOST_SUFFIXES.some((s) => hostname.endsWith(s)) || !hostname.includes(".")) {
    return { ok: false, status: "policy_denied", code: "host_not_public", message: "Host name is not a public DNS name" };
  }
  // The URL parser accepts names such as ".example.org" or "*.example.org"; neither
  // may reach DNS or match a "*.example.org" allowlist entry.
  if (!isValidHostName(hostname)) {
    return { ok: false, status: "invalid_input", code: "invalid_host", message: "Host name is malformed" };
  }
  return allowlistDenial(hostname, policy.allowedHosts) ?? { ok: true, url, hostname, port, ipLiteral: null };
}

function allowlistDenial(host: string, allowlist: HostAllowlist): UrlCheck | null {
  if (isHostAllowlistEmpty(allowlist)) {
    return {
      ok: false,
      status: "policy_denied",
      code: "host_allowlist_empty",
      message: "No hosts are allowlisted, so nothing can be fetched; the operator configures RESEARCH_BROWSER_ALLOWED_HOSTS at startup",
    };
  }
  if (!isHostAllowlisted(host, allowlist)) {
    return { ok: false, status: "policy_denied", code: "host_not_allowlisted", message: "Host is not on the server's allowlist" };
  }
  return null;
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

const SENSITIVE_PARAM =
  /(token|key|secret|pass(word)?|pwd|auth|session|sess|sid|sig(nature)?|credential|code|jwt|bearer|cookie|otp|state|nonce|ticket)/i;

/**
 * Display-safe URL.
 *   "display": drops userinfo and fragment and masks the values of query parameters
 *              whose names look secret-bearing. Keeps the path: fetch results need
 *              it to identify the evidence.
 *   "origin":  scheme, host and port only, for logs, handoff records and challenge
 *              reports, since a path segment can carry a secret too.
 */
export function redactUrl(raw: string, mode: "display" | "origin" = "display"): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return "[unparseable-url]";
  }
  if (mode === "origin") return url.protocol === "https:" || url.protocol === "http:" ? url.origin : "[non-http-url]";
  url.username = "";
  url.password = "";
  url.hash = "";
  const params = new URLSearchParams();
  for (const [k, v] of url.searchParams) {
    params.append(k, SENSITIVE_PARAM.test(k) ? "REDACTED" : v);
  }
  url.search = params.toString();
  return url.toString();
}

const SENSITIVE_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "x-api-key",
  "x-auth-token",
  "x-amz-security-token",
]);

export function redactHeaders(headers: Record<string, string | string[] | undefined>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (v === undefined) continue;
    const name = k.toLowerCase();
    out[name] = SENSITIVE_HEADERS.has(name) || SENSITIVE_PARAM.test(name) ? "REDACTED" : Array.isArray(v) ? v.join(", ") : v;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Challenge classification (advisory only — never triggers a bypass)
// ---------------------------------------------------------------------------

export type ChallengeType = "none" | "captcha" | "login_required" | "rate_limited" | "robots_or_policy_block" | "unknown";

export interface ChallengeObservation {
  httpStatus: number;
  headers?: Record<string, string>;
  title?: string;
  /** Bounded excerpt of raw HTML or extracted text. */
  body?: string;
}

export interface ChallengeResult {
  challenge_type: ChallengeType;
  confidence: "low" | "medium" | "high";
  signals: string[];
  recommended_action: string;
  retry_after_seconds?: number;
}

const CAPTCHA_MARKERS: [RegExp, string][] = [
  [/g-recaptcha|recaptcha\/api|grecaptcha/i, "recaptcha_marker"],
  [/h-captcha|hcaptcha\.com/i, "hcaptcha_marker"],
  [/challenges\.cloudflare\.com|cf-turnstile|cf-chl-|__cf_chl_/i, "cloudflare_challenge_marker"],
  [/\bcaptcha\b/i, "captcha_word"],
  [/verify (that )?you are (a )?human|are you a robot|not a robot|human verification/i, "human_check_text"],
];

const LOGIN_MARKERS: [RegExp, string][] = [
  [/<input[^>]+type=["']?password/i, "password_field"],
  [/\b(sign|log) ?in to (continue|view|access)\b|please (sign|log) ?in\b|login required/i, "login_text"],
];

const POLICY_MARKERS: [RegExp, string][] = [
  [/access (to this (page|site|resource) )?(has been |is )?denied|request (was )?blocked|you have been blocked/i, "access_denied_text"],
  [/<meta[^>]+name=["']?robots["']?[^>]+content=["'][^"']*noarchive/i, "robots_noarchive_meta"],
];

function match(markers: [RegExp, string][], text: string): string[] {
  return markers.filter(([re]) => re.test(text)).map(([, signal]) => signal);
}

function parseRetryAfter(value: string | undefined): number | undefined {
  if (!value) return undefined;
  const secs = Number(value);
  if (Number.isFinite(secs) && secs >= 0) return Math.min(Math.round(secs), 86_400);
  const date = Date.parse(value);
  if (!Number.isNaN(date)) return Math.max(0, Math.min(Math.round((date - Date.now()) / 1000), 86_400));
  return undefined;
}

export function classifyChallenge(obs: ChallengeObservation): ChallengeResult {
  const text = `${obs.title ?? ""}\n${obs.body ?? ""}`;
  const headers = obs.headers ?? {};
  const status = obs.httpStatus;

  if (status === 429) {
    const retry = parseRetryAfter(headers["retry-after"]);
    return {
      challenge_type: "rate_limited",
      confidence: "high",
      signals: ["http_429", ...(retry !== undefined ? ["retry_after_header"] : [])],
      recommended_action: "Respect retry guidance and caller budgets; do not rotate identity to evade the limit.",
      ...(retry !== undefined ? { retry_after_seconds: retry } : {}),
    };
  }

  const captcha = match(CAPTCHA_MARKERS, text);
  const strongCaptcha = captcha.some((s) => s !== "captcha_word");
  if (strongCaptcha || (captcha.length > 0 && status >= 400)) {
    return {
      challenge_type: "captcha",
      confidence: strongCaptcha && status >= 400 ? "high" : "medium",
      signals: [...(status >= 400 ? [`http_${status}`] : []), ...captcha],
      recommended_action: "Pause for human verification through the host runtime; do not solve or bypass.",
    };
  }

  const login = match(LOGIN_MARKERS, text);
  if (status === 401 || (login.length > 0 && (status === 403 || login.includes("login_text")))) {
    return {
      challenge_type: "login_required",
      confidence: status === 401 ? "high" : "medium",
      signals: [...(status === 401 || status === 403 ? [`http_${status}`] : []), ...login],
      recommended_action: "Pause for human review or choose a different authorized public source; never reuse credentials.",
    };
  }

  const policy = match(POLICY_MARKERS, text);
  if (status === 451 || status === 403) {
    return {
      challenge_type: "robots_or_policy_block",
      confidence: status === 451 || policy.length > 0 ? "high" : "medium",
      signals: [`http_${status}`, ...policy],
      recommended_action: "Stop; the site disallows this access. Do not attempt a bypass.",
    };
  }

  // A bare mention of "captcha" on a successful page is usually an article about
  // CAPTCHAs; surface it as a signal but do not block the content.
  return {
    challenge_type: "none",
    confidence: captcha.length > 0 ? "low" : "medium",
    signals: captcha,
    recommended_action: "Continue within normal policy.",
  };
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

export type HashBasis = "decoded_body_bytes" | "extracted_text_utf8";

export interface ContentHash {
  algorithm: "sha256";
  basis: HashBasis;
  value: string;
}

export function sha256(data: Uint8Array | string, basis: HashBasis): ContentHash {
  return { algorithm: "sha256", basis, value: createHash("sha256").update(data).digest("hex") };
}
