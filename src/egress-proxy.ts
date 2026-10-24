import { randomBytes, timingSafeEqual } from "node:crypto";
import http from "node:http";
import type { AddressInfo, Socket } from "node:net";
import type { Duplex } from "node:stream";
import { connectPinned, FetchStop, type ResolvedAddress } from "./fetcher.js";
import type { AuditLogger } from "./result.js";
import { DEFAULT_URL_POLICY, EMPTY_HOST_ALLOWLIST, isUrlHostListed, redactUrl, validateUrl, type HostAllowlist, type UrlPolicy } from "./security.js";

/**
 * Local forward proxy that is the browser's only route to the network. Chromium
 * is started with --proxy-server pointing here (and no loopback bypass), so every
 * request it makes, including redirects, subresources and background fetches,
 * passes the same checks as research.fetch_public_page:
 *
 *   URL policy (scheme, port, credentials, host allowlist)
 *     -> every DNS answer -> connect to the validated address -> peer check
 *
 * Plain HTTP is forwarded with the method checked; HTTPS arrives as CONNECT and
 * is relayed as an opaque tunnel. TLS is never terminated here: the browser
 * verifies the destination certificate itself. The proxy listens on 127.0.0.1
 * and requires per-proxy random credentials, so other local processes and page
 * content cannot use it.
 */

export interface EgressPolicy extends UrlPolicy {
  connectTimeoutMs: number;
  /** A relayed connection with no traffic for this long is closed. */
  idleTimeoutMs: number;
  /** Body bytes relayed for one plain-HTTP response. */
  maxResponseBytes: number;
  /** Bytes relayed in both directions over the proxy's lifetime (one browser session). */
  maxSessionBytes: number;
  maxConnections: number;
  /**
   * Methods allowed on plain-HTTP requests. Tunnels are opaque, so for HTTPS the
   * browser layer enforces the same rule on each request before it is sent.
   */
  allowedMethods: ReadonlySet<string>;
  /** Hosts where other methods (form posts) are allowed too. Empty by default. */
  formSubmitHosts: HostAllowlist;
}

export const DEFAULT_EGRESS_POLICY: EgressPolicy = {
  ...DEFAULT_URL_POLICY,
  connectTimeoutMs: 5_000,
  idleTimeoutMs: 60_000,
  maxResponseBytes: 10 * 1024 * 1024,
  maxSessionBytes: 200 * 1024 * 1024,
  maxConnections: 64,
  allowedMethods: new Set(["GET", "HEAD"]),
  formSubmitHosts: EMPTY_HOST_ALLOWLIST,
};

export interface EgressDeps {
  resolve: (hostname: string) => Promise<ResolvedAddress[]>;
  log: AuditLogger;
}

export interface EgressDiagnostic {
  /** Increases by one per diagnostic event over the proxy's lifetime. */
  seq: number;
  /** Origin only; never a path or query. */
  origin: string;
  code: string;
  kind: "error" | "deny";
  at: string;
}

export interface EgressDenial extends EgressDiagnostic {
  kind: "deny";
}

export interface EgressProxy {
  readonly host: "127.0.0.1";
  readonly port: number;
  readonly username: string;
  readonly password: string;
  /** The most recent policy denials (at most 50), newest last. */
  denials(): readonly EgressDenial[];
  /**
   * The most recent denials and errors, in seq order. Each kind keeps its own
   * newest 50, so a burst of errors never pushes a denial out.
   */
  events(): readonly EgressDiagnostic[];
  bytesRelayed(): number;
  close(): Promise<void>;
}

export const DENIAL_HEADER = "x-research-browser-denial";
/** Set on plain-HTTP error replies the proxy writes itself (never on a destination's reply). */
export const PROXY_ERROR_HEADER = "x-research-browser-proxy-error";

const HOP_BY_HOP = new Set(["connection", "keep-alive", "proxy-authorization", "proxy-authenticate", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade"]);

function forwardHeaders(headers: http.IncomingHttpHeaders): http.OutgoingHttpHeaders {
  const listed = new Set(
    String(headers.connection ?? "")
      .split(",")
      .map((h) => h.trim().toLowerCase())
      .filter(Boolean),
  );
  const out: http.OutgoingHttpHeaders = {};
  for (const [k, v] of Object.entries(headers)) {
    if (v === undefined || HOP_BY_HOP.has(k) || listed.has(k)) continue;
    out[k] = v;
  }
  return out;
}

// host:port, or [v6]:port. No userinfo, path or extra colons.
const CONNECT_TARGET = /^(\[[0-9a-fA-F:.]+\]|[^\s/@:[\]?#\\%]+):(\d{1,5})$/;

export async function startEgressProxy(policy: EgressPolicy, deps: EgressDeps): Promise<EgressProxy> {
  const username = "rbmcp";
  const password = randomBytes(24).toString("base64url");
  const expected = Buffer.from(`Basic ${Buffer.from(`${username}:${password}`).toString("base64")}`);
  const recentDenials: EgressDenial[] = [];
  const recentErrors: EgressDiagnostic[] = [];
  const open = new Set<Duplex>();
  let relayed = 0;
  let seq = 0;
  let closed = false;

  const authorized = (header: string | undefined): boolean => {
    if (!header) return false;
    const got = Buffer.from(header);
    return got.length === expected.length && timingSafeEqual(got, expected);
  };

  const track = (s: Duplex) => {
    open.add(s);
    s.once("close", () => open.delete(s));
  };

  const record = (origin: string, code: string, kind: "error" | "deny") => {
    const event = { seq: ++seq, origin, code, at: new Date().toISOString() };
    const buffer: EgressDiagnostic[] = kind === "deny" ? recentDenials : recentErrors;
    buffer.push({ ...event, kind });
    if (buffer.length > 50) buffer.shift();
    deps.log({ event: "egress", decision: kind, kind, origin, code });
  };
  const deny = (origin: string, code: string) => record(origin, code, "deny");

  /** Counts relayed bytes; once the session budget is spent every open connection is closed. */
  const count = (n: number) => {
    relayed += n;
    if (relayed > policy.maxSessionBytes) {
      for (const s of open) s.destroy();
    }
  };

  /**
   * Records `upstream_error` once per admitted connection when the destination
   * side fails before the response or tunnel ended normally. Closes this proxy
   * caused itself (idle timeout, byte limits, shutdown) are not errors.
   */
  const upstreamFailure = (origin: string) => {
    let settled = false;
    return {
      quiet: () => {
        settled = true;
      },
      fail: () => {
        if (settled || closed || relayed > policy.maxSessionBytes) return;
        settled = true;
        record(origin, "upstream_error", "error");
      },
    };
  };

  /** Shared checks for both request kinds. Returns the connected upstream socket or a denial. */
  const admit = async (target: string, method: string | null): Promise<{ socket: Socket; origin: string } | { status: number; code: string; origin: string; kind: "error" | "deny" }> => {
    const origin = redactUrl(target, "origin");
    if (closed) return { status: 503, code: "proxy_closed", origin, kind: "error" };
    const check = validateUrl(target, policy);
    if (!check.ok) {
      deny(origin, check.code);
      return { status: check.status === "invalid_input" ? 400 : 403, code: check.code, origin, kind: "deny" };
    }
    if (method !== null && !policy.allowedMethods.has(method) && !isUrlHostListed(check.url, policy.formSubmitHosts)) {
      deny(origin, "method_not_allowed");
      return { status: 403, code: "method_not_allowed", origin, kind: "deny" };
    }
    if (relayed >= policy.maxSessionBytes) {
      deny(origin, "session_byte_budget_exceeded");
      return { status: 403, code: "session_byte_budget_exceeded", origin, kind: "deny" };
    }
    try {
      const { socket, peer } = await connectPinned(check.hostname, check.ipLiteral, check.port, policy, deps, policy.connectTimeoutMs);
      deps.log({ event: "egress", decision: "allow", origin, peer, transport: method === null ? "tunnel" : "http" });
      return { socket, origin };
    } catch (err) {
      const stop = err instanceof FetchStop ? err : new FetchStop("provider_unavailable", "connection_failed", "Connection failed");
      if (stop.status === "policy_denied") deny(origin, stop.code);
      else record(origin, stop.code, "error");
      return { status: stop.status === "policy_denied" ? 403 : stop.status === "timeout" ? 504 : 502, code: stop.code, origin, kind: stop.status === "policy_denied" ? "deny" : "error" };
    }
  };

  const rawReply = (socket: Duplex, status: number, reason: string, extra: Record<string, string> = {}) => {
    const lines = [`HTTP/1.1 ${status} ${reason}`, "content-length: 0", "connection: close", ...Object.entries(extra).map(([k, v]) => `${k}: ${v}`)];
    socket.end(`${lines.join("\r\n")}\r\n\r\n`);
  };

  const server = http.createServer();
  server.maxConnections = policy.maxConnections;
  server.on("connection", (s: Socket) => track(s));

  server.on("request", (req: http.IncomingMessage, res: http.ServerResponse) => {
    void (async () => {
      if (!authorized(req.headers["proxy-authorization"])) {
        res.writeHead(407, { "proxy-authenticate": 'Basic realm="research-browser"', connection: "close", "content-length": 0 });
        res.end();
        return;
      }
      const target = req.url ?? "";
      if (!/^http:\/\//i.test(target)) {
        res.writeHead(400, { connection: "close", "content-length": 0 });
        res.end();
        return;
      }
      const method = (req.method ?? "GET").toUpperCase();
      const admitted = await admit(target, method);
      if ("status" in admitted) {
        res.writeHead(admitted.status, { [admitted.kind === "deny" ? DENIAL_HEADER : PROXY_ERROR_HEADER]: admitted.code, "content-type": "text/plain", connection: "close" });
        res.end(`Blocked by research-browser policy: ${admitted.code}\n`);
        req.resume();
        return;
      }
      const url = new URL(target);
      const upstreamSocket = admitted.socket;
      track(upstreamSocket);
      const failure = upstreamFailure(admitted.origin);
      upstreamSocket.setTimeout(policy.idleTimeoutMs, () => {
        failure.quiet();
        upstreamSocket.destroy();
      });
      const upstream = http.request({
        method,
        path: `${url.pathname}${url.search}`,
        headers: { ...forwardHeaders(req.headers), host: url.host, connection: "close" },
        createConnection: () => upstreamSocket,
      });
      upstream.on("error", () => {
        failure.fail();
        if (!res.headersSent) {
          res.writeHead(502, { [PROXY_ERROR_HEADER]: "upstream_error", connection: "close", "content-length": 0 });
          res.end();
        } else res.destroy();
      });
      upstream.on("response", (up) => {
        const headers = forwardHeaders(up.headers);
        // Only this proxy may say a request was denied by policy or failed at the proxy.
        delete headers[DENIAL_HEADER];
        delete headers[PROXY_ERROR_HEADER];
        res.writeHead(up.statusCode ?? 502, headers);
        let body = 0;
        up.on("data", (chunk: Buffer) => {
          body += chunk.length;
          count(chunk.length);
          if (body > policy.maxResponseBytes) {
            deny(admitted.origin, "response_too_large");
            failure.quiet();
            up.destroy();
            res.destroy();
            return;
          }
          res.write(chunk);
        });
        up.on("end", () => {
          failure.quiet();
          res.end();
        });
        up.on("error", () => {
          failure.fail();
          res.destroy();
        });
        up.on("aborted", () => {
          failure.fail();
          res.destroy();
        });
      });
      req.on("data", (chunk: Buffer) => count(chunk.length));
      req.pipe(upstream);
    })().catch(() => res.destroy());
  });

  server.on("connect", (req: http.IncomingMessage, client: Duplex, head: Buffer) => {
    track(client);
    client.on("error", () => client.destroy());
    void (async () => {
      if (!authorized(req.headers["proxy-authorization"])) {
        rawReply(client, 407, "Proxy Authentication Required", { "proxy-authenticate": 'Basic realm="research-browser"' });
        return;
      }
      const m = CONNECT_TARGET.exec(req.url ?? "");
      if (!m) {
        rawReply(client, 400, "Bad Request");
        return;
      }
      // A tunnel carries TLS, so it is judged as the https URL it will fetch.
      const admitted = await admit(`https://${m[1]}:${m[2]}/`, null);
      if ("status" in admitted) {
        rawReply(client, admitted.status, admitted.status === 403 ? "Forbidden" : "Bad Gateway", admitted.kind === "deny" ? { [DENIAL_HEADER]: admitted.code } : {});
        return;
      }
      const upstream = admitted.socket;
      track(upstream);
      if (client.destroyed) {
        upstream.destroy();
        return;
      }
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length) {
        count(head.length);
        upstream.write(head);
      }
      const failure = upstreamFailure(admitted.origin);
      const idle = () => {
        failure.quiet();
        upstream.destroy();
        client.destroy();
      };
      upstream.setTimeout(policy.idleTimeoutMs, idle);
      upstream.on("data", (d: Buffer) => {
        // Once the destination has sent bytes, a reset cannot be told apart from the
        // end of a normal exchange inside an opaque tunnel, so it is not an error.
        failure.quiet();
        count(d.length);
      });
      client.on("data", (d: Buffer) => count(d.length));
      upstream.on("error", () => {
        failure.fail();
        client.destroy();
      });
      upstream.on("close", () => client.destroy());
      client.on("close", () => upstream.destroy());
      upstream.pipe(client);
      client.pipe(upstream);
    })().catch(() => client.destroy());
  });

  server.on("upgrade", (req: http.IncomingMessage, socket: Duplex) => {
    track(socket);
    deny(redactUrl(req.url ?? "", "origin"), "upgrade_not_allowed");
    rawReply(socket, 403, "Forbidden", { [DENIAL_HEADER]: "upgrade_not_allowed" });
  });

  server.on("clientError", (_err, socket: Duplex) => {
    if (!socket.destroyed) rawReply(socket, 400, "Bad Request");
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const port = (server.address() as AddressInfo).port;

  return {
    host: "127.0.0.1",
    port,
    username,
    password,
    denials: () => [...recentDenials],
    events: () => [...recentDenials, ...recentErrors].sort((a, b) => a.seq - b.seq),
    bytesRelayed: () => relayed,
    close: () =>
      new Promise<void>((resolve) => {
        closed = true;
        for (const s of open) s.destroy();
        server.close(() => resolve());
      }),
  };
}
