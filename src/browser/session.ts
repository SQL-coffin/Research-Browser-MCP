import { randomUUID } from "node:crypto";
import { chromium, type Browser, type BrowserContext, type ElementHandle, type Page } from "playwright-core";
import { DEFAULT_EGRESS_POLICY, startEgressProxy, type EgressDeps, type EgressPolicy, type EgressProxy } from "../egress-proxy.js";
import type { EvidenceSink } from "../evidence.js";
import type { HandoffStore } from "../handoff.js";
import type { AuditLogger } from "../result.js";
import { isUrlHostListed, ORIGIN_ONLY, redactUrl, validateUrl, type UrlDisclosure } from "../security.js";
import type { ResolvedAddress } from "../fetcher.js";

/**
 * One browser session = one Chromium process, one fresh in-memory context and one
 * page, behind its own egress proxy:
 *
 *  - Isolation: a session shares no process, profile, cookies, cache or storage
 *    with another session; Playwright's temporary profile is deleted on close.
 *  - Network: the proxy (no loopback bypass) is the only route out, and applies
 *    the fetch policy to every connection. A request handler in the context
 *    re-checks each request's URL and method before it leaves the browser, which
 *    also covers HTTPS, where the proxy only sees a tunnel.
 *  - Off: downloads, service workers, WebSockets, popups (closed on open),
 *    dialogs (dismissed), QUIC and non-proxied WebRTC UDP.
 */

export interface BrowserConfig {
  /** Network policy for the session's proxy and request checks; the allowlist comes from startup configuration. */
  egress: EgressPolicy;
  /** Output only, as for fetch results. */
  disclosure: UrlDisclosure;
  /** false shows a window a person can use while a session is paused (needs a display). */
  headless: boolean;
  executablePath: string | null;
  chromiumSandbox: boolean;
  maxSessions: number;
  idleTimeoutMs: number;
  maxSessionMs: number;
  launchTimeoutMs: number;
  actionTimeoutMs: number;
  navigationTimeoutMs: number;
  maxTextChars: number;
  maxElements: number;
  maxNameChars: number;
  maxTypeChars: number;
  maxScreenshotBytes: number;
  viewport: { width: number; height: number };
}

export const DEFAULT_BROWSER_CONFIG: BrowserConfig = {
  egress: DEFAULT_EGRESS_POLICY,
  disclosure: ORIGIN_ONLY,
  headless: true,
  executablePath: null,
  chromiumSandbox: false,
  maxSessions: 2,
  idleTimeoutMs: 5 * 60_000,
  maxSessionMs: 30 * 60_000,
  launchTimeoutMs: 30_000,
  actionTimeoutMs: 10_000,
  navigationTimeoutMs: 20_000,
  maxTextChars: 20_000,
  maxElements: 200,
  maxNameChars: 160,
  maxTypeChars: 2_000,
  maxScreenshotBytes: 5 * 1024 * 1024,
  viewport: { width: 1280, height: 800 },
};

export interface BrowserDeps extends EgressDeps {
  resolve: (hostname: string) => Promise<ResolvedAddress[]>;
  log: AuditLogger;
  now: () => Date;
  evidence: EvidenceSink;
  handoff: HandoffStore;
  /**
   * Tests only: SPKI SHA-256 hashes (base64) of local fixture certificates that
   * Chromium should accept. Never read from the environment or tool input.
   */
  testTrustedSpki?: readonly string[];
}

export type SessionState = "ACTIVE" | "BLOCKED" | "CLOSED";

export interface SessionPause {
  pause_id: string;
  resume_handle: string;
  expires_at: string;
  reason: string;
}

/** Chromium switches applied to every session, on top of Playwright's defaults. */
export const CHROMIUM_ARGS = [
  "--disable-quic",
  "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
  "--webrtc-ip-handling-policy=disable_non_proxied_udp",
  "--disable-background-networking",
  "--disable-component-update",
  "--disable-domain-reliability",
  "--disable-sync",
  "--no-pings",
  "--no-first-run",
];

export class BrowserSession {
  readonly id = randomUUID();
  state: SessionState = "ACTIVE";
  readonly createdAt: number;
  lastUsedAt: number;
  /** Element handles of the latest snapshot, by 1-based index. */
  elements = new Map<number, ElementHandle>();
  snapshotId: string | null = null;
  /** The latest main-frame document response (any navigation, including a person's in a visible window). */
  mainResponse: { status: number; retryAfter: string | null } | null = null;
  pause: SessionPause | null = null;
  /** Requests the context refused before they reached the proxy, newest last (origins only). */
  readonly blockedRequests: { seq: number; origin: string; code: string }[] = [];
  private blockedSeq = 0;
  readonly warnings = new Set<string>();
  private queue: Promise<unknown> = Promise.resolve();
  private closing: Promise<void> | null = null;

  private constructor(
    readonly browser: Browser,
    readonly context: BrowserContext,
    readonly page: Page,
    readonly proxy: EgressProxy,
    private readonly deps: BrowserDeps,
  ) {
    this.createdAt = Date.now();
    this.lastUsedAt = this.createdAt;
  }

  static async launch(config: BrowserConfig, deps: BrowserDeps): Promise<BrowserSession> {
    const proxy = await startEgressProxy(config.egress, deps);
    let browser: Browser | null = null;
    try {
      const args = [...CHROMIUM_ARGS];
      if (deps.testTrustedSpki?.length) args.push(`--ignore-certificate-errors-spki-list=${deps.testTrustedSpki.join(",")}`);
      browser = await chromium.launch({
        headless: config.headless,
        ...(config.executablePath ? { executablePath: config.executablePath } : {}),
        chromiumSandbox: config.chromiumSandbox,
        timeout: config.launchTimeoutMs,
        // "<-loopback>" removes Chromium's implicit loopback bypass, so even
        // 127.0.0.1 and localhost go through the proxy (and are refused there).
        proxy: { server: `http://${proxy.host}:${proxy.port}`, bypass: "<-loopback>", username: proxy.username, password: proxy.password },
        args,
      });
      const context = await browser.newContext({
        acceptDownloads: false,
        serviceWorkers: "block",
        ignoreHTTPSErrors: false,
        bypassCSP: false,
        javaScriptEnabled: true,
        permissions: [],
        viewport: config.viewport,
        locale: "en-US",
      });
      context.setDefaultTimeout(config.actionTimeoutMs);
      context.setDefaultNavigationTimeout(config.navigationTimeoutMs);
      const page = await context.newPage();
      const session = new BrowserSession(browser, context, page, proxy, deps);
      await session.install(config);
      deps.log({ event: "browser_session_open", session_id: session.id, headless: config.headless });
      return session;
    } catch (err) {
      await browser?.close().catch(() => {});
      await proxy.close();
      throw err;
    }
  }

  private async install(config: BrowserConfig): Promise<void> {
    const { context, page } = this;
    // Second check inside the browser: same URL policy and allowlist, plus the
    // method rule, which the proxy cannot see inside an HTTPS tunnel.
    await context.route("**/*", async (route, request) => {
      const raw = request.url();
      const check = validateUrl(raw, config.egress);
      let code: string | null = check.ok ? null : check.code;
      if (check.ok && !config.egress.allowedMethods.has(request.method().toUpperCase()) && !isUrlHostListed(check.url, config.egress.formSubmitHosts)) {
        code = "method_not_allowed";
      }
      if (code) {
        this.recordBlocked(redactUrl(raw, "origin"), code);
        await route.abort("blockedbyclient").catch(() => {});
        return;
      }
      await route.continue().catch(() => {});
    });
    await context.routeWebSocket(/.*/, (ws) => {
      this.recordBlocked(redactUrl(ws.url().replace(/^ws/, "http"), "origin"), "websocket_not_allowed");
      void ws.close({ code: 1008, reason: "WebSockets are disabled by policy" }).catch(() => {});
    });
    context.on("page", (p) => {
      if (p !== page) {
        this.warnings.add("popup_closed");
        void p.close().catch(() => {});
      }
    });
    page.on("dialog", (d) => {
      this.warnings.add("dialog_dismissed");
      void d.dismiss().catch(() => {});
    });
    page.on("download", (d) => {
      this.warnings.add("download_refused");
      void d.cancel().catch(() => {});
    });
    page.on("response", (res) => {
      if (res.request().isNavigationRequest() && res.frame() === page.mainFrame()) {
        this.mainResponse = { status: res.status(), retryAfter: res.headers()["retry-after"] ?? null };
      }
    });
    this.browser.on("disconnected", () => {
      if (this.state !== "CLOSED") {
        this.deps.log({ event: "browser_disconnected", session_id: this.id });
        void this.close("browser_disconnected");
      }
    });
  }

  /** A getter, so callers re-read the state after an await instead of relying on narrowing. */
  get isClosed(): boolean {
    return this.state === "CLOSED";
  }

  recordBlocked(origin: string, code: string): void {
    this.blockedRequests.push({ seq: ++this.blockedSeq, origin, code });
    if (this.blockedRequests.length > 50) this.blockedRequests.shift();
    this.deps.log({ event: "browser_request_blocked", session_id: this.id, origin, code });
  }

  /** Runs `fn` after every earlier action on this session has finished. */
  run<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.queue.then(fn, fn);
    this.queue = next.catch(() => {});
    return next;
  }

  async disposeElements(): Promise<void> {
    const handles = [...this.elements.values()];
    this.elements = new Map();
    await Promise.all(handles.map((h) => h.dispose().catch(() => {})));
  }

  /** Idempotent. Closes the page, context, browser process and proxy. */
  close(reason: string): Promise<void> {
    this.closing ??= (async () => {
      this.state = "CLOSED";
      await this.disposeElements();
      await this.context.close().catch(() => {});
      await this.browser.close().catch(() => {});
      await this.proxy.close().catch(() => {});
      this.deps.log({ event: "browser_session_close", session_id: this.id, reason });
    })();
    return this.closing;
  }
}
