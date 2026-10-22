import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { canonicalAddress, classifyAddress, classifyChallenge, redactHeaders, redactUrl, sha256, validateUrl } from "../src/security.js";

describe("classifyAddress (RB-02, RB-03)", () => {
  const denied: [string, string][] = [
    ["127.0.0.1", "loopback"],
    ["127.255.255.254", "loopback"],
    ["10.1.2.3", "private"],
    ["172.16.0.1", "private"],
    ["172.31.255.255", "private"],
    ["192.168.1.1", "private"],
    ["169.254.169.254", "link_local"],
    ["100.100.100.200", "carrier_grade_nat"],
    ["0.0.0.0", "unspecified"],
    ["224.0.0.1", "multicast"],
    ["255.255.255.255", "reserved"],
    ["198.18.0.1", "benchmarking"],
    ["::1", "loopback"],
    ["::", "unspecified_or_ipv4_compatible"],
    ["fe80::1", "link_local"],
    ["fe80::1%eth0", "link_local"],
    ["fc00::1", "unique_local"],
    ["fd00:ec2::254", "unique_local"],
    ["ff02::1", "multicast"],
    ["2001:db8::1", "documentation"],
    ["::ffff:127.0.0.1", "loopback"],
    ["::ffff:7f00:1", "loopback"],
    ["::ffff:169.254.169.254", "link_local"],
    ["64:ff9b::a00:1", "nat64"],
    ["2002:7f00:1::", "6to4"],
    ["2001:0:4136:e378::1", "reserved"],
  ];
  for (const [ip, reason] of denied) {
    it(`denies ${ip} (${reason})`, () => {
      assert.deepEqual(classifyAddress(ip), { allowed: false, reason });
    });
  }

  for (const ip of ["93.184.215.14", "1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "::ffff:8.8.8.8", "172.32.0.1", "100.128.0.1"]) {
    it(`allows public ${ip}`, () => assert.deepEqual(classifyAddress(ip), { allowed: true }));
  }

  it("denies non-addresses", () => assert.equal(classifyAddress("example.com").allowed, false));
});

describe("canonicalAddress", () => {
  it("normalises IPv4-mapped IPv6 and compressed forms", () => {
    assert.equal(canonicalAddress("::ffff:1.2.3.4"), "1.2.3.4");
    assert.equal(canonicalAddress("2606:4700:4700:0:0:0:0:1111"), canonicalAddress("2606:4700:4700::1111"));
    assert.equal(canonicalAddress("nope"), null);
  });
});

describe("validateUrl (RB-02, RB-06)", () => {
  const reject = (url: string, code: string) => {
    const r = validateUrl(url);
    assert.equal(r.ok, false, url);
    if (!r.ok) assert.equal(r.code, code, url);
  };

  it("accepts a public https URL", () => {
    const r = validateUrl("https://example.org/a?b=1");
    assert.ok(r.ok);
    if (r.ok) assert.equal(r.port, 443);
  });
  it("rejects http by default", () => reject("http://example.org/", "scheme_not_allowed"));
  it("rejects other schemes", () => {
    reject("file:///etc/passwd", "scheme_not_allowed");
    reject("ftp://example.org/", "scheme_not_allowed");
    reject("gopher://example.org/", "scheme_not_allowed");
  });
  it("rejects credentials", () => reject("https://user:pw@example.org/", "url_credentials"));
  it("rejects non-default ports", () => reject("https://example.org:8443/", "port_not_allowed"));
  it("rejects loopback via alternate IPv4 notations", () => {
    reject("https://0x7f.1/", "address_loopback");
    reject("https://2130706433/", "address_loopback");
    reject("https://127.1/", "address_loopback");
  });
  it("rejects bracketed IPv6 loopback and metadata", () => {
    reject("https://[::1]/", "address_loopback");
    reject("https://[::ffff:169.254.169.254]/", "address_link_local");
  });
  it("rejects internal-looking names", () => {
    reject("https://localhost/", "host_not_public");
    reject("https://foo.localhost/", "host_not_public");
    reject("https://metadata.google.internal/", "host_not_public");
    reject("https://intranet/", "host_not_public");
  });
  it("rejects overly long URLs", () => reject(`https://example.org/${"a".repeat(3000)}`, "url_too_long"));
  it("rejects garbage", () => reject("not a url", "url_unparseable"));
});

describe("redaction (RB-09)", () => {
  it("drops userinfo and fragments and masks secret-looking params for display", () => {
    const out = redactUrl("https://u:p@example.org/x?q=cats&api_key=abc123&token=zzz#frag");
    assert.equal(out, "https://example.org/x?q=cats&api_key=REDACTED&token=REDACTED");
  });
  it("masks every query value in log mode", () => {
    assert.equal(redactUrl("https://example.org/x?q=cats", "log"), "https://example.org/x?q=REDACTED");
  });
  it("redacts sensitive headers", () => {
    const h = redactHeaders({ "Set-Cookie": "a=b", Authorization: "Bearer x", "content-type": "text/html", "X-Session-Id": "1" });
    assert.equal(h["set-cookie"], "REDACTED");
    assert.equal(h.authorization, "REDACTED");
    assert.equal(h["x-session-id"], "REDACTED");
    assert.equal(h["content-type"], "text/html");
  });
});

describe("classifyChallenge (RB-10, RB-11, RB-12)", () => {
  it("detects reCAPTCHA", () => {
    const r = classifyChallenge({ httpStatus: 200, body: '<div class="g-recaptcha" data-sitekey="x"></div>' });
    assert.equal(r.challenge_type, "captcha");
  });
  it("detects Cloudflare challenge with 403 at high confidence", () => {
    const r = classifyChallenge({ httpStatus: 403, body: '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>' });
    assert.equal(r.challenge_type, "captcha");
    assert.equal(r.confidence, "high");
  });
  it("does not flag an article that merely mentions captchas", () => {
    const r = classifyChallenge({ httpStatus: 200, body: "A history of the CAPTCHA and its usability problems." });
    assert.equal(r.challenge_type, "none");
  });
  it("detects login walls", () => {
    assert.equal(classifyChallenge({ httpStatus: 401 }).challenge_type, "login_required");
    assert.equal(classifyChallenge({ httpStatus: 200, body: "Please sign in to continue" }).challenge_type, "login_required");
  });
  it("detects rate limits and parses Retry-After", () => {
    const r = classifyChallenge({ httpStatus: 429, headers: { "retry-after": "120" } });
    assert.equal(r.challenge_type, "rate_limited");
    assert.equal(r.retry_after_seconds, 120);
  });
  it("caps absurd Retry-After values", () => {
    assert.equal(classifyChallenge({ httpStatus: 429, headers: { "retry-after": "999999999" } }).retry_after_seconds, 86_400);
  });
  it("maps 451 and bare 403 to policy blocks", () => {
    assert.equal(classifyChallenge({ httpStatus: 451 }).challenge_type, "robots_or_policy_block");
    assert.equal(classifyChallenge({ httpStatus: 403, body: "Access denied" }).challenge_type, "robots_or_policy_block");
  });
});

describe("sha256", () => {
  it("declares its basis", () => {
    assert.deepEqual(sha256("abc", "extracted_text_utf8"), {
      algorithm: "sha256",
      basis: "extracted_text_utf8",
      value: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    });
  });
});
