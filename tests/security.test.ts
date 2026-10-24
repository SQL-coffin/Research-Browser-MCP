import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  canonicalAddress,
  classifyAddress,
  classifyChallenge,
  DEFAULT_URL_POLICY,
  discloseUrl,
  HostAllowlistError,
  isHostAllowlistEmpty,
  ORIGIN_ONLY,
  parseHostAllowlist,
  redactHeaders,
  redactUrl,
  sha256,
  validateUrl,
} from "../src/security.js";

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
    // Special-purpose blocks inside 2000::/3: global unicast space, still denied.
    ["2001:2::1", "reserved"], // benchmarking, inside 2001::/23
    ["2001:20::1", "reserved"], // ORCHIDv2, inside 2001::/23
    ["3fff::1", "documentation"],
    // Outside 2000::/3: denied by the allowlist, whether or not a block is listed.
    ["4000::1", "not_global_unicast"],
    ["8000::1", "not_global_unicast"],
    ["e000::1", "not_global_unicast"],
    ["1::1", "not_global_unicast"],
    ["::ffff:0:a00:1", "not_global_unicast"], // IPv4-translated (SIIT), not IPv4-mapped
    ["100::1", "discard"],
    ["5f00::1", "reserved"],
    ["fec0::1", "site_local"],
  ];
  for (const [ip, reason] of denied) {
    it(`denies ${ip} (${reason})`, () => {
      assert.deepEqual(classifyAddress(ip), { allowed: false, reason });
    });
  }

  for (const ip of [
    "93.184.215.14",
    "1.1.1.1",
    "8.8.8.8",
    "2606:4700:4700::1111",
    "2001:4860:4860::8888", // 2001::/16 but outside the special 2001::/23
    "2a00:1450:4001:80b::200e",
    "::ffff:8.8.8.8",
    "172.32.0.1",
    "100.128.0.1",
  ]) {
    it(`allows public ${ip}`, () => assert.deepEqual(classifyAddress(ip), { allowed: true }));
  }

  it("denies non-addresses", () => assert.equal(classifyAddress("example.com").allowed, false));

  it("allows IPv6 only inside 2000::/3 (sweep of every first hextet)", () => {
    let allowed = 0;
    for (let h = 0; h <= 0xffff; h++) {
      const verdict = classifyAddress(`${h.toString(16)}:abcd::1`);
      if (!verdict.allowed) continue;
      allowed++;
      assert.ok(h >= 0x2000 && h <= 0x3fff, `${h.toString(16)}:abcd::1 is outside 2000::/3 but was allowed`);
    }
    // Every 2000::/3 first hextet passes except 2002::/16 (6to4); with ":abcd" the
    // address sits outside 2001::/23, 2001:db8::/32 and 3fff::/20.
    assert.equal(allowed, 0x2000 - 1);
  });

  it("allows IPv4 only below 224.0.0.0 and outside special blocks (sweep of every first octet)", () => {
    const allowed: number[] = [];
    for (let o = 0; o <= 255; o++) if (classifyAddress(`${o}.1.2.3`).allowed) allowed.push(o);
    assert.equal(Math.max(...allowed), 223);
    for (const o of [0, 10, 127]) assert.ok(!allowed.includes(o), `${o}.1.2.3 was allowed`);
    assert.equal(allowed.length, 224 - 3);
  });
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

  it("accepts a public https URL on an allowlisted host", () => {
    const r = validateUrl("https://example.org/a?b=1", { ...DEFAULT_URL_POLICY, allowedHosts: parseHostAllowlist("example.org") });
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
  it("rejects IPv6 literals outside global unicast", () => {
    reject("https://[4000::1]/", "address_not_global_unicast");
    reject("https://[fe80::1]/", "address_link_local");
    reject("https://[2001:db8::1]/", "address_documentation");
  });
  it("judges IP literals with the policy's own address function, on the canonical spelling", () => {
    const seen: string[] = [];
    const policy = {
      ...DEFAULT_URL_POLICY,
      allowedHosts: parseHostAllowlist("127.0.0.1 8.8.8.8"),
      isAddressAllowed: (ip: string) => {
        seen.push(ip);
        return ip === "127.0.0.1" ? ({ allowed: true } as const) : ({ allowed: false, reason: "test" } as const);
      },
    };
    assert.ok(validateUrl("https://127.0.0.1/", policy).ok, "custom policy must override the default");
    assert.ok(validateUrl("https://[::ffff:7f00:1]/", policy).ok);
    const r = validateUrl("https://8.8.8.8/", policy);
    assert.ok(!r.ok && r.code === "address_test");
    assert.deepEqual(seen, ["127.0.0.1", "127.0.0.1", "8.8.8.8"]);
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

describe("host allowlist (startup configuration)", () => {
  const list = parseHostAllowlist("Example.ORG., bücher.example, 93.184.215.14, [2606:4700:4700::1111]");
  const verdict = (url: string) => {
    const r = validateUrl(url, { ...DEFAULT_URL_POLICY, allowedHosts: list });
    return r.ok ? "ok" : r.code;
  };

  it("normalizes entries: case, trailing dot, IDN to Punycode, canonical IP spelling", () => {
    assert.deepEqual([...list.exact].sort(), ["2606:4700:4700:0:0:0:0:1111", "93.184.215.14", "example.org", "xn--bcher-kva.example"]);
  });

  it("is empty when unset, and an empty allowlist denies everything", () => {
    for (const spec of ["", "   ", ", ,"]) assert.ok(isHostAllowlistEmpty(parseHostAllowlist(spec)));
    const r = validateUrl("https://example.org/");
    assert.ok(!r.ok && r.code === "host_allowlist_empty");
  });

  // Wildcards are not supported in any form.
  for (const entry of ["*", "*.org", "*.co.uk", "*.example.org", "*.example.org.", "*.*", "**.example.org", "a.*.example.org", "*example.org", "example.*", "%2A.example.org"]) {
    it(`rejects the wildcard entry ${JSON.stringify(entry)}`, () => {
      assert.throws(
        () => parseHostAllowlist(`example.com, ${entry}`),
        (err: unknown) => err instanceof HostAllowlistError && /position 2\b/.test(err.message) && /wildcards, .* are not supported/.test(err.message),
      );
    });
  }

  for (const entry of [
    "https://example.org",
    "example.org/path",
    "example.org:443",
    "user@example.org",
    "localhost",
    "example..org",
    ".example.org",
    "xn--zz.example",
    "0x7f.1",
    "exa%6dple.org",
  ]) {
    it(`rejects the entry ${JSON.stringify(entry)}`, () => {
      assert.throws(
        () => parseHostAllowlist(`example.com, ${entry}`),
        (err: unknown) => err instanceof HostAllowlistError && /position 2\b/.test(err.message),
      );
    });
  }

  // Some Node builds' URL parsers accept malformed A-labels, so these must be
  // rejected by our own Punycode check, independent of the parser.
  for (const label of ["xn--zz", "xn--a", "xn--", "xn--99999999999999999999z", "xn--a-zz"]) {
    it(`rejects the malformed Punycode label ${label} in entries and request URLs`, () => {
      assert.throws(() => parseHostAllowlist(`${label}.example`), HostAllowlistError);
      const r = validateUrl(`https://${label}.example/`, { ...DEFAULT_URL_POLICY, allowedHosts: parseHostAllowlist("example.org") });
      assert.ok(!r.ok && (r.code === "invalid_host" || r.code === "url_unparseable"), JSON.stringify(r));
    });
  }

  it("accepts well-formed Punycode labels", () => {
    const hosts = parseHostAllowlist("xn--bcher-kva.example xn--ls8h.example xn--exmple-4nf.org");
    assert.deepEqual([...hosts.exact].sort(), ["xn--bcher-kva.example", "xn--exmple-4nf.org", "xn--ls8h.example"]);
  });

  it("does not echo a rejected entry, which might carry credentials", () => {
    assert.throws(
      () => parseHostAllowlist("https://alice:s3cr3t-PW@example.org/"),
      (err: unknown) => err instanceof HostAllowlistError && !err.message.includes("s3cr3t-PW") && !err.message.includes("alice"),
    );
  });

  for (const url of [
    "https://example.org/",
    "https://EXAMPLE.org/",
    "https://example.org./",
    "https://example.org:443/",
    "https://ｅｘａｍｐｌｅ.org/", // fullwidth letters map to the same ASCII name
    "https://example。org/", // ideographic full stop maps to "."
    "https://bücher.example/",
    "https://BÜCHER.example/",
    "https://xn--bcher-kva.example/",
    "https://93.184.215.14/",
    "https://[2606:4700:4700:0:0:0:0:1111]/",
  ]) {
    it(`allows ${url}`, () => assert.equal(verdict(url), "ok"));
  }

  for (const url of [
    "https://example.com/",
    "https://www.example.org/", // a subdomain of a listed host
    "https://a.b.example.org/",
    "https://sub.bücher.example/",
    "https://example.org.evil.com/",
    "https://evilexample.org/",
    "https://example.org%2eevil.com/", // percent-encoded dot
    "https://example.org．evil.com/", // fullwidth dot
    "https://exаmple.org/", // Cyrillic "а": xn--exmple-4nf.org
    "https://93.184.215.15/",
    "https://[2606:4700:4700::1112]/",
    "https://8.8.8.8/",
  ]) {
    it(`denies ${url} as not allowlisted`, () => assert.equal(verdict(url), "host_not_allowlisted"));
  }

  it("rejects malformed host names before they reach the allowlist or DNS", () => {
    assert.equal(verdict("https://.example.org/"), "invalid_host");
    assert.equal(verdict("https://*.example.org/"), "invalid_host");
    assert.equal(verdict("https://a..example.org/"), "invalid_host");
  });

  it("only narrows the other checks: a listed host still needs a public name and address, https and port 443", () => {
    const p = { ...DEFAULT_URL_POLICY, allowedHosts: parseHostAllowlist("127.0.0.1 printer.local example.org") };
    const code = (url: string) => {
      const r = validateUrl(url, p);
      return r.ok ? "ok" : r.code;
    };
    assert.equal(code("https://127.0.0.1/"), "address_loopback");
    assert.equal(code("https://printer.local/"), "host_not_public");
    assert.equal(code("http://example.org/"), "scheme_not_allowed");
    assert.equal(code("https://example.org:8443/"), "port_not_allowed");
    assert.equal(code("https://user:pw@example.org/"), "url_credentials");
  });
});

describe("URL disclosure in fetch results (output only)", () => {
  const RAW = "https://alice-U:pa55-Wd@Example.ORG/acct/PATH-T0KEN-z1?id=ID-77&token=QTOKEN-k2#frag-F3";
  const optedIn = { fullUrlHosts: parseHostAllowlist("example.org bücher.example 2606:4700:4700::1111") };

  it("shows only the origin by default", () => {
    assert.equal(discloseUrl(RAW, ORIGIN_ONLY), "https://example.org");
    assert.equal(discloseUrl("http://fixture.test:8080/a/PATH-T0KEN?c=d", ORIGIN_ONLY), "http://fixture.test:8080");
  });

  it("shows path and query for an opted-in host, never credentials or the fragment, and masks secret-looking values", () => {
    assert.equal(discloseUrl(RAW, optedIn), "https://example.org/acct/PATH-T0KEN-z1?id=ID-77&token=REDACTED");
  });

  it("decides by each URL's own host, normalized exactly as the allowlist normalizes it", () => {
    for (const listed of [
      "https://EXAMPLE.org/p?q=1",
      "https://example.org./p?q=1",
      "https://ｅｘａｍｐｌｅ.org/p?q=1",
      "https://BÜCHER.example/p?q=1",
      "https://xn--bcher-kva.example/p?q=1",
      "https://[2606:4700:4700:0:0:0:0:1111]/p?q=1",
    ]) {
      assert.match(discloseUrl(listed, optedIn), /\/p\?q=1$/, listed);
    }
    for (const [unlisted, origin] of [
      ["https://www.example.org/p?q=1", "https://www.example.org"],
      ["https://example.org.evil.com/p?q=1", "https://example.org.evil.com"],
      ["https://example.com/p?q=1", "https://example.com"],
      ["https://[2606:4700:4700::1112]/p?q=1", "https://[2606:4700:4700::1112]"],
    ]) {
      assert.equal(discloseUrl(unlisted!, optedIn), origin, unlisted);
    }
  });

  it("returns placeholders for input it cannot show", () => {
    assert.equal(discloseUrl("not a url", optedIn), "[unparseable-url]");
    assert.equal(discloseUrl("file:///etc/passwd", optedIn), "[non-http-url]");
  });

  it("takes its host list with the same rules as the allowlist: no wildcards", () => {
    assert.throws(() => parseHostAllowlist("*.example.org", "RESEARCH_BROWSER_FULL_URL_HOSTS"), /RESEARCH_BROWSER_FULL_URL_HOSTS: invalid entry at position 1/);
  });
});

describe("redaction (RB-09)", () => {
  it("bounds the origin: a host name longer than DNS allows is replaced, in every mode", () => {
    const longHost = `${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(63)}.evil`; // 260 characters
    for (const mode of ["origin", "display"] as const) {
      const out = redactUrl(`https://${longHost}/p?q=1`, mode);
      assert.equal(out, "[invalid-host]", mode);
    }
    assert.equal(discloseUrl(`https://${longHost}/`, ORIGIN_ONLY), "[invalid-host]");
    const maxHost = `${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(57)}.org`; // 253 characters
    assert.equal(redactUrl(`https://${maxHost}/x`, "origin"), `https://${maxHost}`);
  });

  it("drops userinfo and fragments and masks secret-looking params for display", () => {
    const out = redactUrl("https://u:p@example.org/x?q=cats&api_key=abc123&token=zzz#frag");
    assert.equal(out, "https://example.org/x?q=cats&api_key=REDACTED&token=REDACTED");
  });
  it("keeps only the origin in origin mode", () => {
    assert.equal(redactUrl("https://alice:pw@Example.ORG:443/reset/PATH-T0KEN?token=Q&q=cats#frag", "origin"), "https://example.org");
    assert.equal(redactUrl("http://example.org:8080/a", "origin"), "http://example.org:8080");
    assert.equal(redactUrl("https://[2606:4700::1111]/a", "origin"), "https://[2606:4700::1111]");
    assert.equal(redactUrl("file:///etc/passwd", "origin"), "[non-http-url]");
    assert.equal(redactUrl("not a url", "origin"), "[unparseable-url]");
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
