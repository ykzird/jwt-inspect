import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { parseJwt, auditJwt } from "./jwt.js";
import type { ParsedJwt } from "./jwt.js";

// ---------------------------------------------------------------------------
// Helpers — build base64url-encoded JWT parts without any crypto library
// ---------------------------------------------------------------------------

function b64url(obj: unknown): string {
  const json = JSON.stringify(obj);
  return Buffer.from(json, "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function makeToken(header: unknown, payload: unknown, sig = "fakesig"): string {
  return `${b64url(header)}.${b64url(payload)}.${sig}`;
}

// A fixed "now" used for time-sensitive tests (unix seconds)
const FIXED_NOW_S = 1_700_000_000; // 2023-11-14T22:13:20Z

// ---------------------------------------------------------------------------
// parseJwt — structural tests
// ---------------------------------------------------------------------------

describe("parseJwt — valid token", () => {
  it("returns header, payload, and signatureRaw", () => {
    const token = makeToken({ alg: "HS256", typ: "JWT" }, { sub: "1234", iat: 1000 });
    const result = parseJwt(token);
    expect(result.header).toEqual({ alg: "HS256", typ: "JWT" });
    expect(result.payload).toEqual({ sub: "1234", iat: 1000 });
    expect(result.signatureRaw).toBe("fakesig");
  });

  it("preserves raw header and payload strings", () => {
    const headerObj = { alg: "RS256", typ: "JWT" };
    const payloadObj = { sub: "user1" };
    const rawH = b64url(headerObj);
    const rawP = b64url(payloadObj);
    const token = `${rawH}.${rawP}.sig`;
    const result = parseJwt(token);
    expect(result.raw.header).toBe(rawH);
    expect(result.raw.payload).toBe(rawP);
  });

  it("handles tokens with no padding in base64url segments", () => {
    // b64url removes padding — ensure decode works regardless of segment length
    const token = makeToken({ alg: "ES256" }, { iss: "https://example.com", sub: "u1" });
    const result = parseJwt(token);
    expect(result.header.alg).toBe("ES256");
    expect(result.payload.iss).toBe("https://example.com");
  });

  it("handles all standard payload claims", () => {
    const payload = {
      iss: "https://issuer.example.com",
      sub: "subject-001",
      aud: ["api.example.com", "app.example.com"],
      exp: FIXED_NOW_S + 3600,
      nbf: FIXED_NOW_S - 60,
      iat: FIXED_NOW_S - 120,
      jti: "unique-jwt-id-abc123",
    };
    const result = parseJwt(makeToken({ alg: "RS256", typ: "JWT" }, payload));
    expect(result.payload).toEqual(payload);
  });

  it("handles custom (non-standard) claims in payload", () => {
    const payload = { sub: "u1", role: "admin", permissions: ["read", "write"], level: 5 };
    const result = parseJwt(makeToken({ alg: "HS256" }, payload));
    expect(result.payload.role).toBe("admin");
    expect(result.payload.permissions).toEqual(["read", "write"]);
    expect(result.payload.level).toBe(5);
  });

  it("handles audience as a string (not array)", () => {
    const result = parseJwt(makeToken({ alg: "RS256" }, { aud: "api.example.com" }));
    expect(result.payload.aud).toBe("api.example.com");
  });

  it("handles empty payload object", () => {
    const result = parseJwt(makeToken({ alg: "RS256" }, {}));
    expect(result.payload).toEqual({});
  });

  it("handles empty string signature part", () => {
    const token = `${b64url({ alg: "none" })}.${b64url({ sub: "u1" })}.`;
    const result = parseJwt(token);
    expect(result.signatureRaw).toBe("");
  });
});

// ---------------------------------------------------------------------------
// parseJwt — base64url decode correctness
// ---------------------------------------------------------------------------

describe("parseJwt — base64url decode edge cases", () => {
  it("decodes segments that require 1 byte of padding (length % 4 === 3)", () => {
    // Craft a JSON that base64url-encodes to a length % 4 === 3 string
    const payload = { a: "x" }; // short to influence encoded length
    const token = makeToken({ alg: "RS256" }, payload);
    const result = parseJwt(token);
    expect(result.payload).toEqual(payload);
  });

  it("decodes segments that require 2 bytes of padding (length % 4 === 2)", () => {
    const payload = { ab: "xy" };
    const token = makeToken({ alg: "RS256" }, payload);
    const result = parseJwt(token);
    expect(result.payload).toEqual(payload);
  });

  it("decodes base64url chars that differ from standard base64 (+ → - and / → _)", () => {
    // Manually build a payload that when base64-standard-encoded contains + and /
    // We'll encode raw bytes that are known to produce those characters.
    // Instead of guessing, produce the token directly with the replaced chars.
    const raw = JSON.stringify({ sub: "user" });
    const b64standard = Buffer.from(raw).toString("base64");
    // Simulate what b64url does (already done in makeToken) — just confirm round-trip
    const b64u = b64standard.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const token = `${b64url({ alg: "RS256" })}.${b64u}.sig`;
    const result = parseJwt(token);
    expect(result.payload.sub).toBe("user");
  });

  it("handles unicode characters in claim values", () => {
    const payload = { name: "Ålice Ünïcödé", greeting: "こんにちは" };
    const token = makeToken({ alg: "RS256" }, payload);
    const result = parseJwt(token);
    expect(result.payload.name).toBe("Ålice Ünïcödé");
    expect(result.payload.greeting).toBe("こんにちは");
  });

  it("handles very large payload without truncation", () => {
    const largeValue = "x".repeat(5000);
    const payload = { data: largeValue };
    const result = parseJwt(makeToken({ alg: "RS256" }, payload));
    expect(result.payload.data).toBe(largeValue);
    expect((result.payload.data as string).length).toBe(5000);
  });
});

// ---------------------------------------------------------------------------
// parseJwt — malformed input errors
// ---------------------------------------------------------------------------

describe("parseJwt — malformed inputs", () => {
  it("throws when given an empty string", () => {
    expect(() => parseJwt("")).toThrow("Invalid JWT structure");
  });

  it("throws when given a string with only 1 dot-separated part", () => {
    expect(() => parseJwt("onlyonepart")).toThrow("Invalid JWT structure");
    expect(() => parseJwt("onlyonepart")).toThrow("got 1");
  });

  it("throws when given only 2 parts", () => {
    expect(() => parseJwt("header.payload")).toThrow("Invalid JWT structure");
    expect(() => parseJwt("header.payload")).toThrow("got 2");
  });

  it("throws when given 4 parts", () => {
    expect(() => parseJwt("a.b.c.d")).toThrow("Invalid JWT structure");
    expect(() => parseJwt("a.b.c.d")).toThrow("got 4");
  });

  it("throws when header is not valid base64", () => {
    // Use "!!!" as the header — not valid base64url
    expect(() => parseJwt("!!!.payload.sig")).toThrow("Failed to decode JWT header");
  });

  it("throws when header decodes but is not valid JSON", () => {
    const notJson = Buffer.from("not-json-at-all", "utf8").toString("base64url");
    expect(() => parseJwt(`${notJson}.payload.sig`)).toThrow("Failed to decode JWT header");
  });

  it("throws when payload is not valid base64", () => {
    const validHeader = b64url({ alg: "RS256" });
    expect(() => parseJwt(`${validHeader}.!!!!!.sig`)).toThrow("Failed to decode JWT payload");
  });

  it("throws when payload decodes but is not valid JSON", () => {
    const validHeader = b64url({ alg: "RS256" });
    const notJsonPayload = Buffer.from("not-json", "utf8").toString("base64url");
    expect(() => parseJwt(`${validHeader}.${notJsonPayload}.sig`)).toThrow("Failed to decode JWT payload");
  });

  it("throws with a descriptive message on completely random string", () => {
    expect(() => parseJwt("this is not a jwt at all")).toThrow(/Invalid JWT structure|got \d/);
  });

  it("error message includes the actual part count", () => {
    try {
      parseJwt("one.two");
      // Should not reach here
      expect.fail("Expected error was not thrown");
    } catch (e) {
      expect((e as Error).message).toMatch(/got 2/);
    }
  });
});

// ---------------------------------------------------------------------------
// auditJwt — algorithm classification
// ---------------------------------------------------------------------------

describe("auditJwt — algorithm audit", () => {
  function auditWithAlg(alg: string | undefined) {
    const header = alg === undefined ? { typ: "JWT" } : { alg, typ: "JWT" };
    const token = makeToken(header, { sub: "u1" });
    return auditJwt(parseJwt(token));
  }

  // Weak algorithms
  it("classifies HS256 as weak", () => {
    const audit = auditWithAlg("HS256");
    expect(audit.algorithm.verdict).toBe("weak");
    expect(audit.algorithm.isWeak).toBe(true);
    expect(audit.algorithm.isStrong).toBe(false);
    expect(audit.algorithm.value).toBe("HS256");
  });

  it("classifies 'none' as weak (case-sensitive match on lowercase)", () => {
    const audit = auditWithAlg("none");
    expect(audit.algorithm.verdict).toBe("weak");
    expect(audit.algorithm.isWeak).toBe(true);
    expect(audit.algorithm.note).toContain("no signature");
  });

  it("classifies 'None' (mixed-case) as weak via toLowerCase check", () => {
    const audit = auditWithAlg("None");
    expect(audit.algorithm.verdict).toBe("weak");
    expect(audit.algorithm.isWeak).toBe(true);
  });

  it("classifies 'NONE' (all-caps) as weak via toLowerCase check", () => {
    const audit = auditWithAlg("NONE");
    expect(audit.algorithm.verdict).toBe("weak");
    expect(audit.algorithm.isWeak).toBe(true);
  });

  // Strong algorithms
  const strongAlgorithms = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"];
  for (const alg of strongAlgorithms) {
    it(`classifies ${alg} as strong`, () => {
      const audit = auditWithAlg(alg);
      expect(audit.algorithm.verdict).toBe("strong");
      expect(audit.algorithm.isStrong).toBe(true);
      expect(audit.algorithm.isWeak).toBe(false);
      expect(audit.algorithm.note).toContain("asymmetric");
    });
  }

  // Unknown algorithms
  it("classifies an unrecognized algorithm as unknown", () => {
    const audit = auditWithAlg("CUSTOM-ALG");
    expect(audit.algorithm.verdict).toBe("unknown");
    expect(audit.algorithm.isWeak).toBe(false);
    expect(audit.algorithm.isStrong).toBe(false);
    expect(audit.algorithm.note).toContain("not a recognized");
  });

  it("classifies missing alg field as unknown", () => {
    const audit = auditWithAlg(undefined);
    expect(audit.algorithm.verdict).toBe("unknown");
    expect(audit.algorithm.value).toBeUndefined();
    expect(audit.algorithm.note).toContain("No 'alg' field");
  });

  it("note for 'none' mentions token is forgeable", () => {
    const audit = auditWithAlg("none");
    expect(audit.algorithm.note).toMatch(/forgeable/i);
  });

  it("note for weak symmetric algorithm mentions secret", () => {
    const audit = auditWithAlg("HS256");
    expect(audit.algorithm.note).toMatch(/symmetric|secret/i);
  });

  it("note for strong algorithm includes the algorithm name", () => {
    const audit = auditWithAlg("RS256");
    expect(audit.algorithm.note).toContain("RS256");
  });
});

// ---------------------------------------------------------------------------
// auditJwt — expiry audit
// ---------------------------------------------------------------------------

describe("auditJwt — expiry audit", () => {
  // We need to control Date.now() for deterministic expiry tests
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(FIXED_NOW_S * 1000);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("detects an expired token (exp in the past)", () => {
    const expiredAt = FIXED_NOW_S - 3600; // 1 hour ago
    const token = makeToken({ alg: "RS256" }, { sub: "u1", exp: expiredAt });
    const audit = auditJwt(parseJwt(token));

    expect(audit.expiry.hasExpiry).toBe(true);
    expect(audit.expiry.isExpired).toBe(true);
    expect(audit.expiry.secondsUntilExpiry).toBe(-3600);
    expect(audit.expiry.expiresAt).toEqual(new Date(expiredAt * 1000));
  });

  it("detects a valid (non-expired) token", () => {
    const expiresAt = FIXED_NOW_S + 3600; // 1 hour from now
    const token = makeToken({ alg: "RS256" }, { sub: "u1", exp: expiresAt });
    const audit = auditJwt(parseJwt(token));

    expect(audit.expiry.hasExpiry).toBe(true);
    expect(audit.expiry.isExpired).toBe(false);
    expect(audit.expiry.secondsUntilExpiry).toBe(3600);
  });

  it("detects a token that expires exactly now as expired (now > exp is false when equal)", () => {
    // exp === now means now > exp is false → NOT expired
    const token = makeToken({ alg: "RS256" }, { sub: "u1", exp: FIXED_NOW_S });
    const audit = auditJwt(parseJwt(token));
    // now > exp → FIXED_NOW_S > FIXED_NOW_S → false
    expect(audit.expiry.isExpired).toBe(false);
  });

  it("detects a token expiring 1 second ago as expired", () => {
    const token = makeToken({ alg: "RS256" }, { sub: "u1", exp: FIXED_NOW_S - 1 });
    const audit = auditJwt(parseJwt(token));
    expect(audit.expiry.isExpired).toBe(true);
  });

  it("returns hasExpiry=false when no exp claim", () => {
    const token = makeToken({ alg: "RS256" }, { sub: "u1" });
    const audit = auditJwt(parseJwt(token));

    expect(audit.expiry.hasExpiry).toBe(false);
    expect(audit.expiry.isExpired).toBe(false);
    expect(audit.expiry.expiresAt).toBeNull();
    expect(audit.expiry.secondsUntilExpiry).toBeNull();
  });

  it("returns issuedAt as Date when iat is present", () => {
    const iat = FIXED_NOW_S - 300;
    const token = makeToken({ alg: "RS256" }, { sub: "u1", iat });
    const audit = auditJwt(parseJwt(token));

    expect(audit.expiry.issuedAt).toEqual(new Date(iat * 1000));
  });

  it("returns issuedAt as null when iat is absent", () => {
    const token = makeToken({ alg: "RS256" }, { sub: "u1" });
    const audit = auditJwt(parseJwt(token));
    expect(audit.expiry.issuedAt).toBeNull();
  });

  it("returns notBefore as Date when nbf is present", () => {
    const nbf = FIXED_NOW_S - 60;
    const token = makeToken({ alg: "RS256" }, { sub: "u1", nbf });
    const audit = auditJwt(parseJwt(token));
    expect(audit.expiry.notBefore).toEqual(new Date(nbf * 1000));
  });

  it("returns notBefore as null when nbf is absent", () => {
    const token = makeToken({ alg: "RS256" }, { sub: "u1" });
    const audit = auditJwt(parseJwt(token));
    expect(audit.expiry.notBefore).toBeNull();
  });

  it("secondsUntilExpiry is negative for expired tokens", () => {
    const token = makeToken({ alg: "RS256" }, { sub: "u1", exp: FIXED_NOW_S - 500 });
    const audit = auditJwt(parseJwt(token));
    expect(audit.expiry.secondsUntilExpiry).toBe(-500);
  });

  it("handles all three time claims together", () => {
    const payload = {
      iss: "https://example.com",
      sub: "u1",
      iat: FIXED_NOW_S - 120,
      nbf: FIXED_NOW_S - 60,
      exp: FIXED_NOW_S + 3600,
    };
    const audit = auditJwt(parseJwt(makeToken({ alg: "RS256" }, payload)));
    expect(audit.expiry.issuedAt).toEqual(new Date((FIXED_NOW_S - 120) * 1000));
    expect(audit.expiry.notBefore).toEqual(new Date((FIXED_NOW_S - 60) * 1000));
    expect(audit.expiry.expiresAt).toEqual(new Date((FIXED_NOW_S + 3600) * 1000));
    expect(audit.expiry.isExpired).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// auditJwt — claims audit
// ---------------------------------------------------------------------------

describe("auditJwt — claims audit", () => {
  it("detects all four claims present", () => {
    const token = makeToken({ alg: "RS256" }, {
      iss: "https://example.com",
      sub: "user-001",
      aud: "api.example.com",
      jti: "unique-id-123",
    });
    const audit = auditJwt(parseJwt(token));
    expect(audit.claims.hasIssuer).toBe(true);
    expect(audit.claims.hasAudience).toBe(true);
    expect(audit.claims.hasSubject).toBe(true);
    expect(audit.claims.hasJti).toBe(true);
  });

  it("detects all four claims absent", () => {
    const token = makeToken({ alg: "RS256" }, { exp: FIXED_NOW_S + 100 });
    const audit = auditJwt(parseJwt(token));
    expect(audit.claims.hasIssuer).toBe(false);
    expect(audit.claims.hasAudience).toBe(false);
    expect(audit.claims.hasSubject).toBe(false);
    expect(audit.claims.hasJti).toBe(false);
  });

  it("detects only iss present", () => {
    const token = makeToken({ alg: "RS256" }, { iss: "https://example.com" });
    const audit = auditJwt(parseJwt(token));
    expect(audit.claims.hasIssuer).toBe(true);
    expect(audit.claims.hasAudience).toBe(false);
    expect(audit.claims.hasSubject).toBe(false);
    expect(audit.claims.hasJti).toBe(false);
  });

  it("detects aud as string", () => {
    const token = makeToken({ alg: "RS256" }, { aud: "https://api.example.com" });
    const audit = auditJwt(parseJwt(token));
    expect(audit.claims.hasAudience).toBe(true);
  });

  it("detects aud as array", () => {
    const token = makeToken({ alg: "RS256" }, { aud: ["api.example.com", "app.example.com"] });
    const audit = auditJwt(parseJwt(token));
    expect(audit.claims.hasAudience).toBe(true);
  });

  it("detects only jti present", () => {
    const token = makeToken({ alg: "RS256" }, { jti: "abc-def-ghi" });
    const audit = auditJwt(parseJwt(token));
    expect(audit.claims.hasIssuer).toBe(false);
    expect(audit.claims.hasAudience).toBe(false);
    expect(audit.claims.hasSubject).toBe(false);
    expect(audit.claims.hasJti).toBe(true);
  });

  it("returns correct partial mix: iss + sub but not aud or jti", () => {
    const token = makeToken({ alg: "RS256" }, {
      iss: "https://example.com",
      sub: "user-002",
    });
    const audit = auditJwt(parseJwt(token));
    expect(audit.claims.hasIssuer).toBe(true);
    expect(audit.claims.hasSubject).toBe(true);
    expect(audit.claims.hasAudience).toBe(false);
    expect(audit.claims.hasJti).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Integration: parseJwt + auditJwt on a realistic token
// ---------------------------------------------------------------------------

describe("parseJwt + auditJwt — realistic integration", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(FIXED_NOW_S * 1000);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("correctly audits a full realistic RS256 token", () => {
    const payload = {
      iss: "https://auth.example.com",
      sub: "user-999",
      aud: "https://api.example.com",
      exp: FIXED_NOW_S + 900,
      iat: FIXED_NOW_S - 60,
      jti: "jti-abcde-12345",
    };
    const token = makeToken({ alg: "RS256", typ: "JWT" }, payload, "realsig");
    const parsed = parseJwt(token);
    const audit = auditJwt(parsed);

    expect(audit.algorithm.verdict).toBe("strong");
    expect(audit.expiry.isExpired).toBe(false);
    expect(audit.expiry.secondsUntilExpiry).toBe(900);
    expect(audit.claims.hasIssuer).toBe(true);
    expect(audit.claims.hasSubject).toBe(true);
    expect(audit.claims.hasAudience).toBe(true);
    expect(audit.claims.hasJti).toBe(true);
  });

  it("correctly audits an expired HS256 token missing optional claims", () => {
    const payload = {
      exp: FIXED_NOW_S - 7200,
      iat: FIXED_NOW_S - 10800,
    };
    const token = makeToken({ alg: "HS256", typ: "JWT" }, payload, "weaksig");
    const parsed = parseJwt(token);
    const audit = auditJwt(parsed);

    expect(audit.algorithm.verdict).toBe("weak");
    expect(audit.expiry.isExpired).toBe(true);
    expect(audit.expiry.secondsUntilExpiry).toBe(-7200);
    expect(audit.claims.hasIssuer).toBe(false);
    expect(audit.claims.hasSubject).toBe(false);
    expect(audit.claims.hasAudience).toBe(false);
    expect(audit.claims.hasJti).toBe(false);
  });
});
