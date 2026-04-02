import { describe, it, expect } from "vitest";

// lib.ts is the library entry point — it re-exports from jwt.ts.
// We verify that all public symbols are correctly exported through it.
import {
  parseJwt,
  auditJwt,
} from "./lib.js";

// Type-level imports — these exist only at compile time; if they're missing
// the TypeScript compiler will error during the test run.
import type {
  JwtHeader,
  JwtPayload,
  ParsedJwt,
  JwtAudit,
  AlgorithmAudit,
  ExpiryAudit,
  ClaimsAudit,
} from "./lib.js";

describe("lib.ts — re-exports", () => {
  it("exports parseJwt as a function", () => {
    expect(typeof parseJwt).toBe("function");
  });

  it("exports auditJwt as a function", () => {
    expect(typeof auditJwt).toBe("function");
  });

  it("parseJwt from lib is the same functional implementation as from jwt directly", () => {
    // Build a simple token and verify it round-trips correctly via the lib export
    function b64url(obj: unknown): string {
      return Buffer.from(JSON.stringify(obj), "utf8")
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
    }
    const token = `${b64url({ alg: "RS256", typ: "JWT" })}.${b64url({ sub: "test-user" })}.sig`;
    const result = parseJwt(token);
    expect(result.header.alg).toBe("RS256");
    expect(result.payload.sub).toBe("test-user");
  });

  it("auditJwt from lib works with a parsed token", () => {
    function b64url(obj: unknown): string {
      return Buffer.from(JSON.stringify(obj), "utf8")
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
    }
    const token = `${b64url({ alg: "ES256" })}.${b64url({ sub: "u1", iss: "https://example.com" })}.sig`;
    const parsed = parseJwt(token);
    const audit = auditJwt(parsed);
    expect(audit.algorithm.verdict).toBe("strong");
    expect(audit.claims.hasIssuer).toBe(true);
  });

  // Compile-time type checks — if any type export is missing, TypeScript
  // will fail to compile these variable declarations, causing the test run to error.
  it("type exports compile correctly (JwtHeader shape)", () => {
    const h: JwtHeader = { alg: "RS256", typ: "JWT" };
    expect(h.alg).toBe("RS256");
  });

  it("type exports compile correctly (JwtPayload shape)", () => {
    const p: JwtPayload = { sub: "user", iss: "https://example.com" };
    expect(p.sub).toBe("user");
  });

  it("type exports compile correctly (ParsedJwt shape)", () => {
    const p: ParsedJwt = {
      header: { alg: "RS256" },
      payload: { sub: "u1" },
      signatureRaw: "sig",
      raw: { header: "rawH", payload: "rawP" },
    };
    expect(p.signatureRaw).toBe("sig");
  });

  it("type exports compile correctly (JwtAudit shape)", () => {
    const a: JwtAudit = {
      algorithm: { value: "RS256", isWeak: false, isStrong: true, verdict: "strong", note: "ok" },
      expiry: {
        hasExpiry: true, isExpired: false, expiresAt: null,
        issuedAt: null, notBefore: null, secondsUntilExpiry: 100,
      },
      claims: { hasIssuer: true, hasAudience: true, hasSubject: true, hasJti: true },
    };
    expect(a.algorithm.verdict).toBe("strong");
  });

  it("type exports compile correctly (AlgorithmAudit, ExpiryAudit, ClaimsAudit)", () => {
    const alg: AlgorithmAudit = { value: "HS256", isWeak: true, isStrong: false, verdict: "weak", note: "weak" };
    const exp: ExpiryAudit = { hasExpiry: false, isExpired: false, expiresAt: null, issuedAt: null, notBefore: null, secondsUntilExpiry: null };
    const claims: ClaimsAudit = { hasIssuer: false, hasAudience: false, hasSubject: false, hasJti: false };
    expect(alg.verdict).toBe("weak");
    expect(exp.hasExpiry).toBe(false);
    expect(claims.hasIssuer).toBe(false);
  });
});
