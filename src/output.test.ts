import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { printText, printJson } from "./output.js";
import type { ParsedJwt, JwtAudit } from "./jwt.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const FIXED_NOW_S = 1_700_000_000;

function makeBaseParsed(overrides: Partial<ParsedJwt> = {}): ParsedJwt {
  return {
    header: { alg: "RS256", typ: "JWT" },
    payload: {
      iss: "https://example.com",
      sub: "user-001",
      aud: "api.example.com",
      exp: FIXED_NOW_S + 3600,
      iat: FIXED_NOW_S - 300,
      jti: "jti-abc-123",
    },
    signatureRaw: "fakesignaturevalue12345678901234567890abcdefghijklmnopqrstuvwxyz",
    raw: { header: "rawheader", payload: "rawpayload" },
    ...overrides,
  };
}

function makeStrongAudit(expiredOverride = false): JwtAudit {
  const secondsUntilExpiry = expiredOverride ? -3600 : 3600;
  return {
    algorithm: {
      value: "RS256",
      isWeak: false,
      isStrong: true,
      verdict: "strong",
      note: "RS256 uses asymmetric cryptography",
    },
    expiry: {
      hasExpiry: true,
      isExpired: expiredOverride,
      expiresAt: new Date((FIXED_NOW_S + (expiredOverride ? -3600 : 3600)) * 1000),
      issuedAt: new Date((FIXED_NOW_S - 300) * 1000),
      notBefore: null,
      secondsUntilExpiry,
    },
    claims: {
      hasIssuer: true,
      hasAudience: true,
      hasSubject: true,
      hasJti: true,
    },
  };
}

function makeWeakAudit(): JwtAudit {
  return {
    algorithm: {
      value: "HS256",
      isWeak: true,
      isStrong: false,
      verdict: "weak",
      note: "HS256 is a symmetric algorithm — secret must be kept confidential",
    },
    expiry: {
      hasExpiry: false,
      isExpired: false,
      expiresAt: null,
      issuedAt: null,
      notBefore: null,
      secondsUntilExpiry: null,
    },
    claims: {
      hasIssuer: false,
      hasAudience: false,
      hasSubject: false,
      hasJti: false,
    },
  };
}

// Capture console.log lines, stripping ANSI escape codes for plain-text assertions
function stripAnsi(str: string): string {
  // eslint-disable-next-line no-control-regex
  return str.replace(/\x1B\[[0-9;]*m/g, "");
}

// ---------------------------------------------------------------------------
// printJson
// ---------------------------------------------------------------------------

describe("printJson", () => {
  let consoleSpy: ReturnType<typeof vi.spyOn>;
  let capturedLines: string[];

  beforeEach(() => {
    capturedLines = [];
    consoleSpy = vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      capturedLines.push(args.map(String).join(" "));
    });
  });

  afterEach(() => {
    consoleSpy.mockRestore();
  });

  it("outputs valid JSON", () => {
    const parsed = makeBaseParsed();
    const audit = makeStrongAudit();
    printJson(parsed, audit);

    const output = capturedLines.join("\n");
    expect(() => JSON.parse(output)).not.toThrow();
  });

  it("JSON output contains header object", () => {
    const parsed = makeBaseParsed();
    const audit = makeStrongAudit();
    printJson(parsed, audit);

    const output = JSON.parse(capturedLines.join("\n"));
    expect(output.header).toEqual({ alg: "RS256", typ: "JWT" });
  });

  it("JSON output contains payload object", () => {
    const parsed = makeBaseParsed();
    const audit = makeStrongAudit();
    printJson(parsed, audit);

    const output = JSON.parse(capturedLines.join("\n"));
    expect(output.payload.sub).toBe("user-001");
    expect(output.payload.iss).toBe("https://example.com");
  });

  it("JSON output contains audit object", () => {
    const parsed = makeBaseParsed();
    const audit = makeStrongAudit();
    printJson(parsed, audit);

    const output = JSON.parse(capturedLines.join("\n"));
    expect(output.audit).toBeDefined();
    expect(output.audit.algorithm.verdict).toBe("strong");
    expect(output.audit.expiry.isExpired).toBe(false);
  });

  it("JSON output for expired token reflects isExpired=true", () => {
    const parsed = makeBaseParsed({
      payload: { sub: "u1", exp: FIXED_NOW_S - 3600 },
    });
    const audit = makeStrongAudit(true);
    printJson(parsed, audit);

    const output = JSON.parse(capturedLines.join("\n"));
    expect(output.audit.expiry.isExpired).toBe(true);
  });

  it("JSON output for weak algorithm reflects verdict=weak", () => {
    const parsed = makeBaseParsed({ header: { alg: "HS256", typ: "JWT" } });
    const audit = makeWeakAudit();
    printJson(parsed, audit);

    const output = JSON.parse(capturedLines.join("\n"));
    expect(output.audit.algorithm.verdict).toBe("weak");
  });

  it("JSON output does not include signatureRaw at the top level", () => {
    // printJson only includes header, payload, audit — not signatureRaw
    const parsed = makeBaseParsed();
    const audit = makeStrongAudit();
    printJson(parsed, audit);

    const output = JSON.parse(capturedLines.join("\n"));
    expect(output.signatureRaw).toBeUndefined();
  });

  it("JSON output with custom claims includes them in payload", () => {
    const parsed = makeBaseParsed({
      payload: { sub: "u1", role: "admin", level: 3 },
    });
    const audit = makeStrongAudit();
    printJson(parsed, audit);

    const output = JSON.parse(capturedLines.join("\n"));
    expect(output.payload.role).toBe("admin");
    expect(output.payload.level).toBe(3);
  });

  it("JSON output is pretty-printed with 2-space indentation", () => {
    const parsed = makeBaseParsed();
    const audit = makeStrongAudit();
    printJson(parsed, audit);

    const raw = capturedLines.join("\n");
    // Pretty-printed JSON has newlines and spaces
    expect(raw).toContain("\n");
    expect(raw).toContain("  ");
  });
});

// ---------------------------------------------------------------------------
// printText
// ---------------------------------------------------------------------------

describe("printText", () => {
  let consoleSpy: ReturnType<typeof vi.spyOn>;
  let capturedLines: string[];

  beforeEach(() => {
    capturedLines = [];
    consoleSpy = vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      capturedLines.push(args.map(String).join(" "));
    });
  });

  afterEach(() => {
    consoleSpy.mockRestore();
  });

  function getOutput(): string {
    return stripAnsi(capturedLines.join("\n"));
  }

  it("outputs a Header section", () => {
    const parsed = makeBaseParsed();
    const audit = makeStrongAudit();
    printText(parsed, audit, false);
    expect(getOutput()).toContain("Header");
  });

  it("outputs a Payload section", () => {
    const parsed = makeBaseParsed();
    const audit = makeStrongAudit();
    printText(parsed, audit, false);
    expect(getOutput()).toContain("Payload");
  });

  it("outputs a Signature section", () => {
    const parsed = makeBaseParsed();
    const audit = makeStrongAudit();
    printText(parsed, audit, false);
    expect(getOutput()).toContain("Signature");
  });

  it("outputs header alg value", () => {
    const parsed = makeBaseParsed();
    const audit = makeStrongAudit();
    printText(parsed, audit, false);
    expect(getOutput()).toContain("RS256");
  });

  it("outputs payload sub value", () => {
    const parsed = makeBaseParsed();
    const audit = makeStrongAudit();
    printText(parsed, audit, false);
    expect(getOutput()).toContain("user-001");
  });

  it("outputs payload iss value", () => {
    const parsed = makeBaseParsed();
    const audit = makeStrongAudit();
    printText(parsed, audit, false);
    expect(getOutput()).toContain("https://example.com");
  });

  it("includes 'not verified' in signature section", () => {
    const parsed = makeBaseParsed();
    const audit = makeStrongAudit();
    printText(parsed, audit, false);
    expect(getOutput()).toContain("not verified");
  });

  it("truncates long signatures at 40 chars and adds ellipsis", () => {
    // signatureRaw is 64 chars long — should be truncated
    const parsed = makeBaseParsed({
      signatureRaw: "a".repeat(64),
    });
    const audit = makeStrongAudit();
    printText(parsed, audit, false);
    const output = getOutput();
    // The ellipsis character (…) should appear
    expect(output).toContain("…");
  });

  it("does not truncate short signatures (<=40 chars)", () => {
    const parsed = makeBaseParsed({ signatureRaw: "shortsig" });
    const audit = makeStrongAudit();
    printText(parsed, audit, false);
    const output = getOutput();
    expect(output).toContain("shortsig");
    expect(output).not.toContain("…");
  });

  it("shows signature character count", () => {
    const sig = "x".repeat(50);
    const parsed = makeBaseParsed({ signatureRaw: sig });
    const audit = makeStrongAudit();
    printText(parsed, audit, false);
    expect(getOutput()).toContain("50");
  });

  it("does NOT show audit section when showAudit=false", () => {
    const parsed = makeBaseParsed();
    const audit = makeStrongAudit();
    printText(parsed, audit, false);
    expect(getOutput()).not.toContain("Audit");
  });

  it("shows audit section when showAudit=true", () => {
    const parsed = makeBaseParsed();
    const audit = makeStrongAudit();
    printText(parsed, audit, true);
    expect(getOutput()).toContain("Audit");
  });

  it("shows algorithm verdict in audit section", () => {
    const parsed = makeBaseParsed();
    const audit = makeStrongAudit();
    printText(parsed, audit, true);
    expect(getOutput()).toContain("Algorithm");
    expect(getOutput()).toContain("RS256");
  });

  it("shows expiry status in audit section for valid token", () => {
    const parsed = makeBaseParsed();
    const audit = makeStrongAudit(false);
    printText(parsed, audit, true);
    expect(getOutput()).toContain("Expiry");
    expect(getOutput()).toContain("valid");
  });

  it("shows EXPIRED in audit section for expired token", () => {
    const parsed = makeBaseParsed({
      payload: { sub: "u1", exp: FIXED_NOW_S - 3600 },
    });
    const audit = makeStrongAudit(true);
    printText(parsed, audit, true);
    expect(getOutput()).toContain("EXPIRED");
  });

  it("shows no-exp warning in audit when token has no expiry", () => {
    const parsed = makeBaseParsed({ payload: { sub: "u1" } });
    const noExpAudit: JwtAudit = {
      ...makeStrongAudit(),
      expiry: {
        hasExpiry: false,
        isExpired: false,
        expiresAt: null,
        issuedAt: null,
        notBefore: null,
        secondsUntilExpiry: null,
      },
    };
    printText(parsed, noExpAudit, true);
    const output = getOutput();
    expect(output).toContain("no 'exp' claim");
  });

  it("shows missing claims in audit section", () => {
    const parsed = makeBaseParsed({ payload: { sub: "u1" } });
    const missingClaimsAudit: JwtAudit = {
      ...makeStrongAudit(),
      claims: {
        hasIssuer: false,
        hasAudience: false,
        hasSubject: true,
        hasJti: false,
      },
    };
    printText(parsed, missingClaimsAudit, true);
    const output = getOutput();
    expect(output).toContain("missing");
    expect(output).toContain("iss");
    expect(output).toContain("aud");
    expect(output).toContain("jti");
  });

  it("shows all-claims-present message when all four present", () => {
    const parsed = makeBaseParsed();
    const audit = makeStrongAudit();
    printText(parsed, audit, true);
    const output = getOutput();
    expect(output).toContain("iss, sub, aud, jti all present");
  });

  it("displays exp as a unix timestamp with ISO date", () => {
    const parsed = makeBaseParsed();
    const audit = makeStrongAudit();
    printText(parsed, audit, false);
    const output = getOutput();
    // The exp value is a unix timestamp number
    expect(output).toContain(String(FIXED_NOW_S + 3600));
  });

  it("displays custom claims in a Custom claims section", () => {
    const parsed = makeBaseParsed({
      payload: {
        sub: "u1",
        role: "admin",
        permissions: ["read", "write"],
      },
    });
    const audit = makeStrongAudit();
    printText(parsed, audit, false);
    const output = getOutput();
    expect(output).toContain("Custom claims");
    expect(output).toContain("role");
    expect(output).toContain("admin");
  });

  it("does not show Custom claims section when payload has only standard claims", () => {
    const parsed = makeBaseParsed({
      payload: { iss: "https://example.com", sub: "u1", exp: FIXED_NOW_S + 100 },
    });
    const audit = makeStrongAudit();
    printText(parsed, audit, false);
    const output = getOutput();
    expect(output).not.toContain("Custom claims");
  });

  it("outputs expires-in duration for non-expired token in payload section", () => {
    vi.useFakeTimers();
    vi.setSystemTime(FIXED_NOW_S * 1000);

    const parsed = makeBaseParsed();
    const audit = makeStrongAudit(false);
    printText(parsed, audit, false);
    const output = getOutput();
    // Should contain something about expiration time remaining
    expect(output).toMatch(/expires in|1h/);

    vi.useRealTimers();
  });

  it("outputs expired-duration for expired token in payload section", () => {
    vi.useFakeTimers();
    vi.setSystemTime(FIXED_NOW_S * 1000);

    const parsed = makeBaseParsed({
      payload: { sub: "u1", exp: FIXED_NOW_S - 3600 },
    });
    const audit = makeStrongAudit(true);
    printText(parsed, audit, false);
    const output = getOutput();
    expect(output).toMatch(/expired.*ago/);

    vi.useRealTimers();
  });

  it("displays nbf timestamp with ISO date format", () => {
    const nbf = FIXED_NOW_S - 120;
    const parsed = makeBaseParsed({
      payload: { sub: "u1", nbf },
    });
    const audit: JwtAudit = {
      ...makeStrongAudit(),
      expiry: { ...makeStrongAudit().expiry, notBefore: new Date(nbf * 1000) },
    };
    printText(parsed, audit, false);
    const output = getOutput();
    expect(output).toContain(String(nbf));
  });

  it("displays iat timestamp with ISO date format", () => {
    const iat = FIXED_NOW_S - 500;
    const parsed = makeBaseParsed({
      payload: { sub: "u1", iat },
    });
    printText(parsed, makeStrongAudit(), false);
    const output = getOutput();
    expect(output).toContain(String(iat));
  });
});

// ---------------------------------------------------------------------------
// formatDuration (private — tested indirectly via printText output)
// ---------------------------------------------------------------------------

describe("printText — formatDuration indirectly", () => {
  let consoleSpy: ReturnType<typeof vi.spyOn>;
  let capturedLines: string[];

  beforeEach(() => {
    capturedLines = [];
    consoleSpy = vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      capturedLines.push(args.map(String).join(" "));
    });
    vi.useFakeTimers();
    vi.setSystemTime(FIXED_NOW_S * 1000);
  });

  afterEach(() => {
    consoleSpy.mockRestore();
    vi.useRealTimers();
  });

  function getOutput(): string {
    return stripAnsi(capturedLines.join("\n"));
  }

  it("shows seconds for durations under 1 minute", () => {
    const parsed = makeBaseParsed({ payload: { sub: "u1", exp: FIXED_NOW_S + 45 } });
    const audit: JwtAudit = { ...makeStrongAudit(), expiry: { ...makeStrongAudit().expiry, isExpired: false, secondsUntilExpiry: 45 } };
    printText(parsed, audit, false);
    expect(getOutput()).toContain("45s");
  });

  it("shows minutes+seconds for durations under 1 hour", () => {
    const parsed = makeBaseParsed({ payload: { sub: "u1", exp: FIXED_NOW_S + 125 } });
    const audit: JwtAudit = { ...makeStrongAudit(), expiry: { ...makeStrongAudit().expiry, isExpired: false, secondsUntilExpiry: 125 } };
    printText(parsed, audit, false);
    expect(getOutput()).toContain("2m 5s");
  });

  it("shows hours+minutes for durations under 1 day", () => {
    const parsed = makeBaseParsed({ payload: { sub: "u1", exp: FIXED_NOW_S + 7380 } });
    // 7380 seconds = 2h 3m
    const audit: JwtAudit = { ...makeStrongAudit(), expiry: { ...makeStrongAudit().expiry, isExpired: false, secondsUntilExpiry: 7380 } };
    printText(parsed, audit, false);
    expect(getOutput()).toContain("2h 3m");
  });

  it("shows days+hours for durations of 1+ day", () => {
    const parsed = makeBaseParsed({ payload: { sub: "u1", exp: FIXED_NOW_S + 90000 } });
    // 90000 seconds = 1d 1h
    const audit: JwtAudit = { ...makeStrongAudit(), expiry: { ...makeStrongAudit().expiry, isExpired: false, secondsUntilExpiry: 90000 } };
    printText(parsed, audit, false);
    expect(getOutput()).toContain("1d 1h");
  });
});
