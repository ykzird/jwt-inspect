// Known weak or deprecated JWT algorithms
const WEAK_ALGORITHMS = new Set(["none", "HS256"]);
const STRONG_ALGORITHMS = new Set(["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"]);

export interface JwtHeader {
  alg?: string;
  typ?: string;
  kid?: string;
  [key: string]: unknown;
}

export interface JwtPayload {
  iss?: string;   // issuer
  sub?: string;   // subject
  aud?: string | string[];  // audience
  exp?: number;   // expiry (unix timestamp)
  nbf?: number;   // not before (unix timestamp)
  iat?: number;   // issued at (unix timestamp)
  jti?: string;   // JWT ID
  [key: string]: unknown;
}

export interface ParsedJwt {
  header: JwtHeader;
  payload: JwtPayload;
  signatureRaw: string;
  raw: {
    header: string;
    payload: string;
  };
}

export interface JwtAudit {
  algorithm: AlgorithmAudit;
  expiry: ExpiryAudit;
  claims: ClaimsAudit;
}

export interface AlgorithmAudit {
  value: string | undefined;
  isWeak: boolean;
  isStrong: boolean;
  verdict: "strong" | "weak" | "unknown";
  note: string;
}

export interface ExpiryAudit {
  hasExpiry: boolean;
  isExpired: boolean;
  expiresAt: Date | null;
  issuedAt: Date | null;
  notBefore: Date | null;
  secondsUntilExpiry: number | null;
}

export interface ClaimsAudit {
  hasIssuer: boolean;
  hasAudience: boolean;
  hasSubject: boolean;
  hasJti: boolean;
}

// JWT uses base64url encoding — differs from standard base64 in two characters
function base64UrlDecode(input: string): string {
  // Pad to a multiple of 4, then swap url-safe chars back to standard base64
  const padded = input + "=".repeat((4 - (input.length % 4)) % 4);
  const standard = padded.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(standard, "base64").toString("utf8");
}

export function parseJwt(token: string): ParsedJwt {
  const parts = token.split(".");

  if (parts.length !== 3) {
    throw new Error(
      `Invalid JWT structure: expected 3 parts separated by '.', got ${parts.length}`
    );
  }

  const [rawHeader, rawPayload, signatureRaw] = parts as [string, string, string];

  let header: JwtHeader;
  let payload: JwtPayload;

  try {
    header = JSON.parse(base64UrlDecode(rawHeader)) as JwtHeader;
  } catch {
    throw new Error("Failed to decode JWT header — is this a valid JWT?");
  }

  try {
    payload = JSON.parse(base64UrlDecode(rawPayload)) as JwtPayload;
  } catch {
    throw new Error("Failed to decode JWT payload — is this a valid JWT?");
  }

  return { header, payload, signatureRaw, raw: { header: rawHeader, payload: rawPayload } };
}

export function auditJwt(parsed: ParsedJwt): JwtAudit {
  const alg = parsed.header.alg;

  const algorithmAudit: AlgorithmAudit = (() => {
    if (alg === undefined) {
      return { value: undefined, isWeak: false, isStrong: false, verdict: "unknown" as const, note: "No 'alg' field in header" };
    }
    if (alg.toLowerCase() === "none") {
      return { value: alg, isWeak: true, isStrong: false, verdict: "weak" as const, note: "Algorithm 'none' means no signature — token is trivially forgeable" };
    }
    if (WEAK_ALGORITHMS.has(alg)) {
      return { value: alg, isWeak: true, isStrong: false, verdict: "weak" as const, note: `${alg} is a symmetric algorithm — secret must be kept confidential and should be long/random` };
    }
    if (STRONG_ALGORITHMS.has(alg)) {
      return { value: alg, isWeak: false, isStrong: true, verdict: "strong" as const, note: `${alg} uses asymmetric cryptography` };
    }
    return { value: alg, isWeak: false, isStrong: false, verdict: "unknown" as const, note: `${alg} is not a recognized standard algorithm` };
  })();

  const now = Math.floor(Date.now() / 1000);
  const exp = parsed.payload.exp;
  const iat = parsed.payload.iat;
  const nbf = parsed.payload.nbf;

  const expiryAudit: ExpiryAudit = {
    hasExpiry: exp !== undefined,
    isExpired: exp !== undefined ? now > exp : false,
    expiresAt: exp !== undefined ? new Date(exp * 1000) : null,
    issuedAt: iat !== undefined ? new Date(iat * 1000) : null,
    notBefore: nbf !== undefined ? new Date(nbf * 1000) : null,
    secondsUntilExpiry: exp !== undefined ? exp - now : null,
  };

  const claimsAudit: ClaimsAudit = {
    hasIssuer: parsed.payload.iss !== undefined,
    hasAudience: parsed.payload.aud !== undefined,
    hasSubject: parsed.payload.sub !== undefined,
    hasJti: parsed.payload.jti !== undefined,
  };

  return { algorithm: algorithmAudit, expiry: expiryAudit, claims: claimsAudit };
}
