// Library entry point — import this when using jwt-inspect as a package.
// The CLI entry point (src/index.ts) is separate.

export { parseJwt, auditJwt } from "./jwt.js";
export type {
  JwtHeader,
  JwtPayload,
  ParsedJwt,
  JwtAudit,
  AlgorithmAudit,
  ExpiryAudit,
  ClaimsAudit,
} from "./jwt.js";
