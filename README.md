# @ykzird/jwt-inspect

Decode and security-audit JWT tokens from the command line or from your own code.

## Installation

```sh
# CLI — install globally
npm install -g @ykzird/jwt-inspect

# Library — add to a project
npm install @ykzird/jwt-inspect
```

## CLI usage

```sh
jwt-inspect <token>                  # decode and display header + payload
jwt-inspect <token> --audit          # include security audit section
jwt-inspect <token> --format json    # machine-readable JSON output
```

### Output — text mode

```
── Header ──────────────────────────────────
  alg    HS256
  typ    JWT

── Payload ─────────────────────────────────
  iss    "https://example.com"
  sub    "1234567890"
  aud    "myapp"
  exp    1700000000  (2023-11-14T22:13:20.000Z)  expires in 5d 3h
  iat    1699990000  (2023-11-14T19:26:40.000Z)

── Signature ───────────────────────────────
  SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c…
  (43 base64url chars — not verified)
```

With `--audit`:

```
── Audit ───────────────────────────────────
  ✘ Algorithm: HS256  — HS256 is a symmetric algorithm — secret must be kept confidential and should be long/random
  ✔ Expiry:    valid
  ? Claims:    missing jti  — reduces token specificity
```

### Output — JSON mode

Audit is always included in JSON output regardless of `--audit`.

```json
{
  "header": { "alg": "HS256", "typ": "JWT" },
  "payload": { "sub": "1234567890", "exp": 1700000000 },
  "audit": {
    "algorithm": {
      "value": "HS256",
      "isWeak": true,
      "isStrong": false,
      "verdict": "weak",
      "note": "HS256 is a symmetric algorithm — secret must be kept confidential and should be long/random"
    },
    "expiry": {
      "hasExpiry": true,
      "isExpired": false,
      "expiresAt": "2023-11-14T22:13:20.000Z",
      "issuedAt": null,
      "notBefore": null,
      "secondsUntilExpiry": 432000
    },
    "claims": {
      "hasIssuer": false,
      "hasAudience": false,
      "hasSubject": true,
      "hasJti": false
    }
  }
}
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--audit` | Show security audit section in text output | off |
| `--format <fmt>` | Output format: `text` or `json` | `text` |

### Algorithm classification

| Verdict | Algorithms |
|---------|-----------|
| `weak` | `none`, `HS256` |
| `strong` | `RS256/384/512`, `ES256/384/512`, `PS256/384/512`, `EdDSA` |
| `unknown` | anything else, or missing `alg` field |

## Library usage

### Parse a token

```ts
import { parseJwt } from '@ykzird/jwt-inspect';

const parsed = parseJwt(token);
// Throws if the token is not a valid 3-part JWT
```

`ParsedJwt` shape:

```ts
{
  header: {
    alg?: string;
    typ?: string;
    kid?: string;
    [key: string]: unknown;
  };
  payload: {
    iss?: string;   // issuer
    sub?: string;   // subject
    aud?: string | string[];
    exp?: number;   // unix timestamp
    nbf?: number;   // not before
    iat?: number;   // issued at
    jti?: string;   // JWT ID
    [key: string]: unknown;
  };
  signatureRaw: string;       // base64url-encoded signature (not verified)
  raw: {
    header: string;           // original base64url header segment
    payload: string;          // original base64url payload segment
  };
}
```

### Audit a parsed token

```ts
import { parseJwt, auditJwt } from '@ykzird/jwt-inspect';

const parsed = parseJwt(token);
const audit  = auditJwt(parsed);
```

`JwtAudit` shape:

```ts
{
  algorithm: {
    value:    string | undefined;               // value of the alg header field
    isWeak:   boolean;
    isStrong: boolean;
    verdict:  'strong' | 'weak' | 'unknown';
    note:     string;                           // human-readable explanation
  };
  expiry: {
    hasExpiry:          boolean;
    isExpired:          boolean;
    expiresAt:          Date | null;
    issuedAt:           Date | null;
    notBefore:          Date | null;
    secondsUntilExpiry: number | null;          // negative if already expired
  };
  claims: {
    hasIssuer:   boolean;   // iss
    hasAudience: boolean;   // aud
    hasSubject:  boolean;   // sub
    hasJti:      boolean;   // jti
  };
}
```

### Exported types

```ts
import type {
  ParsedJwt,
  JwtHeader,
  JwtPayload,
  JwtAudit,
  AlgorithmAudit,
  ExpiryAudit,
  ClaimsAudit,
} from '@ykzird/jwt-inspect';
```

## License

MIT
