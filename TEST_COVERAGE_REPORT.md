# Test Coverage Report — `@local/jwt-inspect`

Generated: 2026-04-02  
Vitest: v3.2.4 | Coverage provider: v8 (`@vitest/coverage-v8@3.2.4`)

---

## Summary

| Metric        | Result        |
|---------------|---------------|
| Test files    | 3             |
| Total tests   | 109 (all pass)|
| Failures      | 0             |
| Stmt coverage | 80.32%        |
| Branch coverage | 93.05%      |
| Function coverage | 100%      |
| Line coverage | 80.32%        |

---

## Per-file Breakdown

| File       | Stmts  | Branches | Funcs | Lines | Uncovered lines |
|------------|--------|----------|-------|-------|-----------------|
| `index.ts` | 0%     | 100%     | 100%  | 0%    | 3–41            |
| `jwt.ts`   | 100%   | 100%     | 100%  | 100%  | —               |
| `lib.ts`   | 100%   | 100%     | 100%  | 100%  | —               |
| `output.ts`| 95.23% | 88.37%   | 100%  | 95.23%| 18, 47, 77–78   |
| **All**    | **80.32%** | **93.05%** | **100%** | **80.32%** | |

---

## Notes on uncovered code

### `index.ts` — lines 3–41 (0% statement/line coverage)

`index.ts` is the CLI entry point. It is not tested by the unit test suite by design — running it would require spawning a child process and passing arguments. The file is short (39 executable lines) and contains straightforward glue: argument parsing via `commander`, a format-validation guard, `parseJwt`/`auditJwt` calls, and a conditional dispatch to `printText`/`printJson`. All three underlying functions (`parseJwt`, `auditJwt`, `printText`, `printJson`) are fully exercised through the other test files.

Branch coverage for `index.ts` shows 100% because v8 does not count branches inside dead-code-eliminated module-level statements the same way — the relevant logic is tiny and effectively covered indirectly.

**Gap:** The two error paths (`unknown format` + `parseJwt` throws → `process.exit(1)`) and the `--format json` vs. `--format text` dispatch are not tested. An integration/CLI test (e.g. using `execa` or Node's `child_process.spawnSync`) would close this gap.

### `output.ts` — lines 18, 47, 77–78 (4.77% uncovered)

- **Line 18** — the branch inside `printText` that applies `chalk.red` to a weak algorithm value in the header section. This branch requires a token whose header `alg` is flagged as weak AND whose header contains that key, and the test suite exercises the overall header rendering but always passes `isWeak: false` for the red-value path in the header loop.
- **Line 47** — the `""` fallback when `secondsUntilExpiry` is `null` in the `exp` formatting block. This happens when `exp` is defined but `secondsUntilExpiry` is `null`, which is a logically inconsistent state (the `ExpiryAudit` shape always sets both together), so it is unreachable in practice.
- **Lines 77–78** — the `chalk.yellow("?")` icon branch for the `"unknown"` algorithm verdict in the audit section (`printText` with `showAudit: true`). Tests cover `"strong"` and `"weak"` verdicts but not `"unknown"` in the audit display path.

---

## Test file descriptions

### `src/jwt.test.ts` — 62 tests

Covers `parseJwt` and `auditJwt` from `jwt.ts`.

**`parseJwt` — valid tokens (8 tests)**
- Returns correct `header`, `payload`, and `signatureRaw`.
- Preserves raw base64url strings in `.raw`.
- Handles tokens with no base64 padding.
- Handles all seven standard JWT claims (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`).
- Handles custom/non-standard claims.
- Handles `aud` as a string (not array).
- Handles empty payload `{}`.
- Handles empty signature segment.

**`parseJwt` — base64url decode edge cases (5 tests)**
- Decodes segments needing 1-byte padding (length % 4 === 3).
- Decodes segments needing 2-byte padding (length % 4 === 2).
- Round-trips base64url-specific characters (`-` and `_`).
- Handles unicode claim values (multi-byte UTF-8).
- Handles very large payloads (5 000-char string) without truncation.

**`parseJwt` — malformed inputs (10 tests)**
- Throws `"Invalid JWT structure"` on empty string, 1-part, 2-part, and 4-part inputs.
- Error message includes the actual part count (`"got N"`).
- Throws `"Failed to decode JWT header"` when header is invalid base64 or decodes to non-JSON.
- Throws `"Failed to decode JWT payload"` when payload is invalid base64 or decodes to non-JSON.
- Handles completely random strings.

**`auditJwt` — algorithm classification (18 tests)**
- Classifies `"HS256"` as `"weak"` with symmetric-secret note.
- Classifies `"none"`, `"None"`, `"NONE"` (all case variants) as `"weak"` with forgeable note.
- Classifies all 10 strong algorithms (`RS256/384/512`, `ES256/384/512`, `PS256/384/512`, `EdDSA`) as `"strong"` with asymmetric note — one test per algorithm.
- Classifies unrecognized algorithm as `"unknown"`.
- Classifies missing `alg` field as `"unknown"` with distinct note.
- Checks note text for `"none"` mentions forgeability, for HS256 mentions secret, for RS256 includes the algorithm name.

**`auditJwt` — expiry audit (11 tests, uses fake timers)**
- Detects expired token, `isExpired: true`, negative `secondsUntilExpiry`, correct `expiresAt`.
- Detects valid token, `isExpired: false`, positive `secondsUntilExpiry`.
- Boundary: `exp === now` is NOT expired (`now > exp` is false).
- Boundary: `exp === now - 1` IS expired.
- No `exp` claim: `hasExpiry: false`, `isExpired: false`, `expiresAt: null`, `secondsUntilExpiry: null`.
- `iat` present/absent mapping to `issuedAt`.
- `nbf` present/absent mapping to `notBefore`.
- Negative `secondsUntilExpiry` equals exact seconds elapsed since expiry.
- All three time claims together.

**`auditJwt` — claims audit (7 tests)**
- All four claims present (`iss`, `sub`, `aud`, `jti`).
- All four claims absent.
- Only `iss` present.
- `aud` as string detected.
- `aud` as array detected.
- Only `jti` present.
- Partial mix: `iss` + `sub` but not `aud` or `jti`.

**Integration (2 tests, uses fake timers)**
- Full RS256 token with all claims: strong algorithm, not expired, all claims present.
- Expired HS256 token with minimal claims: weak algorithm, expired, all claims absent.

---

### `src/lib.test.ts` — 9 tests

Covers `lib.ts` re-exports.

- Verifies `parseJwt` and `auditJwt` are exported as functions.
- Functional smoke tests via the re-export path (not directly from `jwt.ts`).
- Seven compile-time type checks: `JwtHeader`, `JwtPayload`, `ParsedJwt`, `JwtAudit`, `AlgorithmAudit`, `ExpiryAudit`, `ClaimsAudit` — TypeScript will error at collection time if any type export is missing.

---

### `src/output.test.ts` — 38 tests

Covers `printText` and `printJson` from `output.ts`. All tests spy on `console.log` and strip ANSI codes for plain-text assertions.

**`printJson` (8 tests)**
- Output is valid JSON.
- JSON contains correct `header` object.
- JSON contains correct `payload` fields.
- JSON `audit` object includes algorithm and expiry data.
- Expired token reflected correctly (`isExpired: true`).
- Weak algorithm reflected (`verdict: "weak"`).
- `signatureRaw` is not included at the top level.
- Custom claims appear in `payload`.
- Output is pretty-printed with 2-space indentation.

**`printText` — structure and sections (8 tests)**
- Outputs Header, Payload, and Signature section headings.
- Header `alg` value appears in output.
- Payload `sub` and `iss` values appear.
- Signature section contains `"not verified"`.
- Long signatures (>40 chars) are truncated with `"…"` ellipsis.
- Short signatures (<=40 chars) appear intact with no ellipsis.
- Signature character count appears in output.

**`printText` — audit section toggle (3 tests)**
- `showAudit: false` — no "Audit" heading.
- `showAudit: true` — "Audit" heading appears.
- Algorithm verdict and value shown in audit section.

**`printText` — expiry display (3 tests)**
- Valid token shows `"valid"` in expiry line.
- Expired token shows `"EXPIRED"`.
- No `exp` claim shows `"no 'exp' claim"`.

**`printText` — claims display (2 tests)**
- Missing claims listed with `"missing"` label.
- All four claims present shows `"iss, sub, aud, jti all present"`.

**`printText` — timestamp formatting (4 tests)**
- `exp` unix value appears in output.
- `exp` + `"expires in"` phrasing for a valid token (fake timer).
- `exp` + `"expired ... ago"` phrasing for an expired token (fake timer).
- `nbf` and `iat` unix values appear in output.

**`printText` — custom claims (2 tests)**
- Custom claims section appears with key and value when non-standard keys are present.
- No Custom claims section when payload contains only standard claims.

**`formatDuration` (tested indirectly — 4 tests)**
- `< 60s` → `"45s"`.
- `< 1h` → `"2m 5s"`.
- `< 1d` → `"2h 3m"`.
- `>= 1d` → `"1d 1h"`.

---

## Known gaps and recommendations

| Gap | Severity | Suggested fix |
|-----|----------|---------------|
| `index.ts` CLI entry point has 0% statement/line coverage | Medium | Add integration tests using `child_process.spawnSync` or `execa` to exercise the format guard, parse error path, and `--format json` / `--format text` dispatch. |
| `output.ts` line 18: weak-alg red-coloring in header loop not hit | Low | Add a `printText` test with `audit.algorithm.isWeak = true` and a token header that has an `alg` key. |
| `output.ts` line 47: null-`secondsUntilExpiry`-with-defined-`exp` fallback | Negligible | Logically unreachable given the current `auditJwt` contract; document as dead code or add a type-narrowing guard. |
| `output.ts` lines 77–78: `"unknown"` verdict icon in audit display | Low | Add a `printText` test with `showAudit: true` and `audit.algorithm.verdict = "unknown"`. |

Overall coverage is strong. The only structural gap is the CLI entry point, which is expected for unit test suites and would be addressed by a dedicated CLI integration test.
