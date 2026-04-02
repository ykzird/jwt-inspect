import chalk from "chalk";
import type { ParsedJwt, JwtAudit } from "./jwt.js";

function formatDuration(seconds: number): string {
  const abs = Math.abs(seconds);
  if (abs < 60) return `${abs}s`;
  if (abs < 3600) return `${Math.floor(abs / 60)}m ${abs % 60}s`;
  if (abs < 86400) return `${Math.floor(abs / 3600)}h ${Math.floor((abs % 3600) / 60)}m`;
  return `${Math.floor(abs / 86400)}d ${Math.floor((abs % 86400) / 3600)}h`;
}

export function printText(parsed: ParsedJwt, audit: JwtAudit, showAudit: boolean): void {
  // Header section
  console.log(chalk.bold.cyan("\n── Header ──────────────────────────────────"));
  for (const [key, value] of Object.entries(parsed.header)) {
    const label = chalk.dim(key.padEnd(6));
    const val = key === "alg" && audit.algorithm.isWeak
      ? chalk.red(String(value))
      : chalk.white(String(value));
    console.log(`  ${label}  ${val}`);
  }

  // Payload section
  console.log(chalk.bold.cyan("\n── Payload ─────────────────────────────────"));

  const knownClaims = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];
  const customClaims = Object.keys(parsed.payload).filter(k => !knownClaims.includes(k));

  const formatTimestamp = (ts: number): string => {
    const date = new Date(ts * 1000);
    return `${ts}  (${date.toISOString()})`;
  };

  for (const key of knownClaims) {
    const value = parsed.payload[key];
    if (value === undefined) continue;

    const label = chalk.dim(key.padEnd(6));
    let formatted: string;

    if (key === "exp") {
      const { isExpired, secondsUntilExpiry } = audit.expiry;
      const timeStr = secondsUntilExpiry !== null
        ? isExpired
          ? chalk.red(`expired ${formatDuration(secondsUntilExpiry)} ago`)
          : chalk.green(`expires in ${formatDuration(secondsUntilExpiry)}`)
        : "";
      formatted = `${chalk.white(formatTimestamp(value as number))}  ${timeStr}`;
    } else if (key === "iat" || key === "nbf") {
      formatted = chalk.white(formatTimestamp(value as number));
    } else {
      formatted = chalk.white(JSON.stringify(value));
    }

    console.log(`  ${label}  ${formatted}`);
  }

  if (customClaims.length > 0) {
    console.log(chalk.dim("\n  Custom claims:"));
    for (const key of customClaims) {
      const label = chalk.dim(key.padEnd(6));
      console.log(`  ${label}  ${chalk.white(JSON.stringify(parsed.payload[key]))}`);
    }
  }

  // Signature
  console.log(chalk.bold.cyan("\n── Signature ───────────────────────────────"));
  console.log(`  ${chalk.dim(parsed.signatureRaw.slice(0, 40))}${parsed.signatureRaw.length > 40 ? chalk.dim("…") : ""}`);
  console.log(chalk.dim(`  (${parsed.signatureRaw.length} base64url chars — not verified)`));

  // Audit section
  if (showAudit) {
    console.log(chalk.bold.cyan("\n── Audit ───────────────────────────────────"));

    // Algorithm
    const algIcon = audit.algorithm.verdict === "strong" ? chalk.green("✔") :
                    audit.algorithm.verdict === "weak"   ? chalk.red("✘") :
                                                           chalk.yellow("?");
    console.log(`  ${algIcon} Algorithm: ${chalk.white(audit.algorithm.value ?? "missing")}  — ${chalk.dim(audit.algorithm.note)}`);

    // Expiry
    if (!audit.expiry.hasExpiry) {
      console.log(`  ${chalk.yellow("?")} Expiry:    ${chalk.yellow("no 'exp' claim")}  — ${chalk.dim("token never expires")}`);
    } else if (audit.expiry.isExpired) {
      console.log(`  ${chalk.red("✘")} Expiry:    ${chalk.red("EXPIRED")}`);
    } else {
      console.log(`  ${chalk.green("✔")} Expiry:    ${chalk.green("valid")}`);
    }

    // Claims coverage
    const missingClaims = [
      !audit.claims.hasIssuer   && "iss",
      !audit.claims.hasAudience && "aud",
      !audit.claims.hasSubject  && "sub",
      !audit.claims.hasJti      && "jti",
    ].filter(Boolean);

    if (missingClaims.length > 0) {
      console.log(`  ${chalk.yellow("?")} Claims:    missing ${chalk.yellow(missingClaims.join(", "))}  — ${chalk.dim("reduces token specificity")}`);
    } else {
      console.log(`  ${chalk.green("✔")} Claims:    iss, sub, aud, jti all present`);
    }
  }

  console.log("");
}

export function printJson(parsed: ParsedJwt, audit: JwtAudit): void {
  console.log(JSON.stringify({ header: parsed.header, payload: parsed.payload, audit }, null, 2));
}
