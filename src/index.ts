#!/usr/bin/env node

import { Command } from "commander";
import { parseJwt, auditJwt } from "./jwt.js";
import { printText, printJson } from "./output.js";

const program = new Command();

program
  .name("jwt-inspect")
  .description("Decode and audit JWT tokens")
  .version("1.0.0")
  .argument("<token>", "JWT token to inspect")
  .option("--audit", "show security audit (algorithm strength, expiry, claims coverage)", false)
  .option("--format <fmt>", "output format: text or json", "text")
  .action((token: string, options: { audit: boolean; format: string }) => {
    const format = options.format;
    if (format !== "text" && format !== "json") {
      console.error(`Error: unknown format '${format}' — must be 'text' or 'json'`);
      process.exit(1);
    }

    let parsed;
    try {
      parsed = parseJwt(token.trim());
    } catch (err) {
      console.error(`Error: ${(err as Error).message}`);
      process.exit(1);
    }

    const audit = auditJwt(parsed);

    if (format === "json") {
      printJson(parsed, audit);
    } else {
      // In text mode, --audit is opt-in; in json mode, audit is always included
      printText(parsed, audit, options.audit);
    }
  });

program.parse();
