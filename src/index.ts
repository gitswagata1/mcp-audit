#!/usr/bin/env node

import { writeFileSync } from "fs";
import { discoverConfigs } from "./scanner.js";
import { runChecks } from "./checks/index.js";
import { printReport } from "./reporter.js";
import { renderMarkdown } from "./markdown.js";
import { generateSarif } from "./sarif.js";
import { computeGrade, computeServerScores } from "./scoring.js";
import type { AuditResult, CliOptions, OutputFormat, Severity } from "./types.js";

const VERSION = "0.3.0";
const VALID_SEVERITIES = new Set<Severity>(["critical", "high", "medium", "low", "info"]);
const VALID_FORMATS = new Set<OutputFormat>(["text", "json", "markdown", "sarif"]);

function usageError(message: string): never {
  console.error(`mcp-audit: ${message}`);
  console.error("Run 'mcp-audit --help' for usage.");
  process.exit(1);
}

function parseFormat(val: string | undefined): OutputFormat {
  if (!val) usageError("--format requires a value (text, json, markdown, sarif)");
  if (!VALID_FORMATS.has(val as OutputFormat)) {
    usageError(`unknown format "${val}". Allowed: text, json, markdown, sarif`);
  }
  return val as OutputFormat;
}

function parseOutput(val: string | undefined, flag: string): string {
  if (!val || val.startsWith("-")) usageError(`${flag} requires a file path`);
  return val;
}

function parseArgs(): CliOptions {
  const args = process.argv.slice(2);
  const opts: CliOptions = {
    format: "text",
    output: null,
    help: false,
    verbose: false,
    severity: "info",
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--help" || arg === "-h") opts.help = true;
    else if (arg === "--json") opts.format = "json";
    else if (arg === "--verbose" || arg === "-v") opts.verbose = true;
    else if (arg === "--markdown" || arg === "--md") opts.format = "markdown";
    else if (arg === "--format") opts.format = parseFormat(args[++i]);
    else if (arg.startsWith("--format=")) opts.format = parseFormat(arg.slice("--format=".length));
    else if (arg === "--output" || arg === "-o") opts.output = parseOutput(args[++i], arg);
    else if (arg.startsWith("--output=")) opts.output = parseOutput(arg.slice("--output=".length), "--output");
    else if (arg === "--severity" || arg === "-s") {
      const val = args[++i] as Severity;
      if (val && VALID_SEVERITIES.has(val)) opts.severity = val;
    }
  }

  if (opts.output && opts.format === "text" && !opts.help) {
    usageError("--output requires a file format: use --format json, markdown or sarif");
  }

  return opts;
}

function toJson(result: AuditResult): string {
  const safeResult = {
    ...result,
    servers: result.servers.map((s) => ({
      ...s,
      env: Object.fromEntries(
        Object.entries(s.env).map(([k]) => [k, "***"])
      ),
    })),
  };
  return JSON.stringify(safeResult, null, 2);
}

function render(result: AuditResult, format: Exclude<OutputFormat, "text">): string {
  if (format === "json") return toJson(result);
  if (format === "markdown") return renderMarkdown(result);
  return JSON.stringify(generateSarif(result), null, 2);
}

function main(): void {
  const opts = parseArgs();

  if (opts.help) {
    console.log(`
  ${"\x1b[1m\x1b[36m"}mcp-audit${"\x1b[0m"} v${VERSION} — security scanner for MCP servers

  Usage:
    npx mcp-audit                  Scan and audit all MCP server configs
    npx mcp-audit --format <fmt>   Output format: text (default), json, markdown, sarif
    npx mcp-audit --json           Shortcut for --format json (with scores and metadata)
    npx mcp-audit --markdown       Shortcut for --format markdown (for PRs, CI comments, docs)
    npx mcp-audit --format sarif   SARIF v2.1.0 (for GitHub Code Scanning / CI)
    npx mcp-audit -o <file>        Write the report to a file (--output <file>; needs a non-text format)
    npx mcp-audit --verbose        Show config paths, recommendations, file locations
    npx mcp-audit --severity high  Only show findings at this level or above
    npx mcp-audit --help           Full help

  Clients scanned:
    Claude Desktop, Claude Code, Cursor, Windsurf, Zed,
    Cline, Roo Code, Amazon Q, GitHub Copilot, VS Code (Continue)

  Check categories:
    Permissions     Shell access, filesystem scope, dangerous flags, command injection
    Secrets         Hardcoded API keys (25+ patterns), credentials in args
    Supply Chain    Unverified packages, unpinned versions, Docker misconfig
    Transport       HTTP vs HTTPS, embedded credentials, remote servers
    Environment     LD_PRELOAD, NODE_OPTIONS, proxy injection, PATH hijack
    Config Hygiene  Duplicate servers, file permissions, excess env vars

  Security grade:
    A (90-100)  B (75-89)  C (50-74)  D (25-49)  F (0-24)

  Exit codes:
    0  All clear (or only low/info findings)
    1  High-severity findings
    2  Critical-severity findings
`);
    process.exit(0);
  }

  const { servers, scannedPaths } = discoverConfigs();
  const findings = runChecks(servers, scannedPaths, opts.severity);
  const { grade, score } = computeGrade(findings);
  const serverScores = computeServerScores(servers, findings);

  const result: AuditResult = {
    version: VERSION,
    servers,
    findings,
    scannedPaths,
    timestamp: new Date().toISOString(),
    grade,
    score,
    serverScores,
  };

  if (opts.format === "text") {
    printReport(result, opts.verbose);
  } else if (opts.output) {
    try {
      writeFileSync(opts.output, render(result, opts.format) + "\n", "utf-8");
    } catch (err) {
      console.error(`mcp-audit: could not write ${opts.output}: ${(err as Error).message}`);
      process.exit(1);
    }
    console.error(`mcp-audit: wrote ${opts.format} report to ${opts.output}`);
  } else {
    console.log(render(result, opts.format));
  }

  if (findings.some((f) => f.severity === "critical")) process.exit(2);
  if (findings.some((f) => f.severity === "high")) process.exit(1);
}

main();
