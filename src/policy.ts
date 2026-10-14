import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import type {
  Category,
  Finding,
  McpServer,
  PolicyAllowRule,
  PolicyConfig,
  PolicyDenyRule,
  Severity,
  SuppressedFinding,
} from "./types.js";

export const POLICY_FILE_NAME = ".mcp-audit.yml";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const CATEGORIES = new Set<string>([
  "permissions", "secrets", "supply-chain", "transport", "config-hygiene", "environment",
] satisfies Category[]);

/** Error raised for missing, unreadable or invalid policy files. */
export class PolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyError";
  }
}

export function emptyPolicy(): PolicyConfig {
  return { allow: [], deny: [], severity: {}, files: [] };
}

// ---------------------------------------------------------------------------
// YAML subset parser (zero dependencies)
//
// Supports what policy files need: block mappings, block sequences (of scalars
// or mappings), flow sequences ([a, "b"]), quoted/plain scalars and comments.
// Anything else (anchors, block scalars, flow mappings, tabs) is rejected with
// a line-numbered error instead of being silently misread.
// ---------------------------------------------------------------------------

interface YamlLine {
  no: number;
  indent: number;
  text: string;
}

const KEY_RE = /^("(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^\s"'[\]{}#][^:]*?)\s*:(?:\s+|$)/;

export function parseYaml(content: string, filePath: string = POLICY_FILE_NAME): unknown {
  const fail = (no: number, msg: string) => new PolicyError(`Invalid policy file ${filePath} (line ${no}): ${msg}`);

  const lines: YamlLine[] = [];
  content.replace(/^\uFEFF/, "").split(/\r?\n/).forEach((raw, idx) => {
    const text = stripComment(raw).trimEnd();
    if (!text.trim()) return;
    const leading = /^[ \t]*/.exec(text)![0];
    if (leading.includes("\t")) throw fail(idx + 1, "tabs are not allowed for indentation");
    const body = text.slice(leading.length);
    if (body === "---" && leading.length === 0) return;
    lines.push({ no: idx + 1, indent: leading.length, text: body });
  });

  if (lines.length === 0) return null;

  let pos = 0;
  const result = parseBlock(lines[0].indent);
  if (pos < lines.length) throw fail(lines[pos].no, "unexpected indentation");
  return result;

  function parseBlock(indent: number): unknown {
    return isSeqItem(lines[pos].text) ? parseSeq(indent) : parseMap(indent);
  }

  function parseMap(indent: number): Record<string, unknown> {
    const obj: Record<string, unknown> = {};
    while (pos < lines.length) {
      const line = lines[pos];
      if (line.indent < indent) break;
      if (line.indent > indent) throw fail(line.no, "unexpected indentation");
      if (isSeqItem(line.text)) throw fail(line.no, `expected "key: value" but found a list item`);

      const m = KEY_RE.exec(line.text);
      if (!m) throw fail(line.no, `expected "key: value" but found "${line.text}"`);
      const key = unquote(m[1], line.no);
      if (Object.prototype.hasOwnProperty.call(obj, key)) throw fail(line.no, `duplicate key "${key}"`);
      const rest = line.text.slice(m[0].length).trim();
      pos++;

      if (rest) {
        obj[key] = parseScalar(rest, line.no);
      } else if (pos < lines.length && lines[pos].indent > indent) {
        obj[key] = parseBlock(lines[pos].indent);
      } else if (pos < lines.length && lines[pos].indent === indent && isSeqItem(lines[pos].text)) {
        obj[key] = parseSeq(indent);
      } else {
        obj[key] = null;
      }
    }
    return obj;
  }

  function parseSeq(indent: number): unknown[] {
    const list: unknown[] = [];
    while (pos < lines.length) {
      const line = lines[pos];
      if (line.indent < indent) break;
      if (line.indent > indent) throw fail(line.no, "unexpected indentation");
      if (!isSeqItem(line.text)) break;

      const rest = line.text.slice(1).trimStart();
      if (!rest) {
        pos++;
        list.push(pos < lines.length && lines[pos].indent > indent ? parseBlock(lines[pos].indent) : null);
      } else if (KEY_RE.test(rest)) {
        // "- key: value" starts a mapping whose keys align with "key".
        const itemIndent = line.indent + (line.text.length - rest.length);
        lines[pos] = { no: line.no, indent: itemIndent, text: rest };
        list.push(parseMap(itemIndent));
      } else {
        pos++;
        list.push(parseScalar(rest, line.no));
      }
    }
    return list;
  }

  function parseScalar(raw: string, no: number): unknown {
    const v = raw.trim();
    if (v.startsWith("[")) {
      if (!v.endsWith("]")) throw fail(no, `unterminated list "${v}"`);
      return splitFlow(v.slice(1, -1), no).map((item) => {
        if (item.startsWith("[") || item.startsWith("{")) throw fail(no, "nested collections are not supported");
        return parseScalar(item, no);
      });
    }
    if (v.startsWith("{")) throw fail(no, "inline mappings ({ ... }) are not supported; use indented key: value lines");
    if (v.startsWith("&") || v.startsWith("*")) throw fail(no, "anchors and aliases are not supported");
    if (v === "|" || v === ">" || /^[|>][-+]?$/.test(v)) throw fail(no, "block scalars are not supported");
    if (v.startsWith('"') || v.startsWith("'")) return unquote(v, no);
    if (v === "null" || v === "~") return null;
    return v;
  }

  function unquote(v: string, no: number): string {
    if (v.startsWith('"')) {
      if (v.length < 2 || !v.endsWith('"')) throw fail(no, `unterminated string ${v}`);
      try {
        return JSON.parse(v) as string;
      } catch {
        throw fail(no, `invalid escape sequence in ${v}`);
      }
    }
    if (v.startsWith("'")) {
      if (v.length < 2 || !v.endsWith("'")) throw fail(no, `unterminated string ${v}`);
      return v.slice(1, -1).replace(/''/g, "'");
    }
    return v;
  }

  function splitFlow(inner: string, no: number): string[] {
    const parts: string[] = [];
    let current = "";
    let quote: string | null = null;
    for (let i = 0; i < inner.length; i++) {
      const ch = inner[i];
      if (quote) {
        current += ch;
        if (quote === '"' && ch === "\\") current += inner[++i] ?? "";
        else if (ch === quote) quote = null;
      } else if (ch === '"' || ch === "'") {
        quote = ch;
        current += ch;
      } else if (ch === ",") {
        parts.push(current.trim());
        current = "";
      } else {
        current += ch;
      }
    }
    if (quote) throw fail(no, "unterminated string in list");
    parts.push(current.trim());
    if (parts.length > 0 && parts[parts.length - 1] === "") parts.pop(); // trailing comma / empty list
    if (parts.some((p) => p === "")) throw fail(no, "empty item in list");
    return parts;
  }
}

function isSeqItem(text: string): boolean {
  return text === "-" || text.startsWith("- ");
}

function stripComment(raw: string): string {
  let quote: string | null = null;
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (quote) {
      if (quote === '"' && ch === "\\") i++;
      else if (ch === quote) quote = null;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (ch === "#" && (i === 0 || /\s/.test(raw[i - 1]))) {
      return raw.slice(0, i);
    }
  }
  return raw;
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

const ALLOW_KEYS = ["server", "paths", "check"];
const DENY_KEYS = ["server", "args_pattern", "command_pattern", "url_pattern"];

/** Validates a parsed policy document and normalizes it into a PolicyConfig. */
export function validatePolicy(raw: unknown, filePath: string): PolicyConfig {
  const fail = (msg: string) => new PolicyError(`Invalid policy file ${filePath}: ${msg}`);
  const policy = emptyPolicy();
  policy.files.push(filePath);

  if (raw === null || raw === undefined) return policy; // empty file
  if (!isPlainObject(raw)) throw fail("expected a mapping with allow, deny and/or severity sections");

  for (const key of Object.keys(raw)) {
    if (!["allow", "deny", "severity"].includes(key)) {
      throw fail(`unknown section "${key}" (expected allow, deny or severity)`);
    }
  }

  const ruleList = (section: string, keys: string[]): Record<string, unknown>[] => {
    const value = raw[section];
    if (value === null || value === undefined) return [];
    if (!Array.isArray(value)) throw fail(`"${section}" must be a list of rules`);
    return value.map((item, i) => {
      const where = `${section}[${i}]`;
      if (!isPlainObject(item)) throw fail(`${where} must be a mapping (e.g. "- server: name")`);
      for (const k of Object.keys(item)) {
        if (!keys.includes(k)) throw fail(`${where} has unknown key "${k}" (expected ${keys.join(", ")})`);
      }
      return item;
    });
  };

  const optString = (rule: Record<string, unknown>, key: string, where: string): string | undefined => {
    const v = rule[key];
    if (v === null || v === undefined) return undefined;
    if (typeof v !== "string" || v.trim() === "") throw fail(`${where}.${key} must be a non-empty string`);
    return v;
  };

  ruleList("allow", ALLOW_KEYS).forEach((item, i) => {
    const where = `allow[${i}]`;
    const rule: PolicyAllowRule = {};
    const server = optString(item, "server", where);
    const check = optString(item, "check", where);
    if (server) rule.server = server;
    if (check) rule.check = check;

    const paths = item.paths;
    if (paths !== null && paths !== undefined) {
      const list = typeof paths === "string" ? [paths] : paths;
      if (!Array.isArray(list) || list.length === 0 || list.some((p) => typeof p !== "string" || p.trim() === "")) {
        throw fail(`${where}.paths must be a path or a non-empty list of paths`);
      }
      rule.paths = list as string[];
    }

    if (!rule.server && !rule.check && !rule.paths) throw fail(`${where} must set at least one of server, paths, check`);
    policy.allow.push(rule);
  });

  ruleList("deny", DENY_KEYS).forEach((item, i) => {
    const where = `deny[${i}]`;
    const rule: PolicyDenyRule = {};
    const server = optString(item, "server", where);
    if (server) rule.server = server;
    for (const key of ["args_pattern", "command_pattern", "url_pattern"] as const) {
      const v = optString(item, key, where);
      if (v) rule[key] = v;
    }
    if (!rule.args_pattern && !rule.command_pattern && !rule.url_pattern) {
      throw fail(`${where} must set at least one of args_pattern, command_pattern, url_pattern`);
    }
    policy.deny.push(rule);
  });

  const severity = raw.severity;
  if (severity !== null && severity !== undefined) {
    if (!isPlainObject(severity)) throw fail(`"severity" must be a mapping of check: level`);
    for (const [key, value] of Object.entries(severity)) {
      const level = typeof value === "string" ? value.toLowerCase() : value;
      if (!SEVERITIES.includes(level as Severity)) {
        throw fail(`severity "${key}" must be one of ${SEVERITIES.join(", ")} (got ${JSON.stringify(value)})`);
      }
      policy.severity[key] = level as Severity;
    }
  }

  return policy;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/**
 * Returns the policy files that apply, in merge order:
 * 1. Global: first of ~/.config/mcp-audit/.mcp-audit.yml, ~/.config/mcp-audit/policy.yml, ~/.mcp-audit.yml
 * 2. Project: <cwd>/.mcp-audit.yml
 */
export function findPolicyFiles(cwd: string = process.cwd(), home: string = homedir()): string[] {
  const files: string[] = [];
  const global = [
    join(home, ".config", "mcp-audit", POLICY_FILE_NAME),
    join(home, ".config", "mcp-audit", "policy.yml"),
    join(home, POLICY_FILE_NAME),
  ].find((p) => existsSync(p));
  if (global) files.push(resolve(global));

  const local = resolve(cwd, POLICY_FILE_NAME);
  if (existsSync(local) && !files.includes(local)) files.push(local);
  return files;
}

/**
 * Loads the policy. With an explicit path only that file is used; otherwise the
 * global and project policies are merged (project wins on conflicting severity keys).
 * Throws PolicyError for missing explicit files and invalid policies.
 */
export function loadPolicy(cwd: string = process.cwd(), explicitPath?: string, home: string = homedir()): PolicyConfig {
  let files: string[];
  if (explicitPath !== undefined) {
    if (explicitPath.trim() === "") throw new PolicyError("--policy requires a file path");
    const p = resolve(cwd, explicitPath);
    if (!existsSync(p)) throw new PolicyError(`Policy file not found: ${p}`);
    files = [p];
  } else {
    files = findPolicyFiles(cwd, home);
  }
  return mergePolicies(files.map(readPolicyFile));
}

function readPolicyFile(path: string): PolicyConfig {
  let content: string;
  try {
    content = readFileSync(path, "utf-8");
  } catch (err) {
    throw new PolicyError(`Failed to read policy file ${path}: ${(err as Error).message}`);
  }
  return validatePolicy(parseYaml(content, path), path);
}

/** Merges policies in order; rules accumulate, later severity overrides win. */
export function mergePolicies(policies: PolicyConfig[]): PolicyConfig {
  return policies.reduce<PolicyConfig>(
    (acc, p) => ({
      allow: [...acc.allow, ...p.allow],
      deny: [...acc.deny, ...p.deny],
      severity: { ...acc.severity, ...p.severity },
      files: [...acc.files, ...p.files],
    }),
    emptyPolicy(),
  );
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

function slug(s: string, keepWildcards = false): string {
  return s
    .toLowerCase()
    .replace(keepWildcards ? /[^a-z0-9*]+/g : /[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

/** Stable id derived from a finding title, e.g. "Dangerous flag: sandbox disabled" -> "dangerous-flag-sandbox-disabled". */
export function findingId(title: string): string {
  return slug(title);
}

/**
 * Whether a policy key (allow `check` or a `severity` key) refers to a finding.
 * - A category name (`secrets`, `supply-chain`, ...) matches every finding in that category.
 * - Anything else is normalized like a finding id and must match whole words of the
 *   finding id: `network-access`, `hardcoded`, `Unpinned package version`, `hardcoded-*-secret`.
 */
export function matchesCheck(finding: Pick<Finding, "category" | "title">, key: string): boolean {
  const k = slug(key, true);
  if (!k) return false;
  if (CATEGORIES.has(k)) return finding.category === k;
  const body = k.split("*").join("[a-z0-9-]*");
  return new RegExp(`(?:^|-)${body}(?:-|$)`).test(findingId(finding.title));
}

function globMatch(pattern: string | undefined, value: string): boolean {
  if (!pattern || pattern === "*") return true;
  const re = pattern.split("*").map((part) => part.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*");
  return new RegExp(`^${re}$`).test(value);
}

/** Cross-server findings list several servers ("a, b"); a rule must cover all of them. */
function serverMatches(pattern: string | undefined, findingServer: string): boolean {
  return findingServer.split(", ").every((name) => globMatch(pattern, name));
}

function isPathArg(arg: string): boolean {
  return arg.startsWith("/") || arg.startsWith("~") || /^[A-Z]:[\\/]/i.test(arg);
}

function normalizePath(p: string): string {
  let n = p.replace(/^~(?=$|[\\/])/, homedir()).replace(/\\/g, "/");
  if (/^[a-z]:/i.test(n)) n = n.toLowerCase();
  if (n.length > 1) n = n.replace(/\/+$/, "") || "/";
  return n;
}

function isWithin(arg: string, allowed: string): boolean {
  const a = normalizePath(arg);
  const b = normalizePath(allowed);
  return a === b || a.startsWith(b.endsWith("/") ? b : b + "/");
}

function allowRuleMatches(rule: PolicyAllowRule, finding: Finding, servers: McpServer[]): boolean {
  if (rule.server && !serverMatches(rule.server, finding.server)) return false;
  if (rule.check && !matchesCheck(finding, rule.check)) return false;
  if (rule.paths) {
    const server = servers.find((s) => s.name === finding.server && s.source === finding.source);
    if (!server) return false;
    const pathArgs = server.args.filter(isPathArg);
    // Unknown scope is never considered "inside" the approved paths.
    if (pathArgs.length === 0) return false;
    if (!pathArgs.every((arg) => rule.paths!.some((allowed) => isWithin(arg, allowed)))) return false;
  }
  return true;
}

function describeAllowRule(rule: PolicyAllowRule): string {
  const parts: string[] = [];
  if (rule.server) parts.push(`server "${rule.server}"`);
  if (rule.check) parts.push(`check "${rule.check}"`);
  if (rule.paths) parts.push(`paths ${rule.paths.join(", ")}`);
  return `allowed by policy (${parts.join(", ")})`;
}

/** Severity override for a finding: category keys apply first, the most specific title key wins. */
export function overrideSeverity(finding: Finding, overrides: Record<string, Severity>): Severity {
  let best: { rank: number; severity: Severity } | null = null;
  for (const [key, severity] of Object.entries(overrides)) {
    if (!matchesCheck(finding, key)) continue;
    const k = slug(key, true);
    const rank = CATEGORIES.has(k) ? 0 : 1 + k.replace(/\*/g, "").length;
    if (!best || rank >= best.rank) best = { rank, severity };
  }
  return best ? best.severity : finding.severity;
}

function denyFindings(servers: McpServer[], rules: PolicyDenyRule[]): Finding[] {
  const findings: Finding[] = [];
  for (const server of servers) {
    for (const rule of rules) {
      if (!globMatch(rule.server, server.name)) continue;

      const hits: { what: string; pattern: string; category: Category }[] = [];
      if (rule.args_pattern && server.args.join(" ").includes(rule.args_pattern)) {
        hits.push({ what: "args contain", pattern: rule.args_pattern, category: "permissions" });
      }
      if (rule.command_pattern && server.command.includes(rule.command_pattern)) {
        hits.push({ what: "command contains", pattern: rule.command_pattern, category: "permissions" });
      }
      if (rule.url_pattern && server.url.includes(rule.url_pattern)) {
        hits.push({ what: "URL contains", pattern: rule.url_pattern, category: "transport" });
      }

      for (const hit of hits) {
        findings.push({
          severity: "critical",
          category: hit.category,
          title: `Deny policy violated: ${hit.what} ${hit.pattern}`,
          detail: `Server "${server.name}" ${hit.what} "${hit.pattern}", which is forbidden by the policy file.`,
          recommendation: "Remove the forbidden configuration, or update the deny rule in your policy file if it is intentional.",
          server: server.name,
          source: server.source,
        });
      }
    }
  }
  return findings;
}

export interface PolicyOutcome {
  findings: Finding[];
  suppressed: SuppressedFinding[];
}

/**
 * Applies a policy to raw check results. Run this before computing grades so
 * suppressed findings and severity overrides are reflected in scores and exit codes.
 * - allow rules move matching findings to `suppressed`
 * - deny rules add critical findings (they cannot be allowlisted)
 * - severity overrides are applied to the remaining findings
 * - finally findings are filtered by `minSeverity` and sorted by severity
 */
export function applyPolicy(
  servers: McpServer[],
  findings: Finding[],
  policy: PolicyConfig,
  minSeverity: Severity = "info",
): PolicyOutcome {
  const active: Finding[] = [];
  const suppressed: SuppressedFinding[] = [];

  for (const finding of findings) {
    const rule = policy.allow.find((r) => allowRuleMatches(r, finding, servers));
    if (rule) {
      suppressed.push({ ...finding, reason: describeAllowRule(rule) });
      continue;
    }
    active.push(finding);
  }

  active.push(...denyFindings(servers, policy.deny));

  const threshold = SEVERITY_RANK[minSeverity];
  const visible = (f: Finding) => SEVERITY_RANK[f.severity] <= threshold;

  return {
    findings: active
      .map((f) => ({ ...f, severity: overrideSeverity(f, policy.severity) }))
      .filter(visible)
      .sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]),
    suppressed: suppressed.filter(visible),
  };
}
