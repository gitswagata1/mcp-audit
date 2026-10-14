export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Category = "permissions" | "secrets" | "supply-chain" | "transport" | "config-hygiene" | "environment";

export type Grade = "A" | "B" | "C" | "D" | "F";

export interface McpServer {
  name: string;
  command: string;
  args: string[];
  env: Record<string, string>;
  url: string;
  source: string;
  sourcePath: string;
}

export interface Finding {
  severity: Severity;
  category: Category;
  title: string;
  detail: string;
  recommendation: string;
  server: string;
  source: string;
}

export interface ServerScore {
  server: string;
  source: string;
  score: number;
  grade: Grade;
  findingCount: number;
  worstSeverity: Severity | null;
}

export interface AuditResult {
  version: string;
  servers: McpServer[];
  findings: Finding[];
  scannedPaths: string[];
  timestamp: string;
  grade: Grade;
  score: number;
  serverScores: ServerScore[];
  /** Present only when a policy file was loaded. */
  policy?: PolicyReport;
}

export interface PolicyAllowRule {
  /** Server name; supports `*` wildcards. Omitted = any server. */
  server?: string;
  /** Only allow when every path argument of the server is inside one of these paths. */
  paths?: string[];
  /** Category (e.g. `supply-chain`) or finding id/title (e.g. `unpinned-package-version`). */
  check?: string;
}

export interface PolicyDenyRule {
  /** Server name; supports `*` wildcards. Omitted = any server. */
  server?: string;
  args_pattern?: string;
  command_pattern?: string;
  url_pattern?: string;
}

export interface PolicyConfig {
  allow: PolicyAllowRule[];
  deny: PolicyDenyRule[];
  /** Severity overrides keyed by category or finding id/title. */
  severity: Record<string, Severity>;
  /** Policy files that were loaded, in merge order (global first, project last). */
  files: string[];
}

export interface SuppressedFinding extends Finding {
  /** Why the finding was suppressed (which allow rule matched). */
  reason: string;
}

export interface PolicyReport {
  files: string[];
  suppressed: SuppressedFinding[];
}

export interface McpConfig {
  mcpServers?: Record<string, RawServerEntry>;
}

export interface RawServerEntry {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
}

export interface CliOptions {
  json: boolean;
  help: boolean;
  verbose: boolean;
  markdown: boolean;
  severity: Severity;
  /** File given by --policy; null when no explicit policy file was requested. */
  policy: string | null;
  /** --no-policy: ignore global and project policy files. */
  noPolicy: boolean;
}
