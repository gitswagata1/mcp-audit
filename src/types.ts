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
  /** Concrete, machine-applicable fix for `recommendation`, when one can be derived from the config. */
  fix?: Fix;
  server: string;
  source: string;
}

/**
 * RFC 7396 JSON Merge Patch for a single server entry (e.g. `mcpServers.<name>`).
 * `args` replaces the whole array; an env value of `null` removes that variable.
 */
export interface ServerPatch {
  args?: string[];
  env?: Record<string, string | null>;
  url?: string;
}

export interface Fix {
  /** Config file the fix applies to. */
  file: string;
  /** Corrected fields to merge into the server's config entry. */
  patch?: ServerPatch;
  /** Shell command that applies the fix (e.g. chmod). */
  command?: string;
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
}
