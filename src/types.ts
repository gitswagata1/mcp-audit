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

export type OutputFormat = "text" | "json" | "markdown" | "sarif";

export interface CliOptions {
  format: OutputFormat;
  output: string | null;
  help: boolean;
  verbose: boolean;
  severity: Severity;
}
