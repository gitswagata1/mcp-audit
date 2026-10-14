import type { AuditResult, Category, Finding, McpServer, Severity } from "./types.js";

// SARIF v2.1.0 — https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

export type SarifLevel = "error" | "warning" | "note";

export interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  help: { text: string };
  defaultConfiguration: { level: SarifLevel };
  properties: {
    category: Category;
    tags: string[];
    "security-severity"?: string;
  };
}

export interface SarifLocation {
  physicalLocation: {
    artifactLocation: { uri: string };
    region: { startLine: number; startColumn: number };
  };
  logicalLocations: Array<{ name: string; kind: string }>;
}

export interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: SarifLevel;
  message: { text: string };
  locations: SarifLocation[];
  properties: {
    severity: Severity;
    category: Category;
    source: string;
  };
}

export interface SarifReport {
  $schema: string;
  version: "2.1.0";
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: SarifRule[];
      };
    };
    results: SarifResult[];
    properties: { grade: string; score: number };
  }>;
}

const SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

// GitHub code scanning reads this rule property to bucket alerts (critical > 9.0, high 7.0–8.9, ...).
const SECURITY_SEVERITY: Partial<Record<Severity, string>> = {
  critical: "9.5",
  high: "8.0",
  medium: "5.5",
  low: "2.0",
};

// Titles that embed a dynamic value (e.g. the secret provider) in the middle of the text.
// Titles of the form "Label: dynamic value" are handled generically in genericTitle().
const TEMPLATED_TITLES: Array<[RegExp, string]> = [
  [/^Hardcoded .+ secret$/, "Hardcoded secret"],
  [/^.+ key in non-standard env var$/, "Secret key in non-standard env var"],
  [/^.+ secret in command args$/, "Secret in command args"],
];

export function severityToSarifLevel(severity: Severity): SarifLevel {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    default:
      return "note";
  }
}

/** Finding title with per-instance details removed, e.g. "Dangerous flag: --no-sandbox" -> "Dangerous flag". */
export function genericTitle(title: string): string {
  for (const [pattern, generic] of TEMPLATED_TITLES) {
    if (pattern.test(title)) return generic;
  }
  return title.replace(/:\s.*$/, "").trim();
}

function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

/** Stable rule id: "<category>/<slug>", e.g. "secrets/hardcoded-secret". */
export function ruleIdFor(finding: Finding): string {
  // Trailing parentheticals are qualifiers ("Shadow server (same name, different command)") — keep ids short.
  const base = genericTitle(finding.title).replace(/\s*\([^)]*\)\s*$/, "");
  return `${finding.category}/${slugify(base) || "finding"}`;
}

function ruleName(id: string): string {
  const slug = id.slice(id.indexOf("/") + 1);
  return slug
    .split("-")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join("");
}

/** Converts a filesystem path to a SARIF artifact URI (forward slashes, file:// for absolute paths). */
export function toSarifUri(filePath: string): string {
  const normalized = filePath.replace(/\\/g, "/");
  const encoded = encodeURI(normalized).replace(/#/g, "%23").replace(/\?/g, "%3F");
  if (normalized.startsWith("/")) return `file://${encoded}`;
  if (/^[a-zA-Z]:\//.test(normalized)) return `file:///${encoded}`;
  return encoded;
}

function resolveConfigPaths(finding: Finding, result: AuditResult): string[] {
  const exact = result.servers.find((s) => s.name === finding.server && s.source === finding.source);
  if (exact) return [exact.sourcePath];

  // Config-file findings (e.g. file permissions) carry the config path as their source.
  if (result.scannedPaths.includes(finding.source)) return [finding.source];

  // Cross-config findings: duplicate/shadow servers ("a"), shared credentials ("a, b").
  const names = new Set([finding.server, ...finding.server.split(", ")]);
  const matches: McpServer[] = result.servers.filter((s) => names.has(s.name));
  const paths = [...new Set(matches.map((s) => s.sourcePath).filter(Boolean))];
  if (paths.length > 0) return paths;

  return result.scannedPaths.length > 0 ? [result.scannedPaths[0]] : [];
}

export function generateSarif(result: AuditResult): SarifReport {
  const rules: SarifRule[] = [];
  const ruleIndex = new Map<string, number>();
  const worstSeverity: Severity[] = [];

  const results: SarifResult[] = result.findings.map((f) => {
    const ruleId = ruleIdFor(f);
    let index = ruleIndex.get(ruleId);

    if (index === undefined) {
      index = rules.length;
      ruleIndex.set(ruleId, index);
      worstSeverity.push(f.severity);
      rules.push({
        id: ruleId,
        name: ruleName(ruleId),
        shortDescription: { text: genericTitle(f.title) },
        help: { text: f.recommendation },
        defaultConfiguration: { level: severityToSarifLevel(f.severity) },
        properties: { category: f.category, tags: ["security", f.category] },
      });
    } else if (SEVERITY_RANK[f.severity] < SEVERITY_RANK[worstSeverity[index]]) {
      worstSeverity[index] = f.severity;
    }

    return {
      ruleId,
      ruleIndex: index,
      level: severityToSarifLevel(f.severity),
      message: { text: `${f.title}: ${f.detail}\nRecommendation: ${f.recommendation}` },
      locations: resolveConfigPaths(f, result).map((p) => ({
        physicalLocation: {
          artifactLocation: { uri: toSarifUri(p) },
          region: { startLine: 1, startColumn: 1 },
        },
        logicalLocations: [{ name: f.server, kind: "configuration" }],
      })),
      properties: { severity: f.severity, category: f.category, source: f.source },
    };
  });

  // A rule's default level / security-severity reflects the worst finding reported for it.
  rules.forEach((rule, i) => {
    rule.defaultConfiguration.level = severityToSarifLevel(worstSeverity[i]);
    const securitySeverity = SECURITY_SEVERITY[worstSeverity[i]];
    if (securitySeverity) rule.properties["security-severity"] = securitySeverity;
  });

  return {
    $schema: SARIF_SCHEMA,
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "mcp-audit",
            version: result.version,
            informationUri: "https://github.com/gitswagata1/mcp-audit",
            rules,
          },
        },
        results,
        properties: { grade: result.grade, score: result.score },
      },
    ],
  };
}
