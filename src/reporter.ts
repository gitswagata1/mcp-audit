import type { AuditResult, Finding, McpServer, Severity, Category, Grade, ServerScore, PolicyReport } from "./types.js";

const SEVERITY_CONFIG: Record<Severity, { icon: string; color: string; label: string }> = {
  critical: { icon: "\u{1F6D1}", color: "\x1b[91m", label: "CRITICAL" },
  high:     { icon: "\u{1F7E0}", color: "\x1b[33m", label: "HIGH" },
  medium:   { icon: "\u{1F7E1}", color: "\x1b[93m", label: "MEDIUM" },
  low:      { icon: "\u{1F535}", color: "\x1b[94m", label: "LOW" },
  info:     { icon: "\u{2139}\u{FE0F}",  color: "\x1b[90m", label: "INFO" },
};

const CATEGORY_LABELS: Record<Category, string> = {
  "permissions": "Permissions",
  "secrets": "Secrets",
  "supply-chain": "Supply Chain",
  "transport": "Transport",
  "config-hygiene": "Config Hygiene",
  "environment": "Environment",
};

const GRADE_CONFIG: Record<Grade, { color: string; icon: string }> = {
  A: { color: "\x1b[32m",  icon: "\u{1F7E2}" },
  B: { color: "\x1b[94m",  icon: "\u{1F535}" },
  C: { color: "\x1b[93m",  icon: "\u{1F7E1}" },
  D: { color: "\x1b[33m",  icon: "\u{1F7E0}" },
  F: { color: "\x1b[91m",  icon: "\u{1F534}" },
};

const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const CYAN = "\x1b[36m";
const GREEN = "\x1b[32m";
const RED = "\x1b[91m";
const WHITE = "\x1b[97m";
const YELLOW = "\x1b[33m";

export function printReport(result: AuditResult, verbose: boolean = false): void {
  console.log();
  console.log(`${BOLD}${CYAN}  mcp-audit${RESET}${DIM} v${result.version} — security scanner for MCP servers${RESET}`);
  console.log(`${DIM}  ${"─".repeat(56)}${RESET}`);
  console.log();

  if (result.scannedPaths.length > 0 && verbose) {
    console.log(`  ${DIM}Scanned config paths:${RESET}`);
    for (const p of result.scannedPaths) {
      console.log(`  ${DIM}  ✓ ${p}${RESET}`);
    }
    console.log();
  }

  printServers(result.servers, result.serverScores, verbose);
  printFindings(result.findings, verbose);
  if (result.policy) printSuppressions(result.policy);
  printSummary(result);
}

function printSuppressions(policy: PolicyReport): void {
  if (policy.suppressed.length === 0) return;

  console.log(`  ${DIM}${BOLD}Suppressed by policy: ${policy.suppressed.length}${RESET}`);
  console.log();
  for (const f of policy.suppressed) {
    const cat = CATEGORY_LABELS[f.category] ?? f.category;
    console.log(`  ${DIM}  ◦ [${cat}] ${f.title} — ${f.server}${RESET}`);
    console.log(`  ${DIM}    ${f.reason}${RESET}`);
  }
  console.log();
}

function printServers(servers: McpServer[], scores: ServerScore[], verbose: boolean): void {
  if (servers.length === 0) {
    console.log(`  ${DIM}No MCP servers found.${RESET}`);
    console.log();
    return;
  }

  console.log(`  ${BOLD}${WHITE}Servers discovered: ${servers.length}${RESET}`);
  console.log();

  for (const s of servers) {
    const ss = scores.find(sc => sc.server === s.name && sc.source === s.source);
    const transport = s.url ? `${DIM}${YELLOW}remote${RESET}` : `${DIM}stdio${RESET}`;

    let gradeTag = "";
    if (ss) {
      const gc = GRADE_CONFIG[ss.grade];
      gradeTag = `  ${gc.icon} ${gc.color}${BOLD}${ss.grade}${RESET}`;
      if (ss.findingCount > 0) {
        gradeTag += ` ${DIM}(${ss.findingCount} issue${ss.findingCount > 1 ? "s" : ""})${RESET}`;
      }
    }

    console.log(`  ${BOLD}${s.name}${RESET}  ${DIM}(${s.source})${RESET}  ${transport}${gradeTag}`);

    if (s.command) {
      console.log(`  ${DIM}  cmd: ${s.command} ${s.args.join(" ")}${RESET}`);
    }
    if (s.url) {
      console.log(`  ${DIM}  url: ${s.url}${RESET}`);
    }

    const envKeys = Object.keys(s.env);
    if (envKeys.length > 0) {
      console.log(`  ${DIM}  env: ${envKeys.join(", ")}${RESET}`);
    }

    if (verbose && s.sourcePath) {
      console.log(`  ${DIM}  file: ${s.sourcePath}${RESET}`);
    }

    console.log();
  }
}

function printFindings(findings: Finding[], verbose: boolean): void {
  if (findings.length === 0) {
    console.log(`  ${GREEN}${BOLD}✅ No security issues found.${RESET}`);
    console.log();
    return;
  }

  console.log(`  ${BOLD}${WHITE}Findings: ${findings.length}${RESET}`);
  console.log();

  for (const f of findings) {
    const cfg = SEVERITY_CONFIG[f.severity];
    const cat = CATEGORY_LABELS[f.category] ?? f.category;
    console.log(`  ${cfg.icon} ${cfg.color}${BOLD}${cfg.label}${RESET} ${DIM}[${cat}]${RESET} ${BOLD}${f.title}${RESET}`);
    console.log(`  ${DIM}  ${f.detail}${RESET}`);

    if (verbose || f.severity === "critical" || f.severity === "high") {
      console.log(`  ${GREEN}  → ${f.recommendation}${RESET}`);
    }

    console.log(`  ${DIM}  server: ${f.server} · source: ${f.source}${RESET}`);
    console.log();
  }
}

function printSummary(result: AuditResult): void {
  console.log(`  ${DIM}${"─".repeat(56)}${RESET}`);

  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of result.findings) counts[f.severity]++;

  const categoryCounts: Record<string, number> = {};
  for (const f of result.findings) {
    categoryCounts[f.category] = (categoryCounts[f.category] ?? 0) + 1;
  }

  const parts: string[] = [];
  for (const [sev, count] of Object.entries(counts)) {
    if (count === 0) continue;
    const cfg = SEVERITY_CONFIG[sev as Severity];
    parts.push(`${cfg.color}${count} ${cfg.label.toLowerCase()}${RESET}`);
  }

  const gc = GRADE_CONFIG[result.grade];
  console.log();
  console.log(`  ${gc.icon} ${gc.color}${BOLD}Security Grade: ${result.grade}${RESET}  ${DIM}(${result.score}/100)${RESET}`);

  const affectedServers = result.serverScores.filter(s => s.findingCount > 0).length;
  if (result.servers.length > 0) {
    if (affectedServers === 0) {
      console.log(`  ${GREEN}${BOLD}✅ All ${result.servers.length} servers passed${RESET}`);
    } else {
      console.log(`  ${affectedServers} of ${result.servers.length} servers have issues`);
    }
  }

  console.log(`  ${result.findings.length} findings${parts.length ? " (" + parts.join(", ") + ")" : ""}`);

  if (Object.keys(categoryCounts).length > 0) {
    const catParts = Object.entries(categoryCounts)
      .sort((a, b) => b[1] - a[1])
      .map(([cat, count]) => `${count} ${CATEGORY_LABELS[cat as Category]?.toLowerCase() ?? cat}`);
    console.log(`  ${DIM}by category: ${catParts.join(", ")}${RESET}`);
  }

  console.log(`  ${DIM}${result.scannedPaths.length} config paths scanned · ${result.timestamp}${RESET}`);
  console.log();
}
