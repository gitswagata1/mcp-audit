import type { McpServer, Finding } from "../types.js";
import { argsFix } from "../fixes.js";

const SHELL_COMMANDS = new Set([
  "bash", "sh", "zsh", "fish", "csh", "tcsh", "ksh", "dash",
  "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
  "nushell", "nu", "xonsh",
]);

const FILESYSTEM_PATTERNS = [
  /\bfilesystem\b/i,
  /\bfs[-_]?server\b/i,
  /\bfile[-_]?access\b/i,
  /\bfile[-_]?manager\b/i,
  /\breadfile\b/i,
  /\bwritefile\b/i,
];

const NETWORK_PATTERNS = [
  /\bfetch\b/i,
  /\bhttp\b/i,
  /\bpuppeteer\b/i,
  /\bplaywright\b/i,
  /\bbrowser\b/i,
  /\bscrape\b/i,
  /\bcrawl\b/i,
  /\bwebsocket\b/i,
  /\bproxy\b/i,
  /\brequest\b/i,
];

const DANGEROUS_ARGS = [
  { pattern: /--allow-write/i, label: "write access", sev: "high" as const },
  { pattern: /--allow-run/i, label: "command execution", sev: "critical" as const },
  { pattern: /--allow-net/i, label: "network access", sev: "high" as const },
  { pattern: /--allow-all/i, label: "all permissions", sev: "critical" as const },
  { pattern: /--no-sandbox/i, label: "sandbox disabled", sev: "critical" as const },
  { pattern: /--privileged/i, label: "privileged mode", sev: "critical" as const },
  { pattern: /--disable-seccomp/i, label: "seccomp disabled", sev: "critical" as const },
  { pattern: /\bsudo\b/i, label: "elevated privileges", sev: "critical" as const },
  { pattern: /--allow-env/i, label: "environment access", sev: "medium" as const },
  { pattern: /--allow-read=\//i, label: "root filesystem read", sev: "high" as const },
];

const SHELL_METACHARACTERS = /[|;&`$(){}!<>]/;

const OVERLY_BROAD_PATHS = [
  { pattern: /^\/$/,               label: "root filesystem (/)" },
  { pattern: /^~$/,                label: "entire home directory (~)" },
  { pattern: /^\/home$/,           label: "all home directories (/home)" },
  { pattern: /^\/Users$/,          label: "all user directories (/Users)" },
  { pattern: /^[A-Z]:\\$/i,        label: "drive root" },
  { pattern: /^[A-Z]:\\Users$/i,   label: "all user directories" },
  { pattern: /^\/etc$/,            label: "system config (/etc)" },
  { pattern: /^\/var$/,            label: "system data (/var)" },
  { pattern: /^\.\.$/,             label: "parent directory (..)" },
];

export function checkPermissions(server: McpServer): Finding[] {
  const findings: Finding[] = [];
  const fullCmd = [server.command, ...server.args].join(" ");

  if (SHELL_COMMANDS.has(server.command.toLowerCase())) {
    findings.push({
      severity: "critical",
      category: "permissions",
      title: "Direct shell access",
      detail: `Server "${server.name}" spawns a shell (${server.command}). This grants unrestricted command execution on your machine.`,
      recommendation: "Replace with a purpose-built MCP server that exposes only the specific tools needed. Never grant raw shell access.",
      server: server.name,
      source: server.source,
    });
  }

  if (FILESYSTEM_PATTERNS.some((p) => p.test(server.name) || server.args.some((a) => p.test(a)))) {
    const pathArgs = server.args.filter((a) => a.startsWith("/") || a.startsWith("~") || /^[A-Z]:\\/i.test(a));
    const scope = pathArgs.length ? pathArgs.join(", ") : "unknown scope";

    for (const pathArg of pathArgs) {
      for (const { pattern, label } of OVERLY_BROAD_PATHS) {
        if (pattern.test(pathArg)) {
          findings.push({
            severity: "critical",
            category: "permissions",
            title: "Overly broad filesystem scope",
            detail: `Server "${server.name}" has access to ${label}. This exposes sensitive system files and user data.`,
            recommendation: `Restrict to the minimum directory needed, e.g., a single project folder instead of "${pathArg}".`,
            fix: argsFix(server, (args) => args.map((a) => (a === pathArg ? "<project-dir>" : a))),
            server: server.name,
            source: server.source,
          });
        }
      }
    }

    if (!findings.some(f => f.title === "Overly broad filesystem scope" && f.server === server.name)) {
      findings.push({
        severity: "high",
        category: "permissions",
        title: "Filesystem access",
        detail: `Server "${server.name}" has filesystem access (${scope}). It can read and potentially modify files.`,
        recommendation: "Ensure the paths are scoped to the minimum needed. Prefer read-only access where possible.",
        server: server.name,
        source: server.source,
      });
    }
  }

  if (NETWORK_PATTERNS.some((p) => p.test(fullCmd) || p.test(server.name))) {
    findings.push({
      severity: "medium",
      category: "permissions",
      title: "Network access",
      detail: `Server "${server.name}" appears to have network/browser capabilities. It may access external services or exfiltrate data.`,
      recommendation: "Verify the server only connects to expected domains. Consider firewall rules or network policies.",
      server: server.name,
      source: server.source,
    });
  }

  for (const { pattern, label, sev } of DANGEROUS_ARGS) {
    if (server.args.some((a) => pattern.test(a))) {
      findings.push({
        severity: sev,
        category: "permissions",
        title: `Dangerous flag: ${label}`,
        detail: `Server "${server.name}" uses a flag granting ${label}.`,
        recommendation: `Remove the flag or replace with a more restrictive alternative.`,
        fix: argsFix(server, (args) => args.filter((a) => !pattern.test(a))),
        server: server.name,
        source: server.source,
      });
    }
  }

  for (const arg of server.args) {
    if (SHELL_METACHARACTERS.test(arg) && !arg.startsWith("-") && !arg.startsWith("http")) {
      findings.push({
        severity: "high",
        category: "permissions",
        title: "Shell metacharacters in arguments",
        detail: `Server "${server.name}" has shell metacharacters in its args: "${arg.substring(0, 60)}". This could enable command injection.`,
        recommendation: "Avoid shell metacharacters in args. If a shell is needed, audit the command carefully for injection risks.",
        server: server.name,
        source: server.source,
      });
      break;
    }
  }

  if (server.command === "node" || server.command === "python" || server.command === "python3") {
    const scriptArg = server.args.find(a => !a.startsWith("-"));
    if (scriptArg && (scriptArg.startsWith("http://") || scriptArg.startsWith("https://"))) {
      findings.push({
        severity: "critical",
        category: "permissions",
        title: "Remote code execution",
        detail: `Server "${server.name}" executes a script from a remote URL (${scriptArg.substring(0, 80)}). The script content can change at any time.`,
        recommendation: "Download the script, audit it, and run from a local path instead.",
        server: server.name,
        source: server.source,
      });
    }
  }

  return findings;
}
