import { statSync } from "fs";
import type { Finding } from "../types.js";

export function checkFilePermissions(scannedPaths: string[]): Finding[] {
  const findings: Finding[] = [];

  if (process.platform === "win32") return findings;

  for (const filePath of scannedPaths) {
    try {
      const stat = statSync(filePath);
      const mode = stat.mode;

      const othersRead = (mode & 0o004) !== 0;
      const othersWrite = (mode & 0o002) !== 0;
      const groupWrite = (mode & 0o020) !== 0;

      if (othersWrite) {
        findings.push({
          severity: "critical",
          category: "config-hygiene",
          title: "Config file is world-writable",
          detail: `Config "${filePath}" is writable by any user on this system. An attacker could inject malicious MCP servers.`,
          recommendation: `Fix with: chmod 600 "${filePath}"`,
          fix: { file: filePath, command: `chmod 600 "${filePath}"` },
          server: "(config file)",
          source: filePath,
        });
      } else if (othersRead) {
        findings.push({
          severity: "high",
          category: "config-hygiene",
          title: "Config file is world-readable",
          detail: `Config "${filePath}" is readable by any user. If it contains secrets, they are exposed.`,
          recommendation: `Fix with: chmod 600 "${filePath}"`,
          fix: { file: filePath, command: `chmod 600 "${filePath}"` },
          server: "(config file)",
          source: filePath,
        });
      } else if (groupWrite) {
        findings.push({
          severity: "medium",
          category: "config-hygiene",
          title: "Config file is group-writable",
          detail: `Config "${filePath}" is writable by the file's group. Group members could inject malicious MCP servers.`,
          recommendation: `Fix with: chmod 600 "${filePath}"`,
          fix: { file: filePath, command: `chmod 600 "${filePath}"` },
          server: "(config file)",
          source: filePath,
        });
      }
    } catch {
      // Can't stat — skip
    }
  }

  return findings;
}
