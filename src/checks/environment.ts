import type { McpServer, Finding } from "../types.js";
import { envFix } from "../fixes.js";

const INJECTION_ENV_VARS: Record<string, { severity: "critical" | "high"; risk: string }> = {
  "LD_PRELOAD":      { severity: "critical", risk: "library injection — arbitrary code runs before main process" },
  "LD_LIBRARY_PATH": { severity: "high",     risk: "library search path hijack — can substitute system libraries" },
  "DYLD_INSERT_LIBRARIES": { severity: "critical", risk: "macOS library injection — arbitrary code runs before main process" },
  "NODE_OPTIONS":    { severity: "high",     risk: "Node.js flag injection — can enable --inspect, --require, or --experimental-loader" },
  "NODE_EXTRA_CA_CERTS": { severity: "medium" as "high", risk: "custom CA certificate — could enable MITM on TLS connections" },
  "PYTHONPATH":      { severity: "high",     risk: "Python module search path hijack — can substitute standard libraries" },
  "PYTHONSTARTUP":   { severity: "high",     risk: "Python startup script — runs arbitrary code on interpreter start" },
  "RUBYOPT":         { severity: "high",     risk: "Ruby option injection — can require arbitrary files" },
  "PERL5OPT":        { severity: "high",     risk: "Perl option injection — can load arbitrary modules" },
  "JAVA_TOOL_OPTIONS": { severity: "high",   risk: "JVM flag injection — can attach agents or modify classpath" },
  "HTTP_PROXY":      { severity: "high",     risk: "HTTP proxy override — all HTTP traffic routed through attacker-controlled proxy" },
  "HTTPS_PROXY":     { severity: "high",     risk: "HTTPS proxy override — all HTTPS traffic routed through attacker-controlled proxy" },
  "ALL_PROXY":       { severity: "high",     risk: "all traffic proxy override — every connection routed through attacker-controlled proxy" },
  "NO_PROXY":        { severity: "medium" as "high", risk: "proxy bypass list — can force specific hosts through a malicious proxy" },
  "CURL_CA_BUNDLE":  { severity: "high",     risk: "custom CA bundle for curl — could enable MITM on TLS connections" },
  "SSL_CERT_FILE":   { severity: "high",     risk: "custom SSL cert — could enable MITM on TLS connections" },
  "GIT_SSH_COMMAND": { severity: "high",     risk: "git SSH command override — can execute arbitrary commands on git operations" },
  "EDITOR":          { severity: "medium" as "high", risk: "editor override — can execute arbitrary commands when a tool opens an editor" },
  "SHELL":           { severity: "medium" as "high", risk: "shell override — subprocesses may spawn an attacker-controlled shell" },
};

const PATH_VARS = new Set(["PATH", "Path"]);

/** Drop "." and empty entries from a PATH value, keeping its separator. */
function cleanPath(value: string): string {
  const sep = value.includes(";") ? ";" : ":";
  return value.split(sep).filter((p) => p !== "." && p !== "").join(sep);
}

export function checkEnvironment(server: McpServer): Finding[] {
  const findings: Finding[] = [];

  for (const [key, value] of Object.entries(server.env)) {
    const upperKey = key.toUpperCase();

    const injectionRisk = INJECTION_ENV_VARS[key] ?? INJECTION_ENV_VARS[upperKey];
    if (injectionRisk) {
      findings.push({
        severity: injectionRisk.severity,
        category: "environment",
        title: `Dangerous env var: ${key}`,
        detail: `Server "${server.name}" sets ${key}. Risk: ${injectionRisk.risk}.`,
        recommendation: `Remove ${key} from the server's env unless absolutely required. This variable can be used for privilege escalation.`,
        fix: envFix(server, { [key]: null }),
        server: server.name,
        source: server.source,
      });
    }

    if (PATH_VARS.has(key)) {
      findings.push({
        severity: "high",
        category: "environment",
        title: "PATH override",
        detail: `Server "${server.name}" overrides the PATH variable. This controls which executables are found and run by the server.`,
        recommendation: "Avoid overriding PATH. If needed, append to it rather than replacing it entirely.",
        fix: envFix(server, { [key]: null }),
        server: server.name,
        source: server.source,
      });

      const paths = value.split(/[;:]/);
      for (const p of paths) {
        if (p === "." || p === "") {
          findings.push({
            severity: "critical",
            category: "environment",
            title: "Current directory in PATH",
            detail: `Server "${server.name}" has "." or empty entry in PATH. This allows executing arbitrary binaries from the current working directory.`,
            recommendation: "Remove '.' and empty entries from PATH. Use absolute paths.",
            fix: envFix(server, { [key]: cleanPath(value) }),
            server: server.name,
            source: server.source,
          });
          break;
        }
      }
    }
  }

  const envKeys = Object.keys(server.env).map(k => k.toUpperCase());
  const hasProxy = envKeys.some(k => k.includes("PROXY"));
  const hasSecret = envKeys.some(k => /API[_-]?KEY|TOKEN|SECRET|PASSWORD/.test(k));
  if (hasProxy && hasSecret) {
    findings.push({
      severity: "critical",
      category: "environment",
      title: "Proxy + credentials combination",
      detail: `Server "${server.name}" has both proxy settings and credentials in its env. A malicious proxy could intercept the credentials in transit.`,
      recommendation: "Remove proxy env vars, or ensure they point to a trusted endpoint. Use HTTPS endpoints for the proxy itself.",
      fix: envFix(server, Object.fromEntries(Object.keys(server.env).filter(k => k.toUpperCase().includes("PROXY")).map(k => [k, null]))),
      server: server.name,
      source: server.source,
    });
  }

  return findings;
}

export function checkCrossServerSecrets(servers: McpServer[]): Finding[] {
  const findings: Finding[] = [];

  const secretValues = new Map<string, { server: string; source: string; key: string }[]>();

  for (const server of servers) {
    for (const [key, value] of Object.entries(server.env)) {
      if (value.length < 10 || value.startsWith("${") || value.startsWith("$")) continue;
      const existing = secretValues.get(value) ?? [];
      existing.push({ server: server.name, source: server.source, key });
      secretValues.set(value, existing);
    }
  }

  for (const [, usages] of secretValues) {
    if (usages.length <= 1) continue;
    const uniqueServers = [...new Set(usages.map(u => u.server))];
    if (uniqueServers.length <= 1) continue;

    const serverList = usages.map(u => `${u.server}:${u.key}`).join(", ");
    findings.push({
      severity: "medium",
      category: "environment",
      title: "Shared credential across servers",
      detail: `The same credential value is used across ${uniqueServers.length} servers (${serverList}). A compromise of one server exposes all.`,
      recommendation: "Use unique credentials per server where possible. Rotate shared credentials if one server is compromised.",
      server: uniqueServers.join(", "),
      source: usages[0].source,
    });
  }

  return findings;
}
