import type { McpServer, Finding } from "../types.js";
import { urlFix } from "../fixes.js";

export function checkTransport(server: McpServer): Finding[] {
  const findings: Finding[] = [];

  if (server.url) {
    if (server.url.startsWith("http://")) {
      findings.push({
        severity: "high",
        category: "transport",
        title: "Unencrypted HTTP transport",
        detail: `Server "${server.name}" connects over plain HTTP (${server.url.substring(0, 80)}). Traffic including credentials and tool responses is unencrypted.`,
        recommendation: "Use HTTPS (TLS) for all remote MCP server connections.",
        fix: urlFix(server, { https: true }),
        server: server.name,
        source: server.source,
      });
    }

    if (/localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]/.test(server.url)) {
      if (server.url.startsWith("http://")) {
        // Localhost HTTP is less concerning — downgrade
        const existing = findings.find(f => f.title === "Unencrypted HTTP transport" && f.server === server.name);
        if (existing) existing.severity = "low";
      }
    } else if (server.url.startsWith("https://")) {
      findings.push({
        severity: "info",
        category: "transport",
        title: "Remote MCP server (SSE/Streamable HTTP)",
        detail: `Server "${server.name}" connects to a remote endpoint (${server.url.substring(0, 80)}). The server operator has access to all tool requests and responses.`,
        recommendation: "Verify you trust the remote server operator. Check their privacy policy and data handling.",
        server: server.name,
        source: server.source,
      });
    }

    try {
      const url = new URL(server.url);
      if (url.username || url.password) {
        findings.push({
          severity: "critical",
          category: "transport",
          title: "Credentials embedded in URL",
          detail: `Server "${server.name}" has credentials embedded in its URL. These are visible in logs, process listings, and config files.`,
          recommendation: "Pass credentials via environment variables or auth headers, not in the URL.",
          fix: urlFix(server),
          server: server.name,
          source: server.source,
        });
      }

      if (url.port && !["80", "443", "8080", "8443", "3000", "3001", "8000", "8001"].includes(url.port)) {
        findings.push({
          severity: "info",
          category: "transport",
          title: "Non-standard port",
          detail: `Server "${server.name}" connects on port ${url.port}. This may indicate a development or test server.`,
          recommendation: "Verify this is the intended production endpoint.",
          server: server.name,
          source: server.source,
        });
      }
    } catch {
      findings.push({
        severity: "medium",
        category: "transport",
        title: "Malformed server URL",
        detail: `Server "${server.name}" has a URL that could not be parsed: "${server.url.substring(0, 80)}".`,
        recommendation: "Fix the URL to a valid format.",
        server: server.name,
        source: server.source,
      });
    }
  }

  return findings;
}
