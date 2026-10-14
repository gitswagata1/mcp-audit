import type { McpServer, Finding } from "../types.js";
import { argsFix } from "../fixes.js";

const KNOWN_PUBLISHERS: Record<string, string> = {
  "@modelcontextprotocol/": "Anthropic (official MCP)",
  "@anthropic/": "Anthropic",
  "@cloudflare/": "Cloudflare",
  "@supabase/": "Supabase",
  "@sentry/": "Sentry",
  "@vercel/": "Vercel",
  "@stripe/": "Stripe",
  "@prisma/": "Prisma",
  "@neon/": "Neon",
  "@github/": "GitHub",
  "@azure/": "Microsoft Azure",
  "@google/": "Google",
  "@aws/": "AWS",
  "@linear/": "Linear",
  "@notion/": "Notion",
  "@slack/": "Slack",
  "@grafana/": "Grafana",
  "@datadog/": "Datadog",
  "@playwright/": "Microsoft Playwright",
  "@docker/": "Docker",
};

const PACKAGE_RUNNERS = new Set(["npx", "uvx", "bunx", "pnpx", "dlx"]);

const TYPOSQUAT_INDICATORS = [
  /^@[a-z]+-official\//,
  /^@[a-z]+\d+\//,
  /-free$/,
  /-latest$/,
  /-new$/,
];

const RUNNER_FLAGS = new Set(["-y", "--yes", "-q", "--quiet", "-p", "--package", "--prefer-online", "--prefer-offline"]);

export function checkSupplyChain(server: McpServer): Finding[] {
  const findings: Finding[] = [];

  if (PACKAGE_RUNNERS.has(server.command)) {
    const pkg = server.args.find(a => !a.startsWith("-") && !RUNNER_FLAGS.has(a)) ?? "";

    if (!pkg) {
      findings.push({
        severity: "high",
        category: "supply-chain",
        title: "Package runner with no clear package",
        detail: `Server "${server.name}" runs "${server.command}" with no identifiable package name. This may execute an unintended package.`,
        recommendation: "Ensure the package name is specified in the arguments.",
        server: server.name,
        source: server.source,
      });
      return findings;
    }

    const isVerified = Object.keys(KNOWN_PUBLISHERS).some((prefix) => pkg.startsWith(prefix));

    if (!isVerified) {
      findings.push({
        severity: "medium",
        category: "supply-chain",
        title: "Unverified package",
        detail: `Server "${server.name}" runs "${pkg}" via ${server.command}. This package is not from a known verified publisher.`,
        recommendation: "Verify the package source on npm/PyPI. Check download counts, maintainers, and recent publish dates.",
        server: server.name,
        source: server.source,
      });
    }

    if (!pkg.includes("@") || pkg.endsWith("@latest")) {
      findings.push({
        severity: "medium",
        category: "supply-chain",
        title: "Unpinned package version",
        detail: `Server "${server.name}" runs "${pkg}" without a pinned version. A compromised future release could execute malicious code.`,
        recommendation: `Pin to a specific version, e.g., "${pkg.replace(/@latest$/, "")}@1.2.3".`,
        fix: argsFix(server, (args) => args.map((a) => (a === pkg ? `${pkg.replace(/@latest$/, "")}@<version>` : a))),
        server: server.name,
        source: server.source,
      });
    }

    if (TYPOSQUAT_INDICATORS.some(p => p.test(pkg))) {
      findings.push({
        severity: "high",
        category: "supply-chain",
        title: "Possible typosquat package",
        detail: `Server "${server.name}" runs "${pkg}" which matches common typosquatting patterns.`,
        recommendation: "Double-check the package name against the official publisher's documentation.",
        server: server.name,
        source: server.source,
      });
    }

    if (server.args.some(a => a === "--yes" || a === "-y")) {
      findings.push({
        severity: "medium",
        category: "supply-chain",
        title: "Auto-confirm flag on package runner",
        detail: `Server "${server.name}" uses --yes/-y with ${server.command}, which auto-confirms package installation without prompting.`,
        recommendation: "Remove the --yes flag so the user is prompted before installing new packages.",
        fix: argsFix(server, (args) => args.filter((a) => a !== "--yes" && a !== "-y")),
        server: server.name,
        source: server.source,
      });
    }
  }

  if (server.command === "docker" || server.command === "podman") {
    const allArgs = server.args.join(" ");

    if (server.args.includes("--privileged")) {
      findings.push({
        severity: "critical",
        category: "supply-chain",
        title: "Privileged container",
        detail: `Server "${server.name}" runs a container in privileged mode. This grants near-host-level access.`,
        recommendation: "Remove --privileged. Use specific --cap-add flags for only the capabilities needed.",
        fix: argsFix(server, (args) => args.filter((a) => a !== "--privileged")),
        server: server.name,
        source: server.source,
      });
    }

    if (server.args.includes("--network=host") || server.args.includes("--net=host")) {
      findings.push({
        severity: "high",
        category: "supply-chain",
        title: "Host network mode",
        detail: `Server "${server.name}" runs a container with host networking. The container shares the host's network stack.`,
        recommendation: "Use bridge networking (default) and expose only needed ports with -p.",
        fix: argsFix(server, (args) => args.filter((a) => a !== "--network=host" && a !== "--net=host")),
        server: server.name,
        source: server.source,
      });
    }

    const volumeFlags = server.args.filter(a => a.startsWith("-v") || a.startsWith("--volume") || a.startsWith("--mount"));
    for (const vf of volumeFlags) {
      if (/\/:\/|\/home:\/|\/etc:\/|\/var:\//.test(allArgs)) {
        findings.push({
          severity: "critical",
          category: "supply-chain",
          title: "Sensitive host path mounted in container",
          detail: `Server "${server.name}" mounts a sensitive host path into the container.`,
          recommendation: "Mount only specific project directories, not system paths.",
          server: server.name,
          source: server.source,
        });
        break;
      }
    }

    if (allArgs.includes("--pid=host")) {
      findings.push({
        severity: "high",
        category: "supply-chain",
        title: "Host PID namespace",
        detail: `Server "${server.name}" shares the host PID namespace. It can see and signal all host processes.`,
        recommendation: "Remove --pid=host unless absolutely required.",
        fix: argsFix(server, (args) => args.filter((a) => a !== "--pid=host")),
        server: server.name,
        source: server.source,
      });
    }
  }

  return findings;
}
