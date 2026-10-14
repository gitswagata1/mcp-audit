import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { checkPermissions } from "../src/checks/permissions.js";
import { checkSecrets, redactArgs } from "../src/checks/secrets.js";
import { checkSupplyChain } from "../src/checks/supply-chain.js";
import { checkTransport } from "../src/checks/transport.js";
import { checkEnvironment } from "../src/checks/environment.js";
import { checkFilePermissions } from "../src/checks/file-permissions.js";
import { formatFix } from "../src/fixes.js";
import { printMarkdown } from "../src/markdown.js";
import { printReport } from "../src/reporter.js";
import type { AuditResult, Finding, McpServer } from "../src/types.js";

function server(overrides: Partial<McpServer> = {}): McpServer {
  return { name: "test", command: "npx", args: [], env: {}, url: "", source: "Test", sourcePath: "/tmp/test.json", ...overrides };
}

function find(findings: Finding[], title: string): Finding {
  const f = findings.find(f => f.title === title);
  assert.ok(f, `expected finding "${title}"`);
  return f;
}

function captureLog(fn: () => void): string {
  const original = console.log;
  const lines: string[] = [];
  console.log = (...args: unknown[]) => { lines.push(args.join(" ")); };
  try { fn(); } finally { console.log = original; }
  return lines.join("\n");
}

const OPENAI_KEY = "sk-abcdefghijklmnopqrstuvwxyz1234";

describe("auto-fix suggestions", () => {
  it("pins an unpinned package version", () => {
    const f = find(checkSupplyChain(server({ args: ["-y", "some-pkg@latest"] })), "Unpinned package version");
    assert.deepEqual(f.fix, { file: "/tmp/test.json", patch: { args: ["-y", "some-pkg@<version>"] } });
  });

  it("removes the --yes auto-confirm flag", () => {
    const f = find(checkSupplyChain(server({ args: ["--yes", "some-pkg@1.0.0"] })), "Auto-confirm flag on package runner");
    assert.deepEqual(f.fix?.patch, { args: ["some-pkg@1.0.0"] });
  });

  it("removes docker --privileged, host network and host PID flags", () => {
    const findings = checkSupplyChain(server({ command: "docker", args: ["run", "--privileged", "--network=host", "--pid=host", "img"] }));
    assert.deepEqual(find(findings, "Privileged container").fix?.patch, { args: ["run", "--network=host", "--pid=host", "img"] });
    assert.deepEqual(find(findings, "Host network mode").fix?.patch, { args: ["run", "--privileged", "--pid=host", "img"] });
    assert.deepEqual(find(findings, "Host PID namespace").fix?.patch, { args: ["run", "--privileged", "--network=host", "img"] });
  });

  it("moves a hardcoded env secret to an env reference without echoing it", () => {
    const f = find(checkSecrets(server({ env: { OPENAI_API_KEY: OPENAI_KEY } })), "Hardcoded OpenAI secret");
    assert.deepEqual(f.fix?.patch, { env: { OPENAI_API_KEY: "${OPENAI_API_KEY}" } });
    assert.ok(!JSON.stringify(f.fix).includes(OPENAI_KEY));
  });

  it("replaces a secret in args with an env reference", () => {
    const f = find(checkSecrets(server({ command: "node", args: ["server.js", "--key", OPENAI_KEY] })), "OpenAI secret in command args");
    assert.deepEqual(f.fix?.patch, { args: ["server.js", "--key", "${API_KEY}"] });
  });

  it("never leaks arg secrets through unrelated arg fixes", () => {
    const findings = checkSupplyChain(server({ args: ["some-pkg", OPENAI_KEY] }));
    const f = find(findings, "Unpinned package version");
    assert.deepEqual(f.fix?.patch, { args: ["some-pkg@<version>", "${API_KEY}"] });
    assert.deepEqual(redactArgs(["a", OPENAI_KEY, OPENAI_KEY]), ["a", "${API_KEY}", "${API_KEY_2}"]);
  });

  it("removes dangerous permission flags", () => {
    const f = find(checkPermissions(server({ command: "deno", args: ["run", "--allow-all", "main.ts"] })), "Dangerous flag: all permissions");
    assert.deepEqual(f.fix?.patch, { args: ["run", "main.ts"] });
  });

  it("narrows an overly broad filesystem scope", () => {
    const f = find(checkPermissions(server({ name: "filesystem", args: ["@modelcontextprotocol/server-filesystem", "/"] })), "Overly broad filesystem scope");
    assert.deepEqual(f.fix?.patch, { args: ["@modelcontextprotocol/server-filesystem", "<project-dir>"] });
  });

  it("upgrades HTTP to HTTPS and strips URL credentials", () => {
    const findings = checkTransport(server({ command: "", url: "http://admin:hunter2@api.example.com/mcp" }));
    assert.deepEqual(find(findings, "Unencrypted HTTP transport").fix?.patch, { url: "https://api.example.com/mcp" });
    assert.deepEqual(find(findings, "Credentials embedded in URL").fix?.patch, { url: "http://api.example.com/mcp" });
    assert.ok(!JSON.stringify(findings.map(f => f.fix)).includes("hunter2"));
  });

  it("removes dangerous env vars and cleans PATH", () => {
    const findings = checkEnvironment(server({ env: { LD_PRELOAD: "/tmp/evil.so", PATH: ".:/usr/bin::/bin" } }));
    assert.deepEqual(find(findings, "Dangerous env var: LD_PRELOAD").fix?.patch, { env: { LD_PRELOAD: null } });
    assert.deepEqual(find(findings, "Current directory in PATH").fix?.patch, { env: { PATH: "/usr/bin:/bin" } });
  });

  it("removes proxy vars when combined with credentials", () => {
    const findings = checkEnvironment(server({ env: { HTTPS_PROXY: "http://proxy:8080", API_KEY: "${API_KEY}" } }));
    assert.deepEqual(find(findings, "Proxy + credentials combination").fix?.patch, { env: { HTTPS_PROXY: null } });
  });

  it("suggests chmod for world-readable configs", { skip: process.platform === "win32" }, async () => {
    const { mkdtempSync, writeFileSync, chmodSync } = await import("node:fs");
    const { join } = await import("node:path");
    const { tmpdir } = await import("node:os");
    const file = join(mkdtempSync(join(tmpdir(), "mcp-audit-")), "mcp.json");
    writeFileSync(file, "{}");
    chmodSync(file, 0o644);
    const f = find(checkFilePermissions([file]), "Config file is world-readable");
    assert.deepEqual(f.fix, { file, command: `chmod 600 "${file}"` });
  });

  it("omits fix when no concrete change can be derived", () => {
    const f = find(checkSupplyChain(server({ args: ["some-pkg@1.0.0"] })), "Unverified package");
    assert.equal(f.fix, undefined);
  });

  it("formats fixes as copy-pasteable JSON or commands", () => {
    assert.equal(formatFix({ file: "x", patch: { env: { A: null } } }), '{"env":{"A":null}}');
    assert.equal(formatFix({ file: "x", command: 'chmod 600 "x"' }), 'chmod 600 "x"');
  });
});

describe("auto-fix output", () => {
  const s = server({ args: ["some-pkg@1.0.0", "--yes"] });
  const findings = checkSupplyChain(s);
  const result: AuditResult = {
    version: "test", servers: [s], findings, scannedPaths: [], timestamp: "now",
    grade: "C", score: 60, serverScores: [],
  };

  it("shows fixes in default (non-verbose) text output, even for medium findings", () => {
    const out = captureLog(() => printReport(result));
    assert.ok(out.includes('fix: {"args":["some-pkg@1.0.0"]}'));
  });

  it("shows fixes in markdown output", () => {
    const out = captureLog(() => printMarkdown(result));
    assert.ok(out.includes('**Auto-fix:** `{"args":["some-pkg@1.0.0"]}`'));
  });

  it("includes fixes in JSON output", () => {
    const parsed = JSON.parse(JSON.stringify(result)) as AuditResult;
    const f = parsed.findings.find(f => f.title === "Auto-confirm flag on package runner");
    assert.deepEqual(f?.fix, { file: "/tmp/test.json", patch: { args: ["some-pkg@1.0.0"] } });
  });
});
