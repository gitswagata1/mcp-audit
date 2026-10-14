import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { generateSarif, genericTitle, ruleIdFor, severityToSarifLevel, toSarifUri } from "../src/sarif.js";
import { checkSecrets } from "../src/checks/secrets.js";
import { checkPermissions } from "../src/checks/permissions.js";
import type { AuditResult, Finding, McpServer } from "../src/types.js";

function server(overrides: Partial<McpServer> = {}): McpServer {
  return { name: "test", command: "", args: [], env: {}, url: "", source: "Test", sourcePath: "/tmp/test.json", ...overrides };
}

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    severity: "critical",
    category: "permissions",
    title: "Direct shell access",
    detail: 'Server "test" spawns a shell (bash).',
    recommendation: "Replace with a purpose-built MCP server.",
    server: "test",
    source: "Test",
    ...overrides,
  };
}

function audit(findings: Finding[], servers: McpServer[] = [server()]): AuditResult {
  return {
    version: "0.3.0",
    servers,
    findings,
    scannedPaths: servers.map(s => s.sourcePath),
    timestamp: "2026-10-14T12:00:00.000Z",
    grade: "F",
    score: 0,
    serverScores: [],
  };
}

describe("severityToSarifLevel", () => {
  it("maps critical/high to error, medium to warning, low/info to note", () => {
    assert.equal(severityToSarifLevel("critical"), "error");
    assert.equal(severityToSarifLevel("high"), "error");
    assert.equal(severityToSarifLevel("medium"), "warning");
    assert.equal(severityToSarifLevel("low"), "note");
    assert.equal(severityToSarifLevel("info"), "note");
  });
});

describe("ruleIdFor", () => {
  it("combines category and slugified title", () => {
    assert.equal(ruleIdFor(finding()), "permissions/direct-shell-access");
    assert.equal(ruleIdFor(finding({ category: "transport", title: "Unencrypted HTTP transport" })), "transport/unencrypted-http-transport");
  });

  it("strips dynamic values after a colon", () => {
    const a = finding({ title: "Dangerous flag: unrestricted write access" });
    const b = finding({ title: "Dangerous flag: sandbox disabled" });
    assert.equal(ruleIdFor(a), "permissions/dangerous-flag");
    assert.equal(ruleIdFor(a), ruleIdFor(b));
    assert.equal(ruleIdFor(finding({ category: "environment", title: "Dangerous env var: LD_PRELOAD" })), "environment/dangerous-env-var");
  });

  it("collapses secret provider names into one rule", () => {
    const ids = ["OpenAI", "GitHub PAT", "AWS access key"].map(name =>
      ruleIdFor(finding({ category: "secrets", title: `Hardcoded ${name} secret` })));
    assert.deepEqual(new Set(ids), new Set(["secrets/hardcoded-secret"]));
    assert.equal(ruleIdFor(finding({ category: "secrets", title: "Stripe live secret in command args" })), "secrets/secret-in-command-args");
    assert.equal(ruleIdFor(finding({ category: "secrets", title: "Slack bot key in non-standard env var" })), "secrets/secret-key-in-non-standard-env-var");
  });

  it("does not collapse unrelated static titles", () => {
    assert.equal(ruleIdFor(finding({ category: "secrets", title: "Possible hardcoded credential" })), "secrets/possible-hardcoded-credential");
    assert.equal(genericTitle("Short secret value"), "Short secret value");
  });

  it("drops trailing parenthetical qualifiers from the id", () => {
    const f = finding({ category: "config-hygiene", title: "Shadow server (same name, different command)" });
    assert.equal(ruleIdFor(f), "config-hygiene/shadow-server");
  });

  it("produces stable ids for real check output", () => {
    const s = server({
      command: "npx",
      args: ["some-pkg", "sk-abcdefghijklmnopqrstuvwxyz"],
      env: { OPENAI_API_KEY: "sk-abcdefghijklmnopqrstuvwxyz123456" },
    });
    const ids = checkSecrets(s).map(ruleIdFor);
    assert.ok(ids.includes("secrets/hardcoded-secret"));
    assert.ok(ids.includes("secrets/secret-in-command-args"));

    const shell = checkPermissions(server({ command: "bash", args: ["-c", "echo hi"] }));
    assert.ok(shell.map(ruleIdFor).includes("permissions/direct-shell-access"));
  });
});

describe("toSarifUri", () => {
  it("prefixes absolute POSIX paths with file://", () => {
    assert.equal(toSarifUri("/home/user/.cursor/mcp.json"), "file:///home/user/.cursor/mcp.json");
  });

  it("normalises Windows paths to forward slashes with file:///", () => {
    assert.equal(toSarifUri("C:\\Users\\John Doe\\.cursor\\mcp.json"), "file:///C:/Users/John%20Doe/.cursor/mcp.json");
  });

  it("leaves relative paths relative", () => {
    assert.equal(toSarifUri(".vscode\\mcp.json"), ".vscode/mcp.json");
  });
});

describe("generateSarif", () => {
  it("outputs a valid SARIF v2.1.0 envelope", () => {
    const sarif = generateSarif(audit([finding()]));
    assert.equal(sarif.version, "2.1.0");
    assert.ok(sarif.$schema.includes("sarif-schema-2.1.0.json"));
    assert.equal(sarif.runs.length, 1);
    assert.equal(sarif.runs[0].tool.driver.name, "mcp-audit");
    assert.equal(sarif.runs[0].tool.driver.version, "0.3.0");
    assert.deepEqual(sarif.runs[0].properties, { grade: "F", score: 0 });
  });

  it("derives one rule per distinct ruleId with recommendation as help", () => {
    const sarif = generateSarif(audit([
      finding({ category: "secrets", title: "Hardcoded OpenAI secret", recommendation: "Move it to a secrets manager." }),
      finding({ category: "secrets", title: "Hardcoded Anthropic secret" }),
      finding({ severity: "medium", category: "permissions", title: "Network access" }),
    ]));
    const { rules } = sarif.runs[0].tool.driver;
    assert.deepEqual(rules.map(r => r.id), ["secrets/hardcoded-secret", "permissions/network-access"]);
    assert.equal(rules[0].name, "HardcodedSecret");
    assert.equal(rules[0].shortDescription.text, "Hardcoded secret");
    assert.equal(rules[0].help.text, "Move it to a secrets manager.");
    assert.equal(rules[0].properties.category, "secrets");

    const results = sarif.runs[0].results;
    assert.equal(results.length, 3);
    for (const r of results) {
      assert.equal(rules[r.ruleIndex].id, r.ruleId);
    }
  });

  it("uses the worst severity for the rule's default level", () => {
    const sarif = generateSarif(audit([
      finding({ severity: "low", category: "transport", title: "Unencrypted HTTP transport" }),
      finding({ severity: "high", category: "transport", title: "Unencrypted HTTP transport" }),
    ]));
    const [rule] = sarif.runs[0].tool.driver.rules;
    assert.equal(rule.defaultConfiguration.level, "error");
    assert.equal(rule.properties["security-severity"], "8.0");
    assert.deepEqual(sarif.runs[0].results.map(r => r.level), ["note", "error"]);
  });

  it("includes detail and recommendation in the result message", () => {
    const [result] = generateSarif(audit([finding()])).runs[0].results;
    assert.ok(result.message.text.includes('Server "test" spawns a shell'));
    assert.ok(result.message.text.includes("Recommendation: Replace with a purpose-built MCP server."));
    assert.equal(result.properties.category, "permissions");
  });

  it("locates findings in the server's config file", () => {
    const s = server({ name: "shell", source: "Cursor", sourcePath: "C:\\Users\\me\\.cursor\\mcp.json" });
    const [result] = generateSarif(audit([finding({ server: "shell", source: "Cursor" })], [s])).runs[0].results;
    assert.equal(result.locations.length, 1);
    assert.equal(result.locations[0].physicalLocation.artifactLocation.uri, "file:///C:/Users/me/.cursor/mcp.json");
    assert.deepEqual(result.locations[0].logicalLocations, [{ name: "shell", kind: "configuration" }]);
  });

  it("locates config-file findings via their source path", () => {
    const f = finding({ category: "config-hygiene", title: "Config file is world-readable", server: "(config file)", source: "/tmp/test.json" });
    const [result] = generateSarif(audit([f])).runs[0].results;
    assert.equal(result.locations[0].physicalLocation.artifactLocation.uri, "file:///tmp/test.json");
  });

  it("lists every config for cross-config findings", () => {
    const a = server({ name: "dup", source: "Cursor", sourcePath: "/a/mcp.json" });
    const b = server({ name: "dup", source: "Claude Code", sourcePath: "/b/settings.json" });
    const f = finding({ severity: "low", category: "config-hygiene", title: "Duplicate server definition", server: "dup", source: "Cursor, Claude Code" });
    const [result] = generateSarif(audit([f], [a, b])).runs[0].results;
    assert.deepEqual(
      result.locations.map(l => l.physicalLocation.artifactLocation.uri),
      ["file:///a/mcp.json", "file:///b/settings.json"],
    );
  });

  it("returns empty results and rules when there are no findings", () => {
    const sarif = generateSarif(audit([]));
    assert.deepEqual(sarif.runs[0].results, []);
    assert.deepEqual(sarif.runs[0].tool.driver.rules, []);
  });
});
