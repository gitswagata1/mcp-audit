import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  applyPolicy,
  emptyPolicy,
  findingId,
  loadPolicy,
  matchesCheck,
  mergePolicies,
  overrideSeverity,
  parseYaml,
  PolicyError,
  validatePolicy,
} from "../src/policy.js";
import type { Finding, McpServer, PolicyConfig } from "../src/types.js";

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    severity: "medium", category: "permissions", title: "Unpinned package version",
    detail: "", recommendation: "", server: "ctx", source: "Claude Desktop",
    ...overrides,
  };
}

function server(overrides: Partial<McpServer> = {}): McpServer {
  return { name: "ctx", command: "npx", args: [], env: {}, url: "", source: "Claude Desktop", sourcePath: "/tmp/cfg.json", ...overrides };
}

function policy(overrides: Partial<PolicyConfig> = {}): PolicyConfig {
  return { ...emptyPolicy(), ...overrides };
}

describe("parseYaml", () => {
  it("parses the documented policy shape", () => {
    const doc = parseYaml(
      [
        "allow:",
        '  - server: "filesystem"',
        "    paths:",
        "      - /home/user/projects",
        '  - server: "ctx"',
        "    check: [unpinned package, 'supply-chain']",
        "deny:",
        "  - server: \"*\"",
        "    args_pattern: --no-sandbox",
        "severity:",
        "  secrets: high",
      ].join("\n"),
      "p.yml",
    ) as Record<string, unknown>;

    assert.deepEqual(doc.allow, [
      { server: "filesystem", paths: ["/home/user/projects"] },
      { server: "ctx", check: ["unpinned package", "supply-chain"] },
    ]);
    assert.deepEqual(doc.deny, [{ server: "*", args_pattern: "--no-sandbox" }]);
    assert.deepEqual(doc.severity, { secrets: "high" });
  });

  it("rejects constructs it cannot read reliably", () => {
    assert.throws(() => parseYaml("a: {b: c}", "p.yml"), PolicyError);
    assert.throws(() => parseYaml("a: |\n  text", "p.yml"), /block scalars/);
    assert.throws(() => parseYaml("\ta: 1", "p.yml"), /tabs/);
    assert.throws(() => parseYaml("a: 1\na: 2", "p.yml"), /duplicate key/);
  });

  it("ignores comments and blank lines", () => {
    assert.deepEqual(parseYaml("# c\n\nallow:\n  - server: x  # trailing\n", "p.yml"), {
      allow: [{ server: "x" }],
    });
  });
});

describe("validatePolicy", () => {
  it("normalizes a valid document", () => {
    const p = validatePolicy(parseYaml('allow:\n  - server: x\ndeny:\n  - server: "*"\n    args_pattern: --no-sandbox\nseverity:\n  secrets: HIGH\n', "p.yml"), "p.yml");
    assert.deepEqual(p.allow, [{ server: "x" }]);
    assert.deepEqual(p.severity, { secrets: "high" });
    assert.deepEqual(p.files, ["p.yml"]);
  });

  it("reports the offending section and rule", () => {
    assert.throws(() => validatePolicy({ nope: [] }, "p.yml"), /unknown section "nope"/);
    assert.throws(() => validatePolicy({ allow: [{}] }, "p.yml"), /allow\[0\] must set at least one/);
    assert.throws(() => validatePolicy({ allow: [{ server: "x", typo: 1 }] }, "p.yml"), /unknown key "typo"/);
    assert.throws(() => validatePolicy({ severity: { secrets: "urgent" } }, "p.yml"), /must be one of/);
  });
});

describe("finding matching", () => {
  it("matches by category and by title words, with wildcards", () => {
    const f = finding({ category: "secrets", title: "Hardcoded GitHub secret" });
    assert.ok(matchesCheck(f, "secrets"));
    assert.ok(matchesCheck(f, "hardcoded"));
    assert.ok(matchesCheck(f, "Hardcoded-*-secret"));
    assert.ok(!matchesCheck(f, "permissions"));
    assert.ok(!matchesCheck(f, "hardcoded disk secret"));
    assert.equal(findingId("Dangerous flag: sandbox disabled"), "dangerous-flag-sandbox-disabled");
  });
});

describe("applyPolicy", () => {
  it("moves allowlisted findings to suppressed with a reason", () => {
    const p = policy({ allow: [{ server: "ctx", check: "unpinned package" }] });
    const out = applyPolicy([server()], [finding()], p);
    assert.equal(out.findings.length, 0);
    assert.equal(out.suppressed.length, 1);
    assert.match(out.suppressed[0].reason, /server "ctx", check "unpinned package"/);
  });

  it("requires every path arg of a server to be inside the allowed paths", () => {
    const p = policy({ allow: [{ server: "files", paths: ["/home/u/projects"] }] });
    const ok = server({ name: "files", args: ["--allowed", "/home/u/projects/sub", "x"] });
    const bad = server({ name: "files", args: ["/etc"] });
    const f = finding({ server: "files" });
    assert.equal(applyPolicy([ok], [f], p).suppressed.length, 1);
    assert.equal(applyPolicy([bad], [f], p).findings.length, 1);
    // no path args at all: scope unknown, never suppressed
    assert.equal(applyPolicy([server({ name: "files" })], [f], p).findings.length, 1);
  });

  it("adds deny violations that cannot be allowlisted", () => {
    const p = policy({
      deny: [{ server: "*", args_pattern: "--no-sandbox" }],
      allow: [{ server: "chrome" }],
    });
    const out = applyPolicy([server({ name: "chrome", args: ["--no-sandbox"] })], [], p);
    assert.equal(out.findings.length, 1);
    assert.equal(out.findings[0].severity, "critical");
    assert.match(out.findings[0].title, /Deny policy violated/);
  });

  it("applies severity overrides before filtering and sorting", () => {
    const p = policy({ severity: { "unpinned package version": "critical" } });
    const out = applyPolicy([server()], [finding(), finding({ title: "Network access", severity: "low" })], p, "high");
    assert.deepEqual(out.findings.map((f) => f.title), ["Unpinned package version"]);
    assert.equal(out.findings[0].severity, "critical");
  });

  it("the most specific severity key wins over a category key", () => {
    const p = policy({ severity: { secrets: "low", "hardcoded github secret": "critical" } });
    const f = finding({ category: "secrets", title: "Hardcoded GitHub secret" });
    assert.equal(overrideSeverity(f, p.severity), "critical");
    assert.equal(overrideSeverity(finding({ category: "secrets", title: "Short secret value" }), p.severity), "low");
  });
});

describe("loadPolicy / mergePolicies", () => {
  it("uses only the explicit file when given one", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-audit-policy-"));
    const file = join(dir, ".mcp-audit.yml");
    writeFileSync(file, "allow:\n  - server: x\n");
    const p = loadPolicy(dir, file);
    assert.deepEqual(p.allow, [{ server: "x" }]);
    assert.deepEqual(p.files, [p.files[0]]);
  });

  it("errors clearly on a missing or empty path", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-audit-policy-"));
    assert.throws(() => loadPolicy(dir, join(dir, "nope.yml")), /Policy file not found/);
    assert.throws(() => loadPolicy(dir, "  "), /--policy requires a file path/);
  });

  it("merges global and project policies, project severity winning", () => {
    const merged = mergePolicies([
      policy({ allow: [{ server: "a" }], severity: { secrets: "low" }, files: ["/global"] }),
      policy({ allow: [{ server: "b" }], severity: { secrets: "high" }, files: ["/project"] }),
    ]);
    assert.deepEqual(merged.allow, [{ server: "a" }, { server: "b" }]);
    assert.equal(merged.severity.secrets, "high");
    assert.deepEqual(merged.files, ["/global", "/project"]);
  });

  it("an empty policy changes nothing", () => {
    const findings = [finding()];
    const out = applyPolicy([server()], findings, emptyPolicy());
    assert.deepEqual(out.findings, findings);
    assert.equal(out.suppressed.length, 0);
  });
});
