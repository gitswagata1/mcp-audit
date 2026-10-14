<div align="center">

# mcp-audit

### Know what your AI tools can access. In 5 seconds.

Security scanner for [Model Context Protocol](https://modelcontextprotocol.io) servers.<br/>
Finds dangerous permissions, hardcoded secrets, supply chain risks, and transport vulnerabilities across all your MCP configs.

**One command. Zero config. Zero dependencies.**

```
npx mcp-audit
```

<br/>

<img src="https://img.shields.io/npm/v/mcp-audit?style=flat-square&color=blue" alt="npm" />
<img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="MIT" />
<img src="https://img.shields.io/badge/node-%3E%3D18-brightgreen?style=flat-square" alt="node" />
<img src="https://img.shields.io/badge/dependencies-0-brightgreen?style=flat-square" alt="zero deps" />
<img src="https://img.shields.io/badge/checks-40+-blue?style=flat-square" alt="40+ checks" />
<img src="https://img.shields.io/badge/grade-A--F_scoring-purple?style=flat-square" alt="grading" />

</div>

---

## The Problem

MCP servers are the new plugins. Every AI IDE supports them — Claude, Cursor, Windsurf, Zed, Copilot, and more. Developers install them freely.

But each MCP server can:
- **Execute shell commands** on your machine
- **Read and write files** anywhere on disk
- **Access your API keys** passed via environment variables
- **Make network requests** to any endpoint
- **Run unpinned packages** from npm/PyPI with zero verification
- **Exfiltrate data** through remote SSE/HTTP endpoints

There's no `npm audit` for MCP. **Until now.**

---

## What It Scans

| Client | Config Locations |
|--------|-----------------|
| Claude Desktop | `~/Library/Application Support/Claude/`, `%APPDATA%/Claude/`, `~/.config/claude/` |
| Claude Code | `~/.claude.json`, `.claude/settings.json`, `.mcp.json` |
| Cursor | `~/.cursor/mcp.json`, `.cursor/mcp.json` |
| Windsurf | `~/.codeium/windsurf/`, `.windsurf/` |
| Zed | `~/.config/zed/settings.json`, platform-specific |
| Cline | `~/.cline/mcp_settings.json`, `.cline/` |
| Roo Code | `~/.roo/mcp.json`, `.roo/` |
| Amazon Q | `~/.aws/amazonq/mcp.json` |
| GitHub Copilot | `.github/copilot-mcp.json` |
| VS Code (Continue) | `~/.continue/config.json` |
| Project root | `mcp.json` |

## What It Checks

### Permissions (Critical → Medium)

| Check | Severity | What it catches |
|-------|----------|-----------------|
| Shell access | Critical | Servers spawning bash/sh/cmd/powershell — unrestricted execution |
| Overly broad filesystem | Critical | Access to `/`, `~`, `C:\` — the entire filesystem |
| Remote code execution | Critical | Scripts fetched and executed from URLs |
| Dangerous flags | Critical–High | `--no-sandbox`, `--allow-all`, `sudo`, `--privileged` |
| Filesystem access | High | Read/write access to disk with scope info |
| Shell metacharacters | High | `|`, `;`, `` ` ``, `$()` in args — command injection risk |
| Network access | Medium | Fetch, puppeteer, browser, scraping capabilities |

### Secrets (Critical → Info)

| Check | Severity | What it catches |
|-------|----------|-----------------|
| Hardcoded API keys | Critical | 25+ patterns: OpenAI, Anthropic, AWS, GitHub, Stripe, Twilio, Slack, Google, SendGrid, Supabase, npm, PyPI, Hugging Face, Replicate, JWT... |
| Secret in command args | Critical | API keys visible in process listings and shell history |
| Hidden secrets | Critical | Keys in non-standard env var names (evades simple scanners) |
| Possible credentials | High | Suspicious inline values that match credential heuristics |

### Supply Chain (Critical → Medium)

| Check | Severity | What it catches |
|-------|----------|-----------------|
| Privileged containers | Critical | Docker/Podman `--privileged` — near-host access |
| Sensitive volume mounts | Critical | Mounting `/`, `/home`, `/etc` into containers |
| Host network/PID | High | `--network=host`, `--pid=host` — shared namespaces |
| Typosquat indicators | High | Package names matching common typosquatting patterns |
| Unverified packages | Medium | Not from 20+ known publishers (Anthropic, Cloudflare, Stripe, Prisma, etc.) |
| Unpinned versions | Medium | `npx pkg` without `@version` — supply chain risk |
| Auto-confirm flags | Medium | `--yes`/`-y` on package runners — silent installs |

### Transport (Critical → Info)

| Check | Severity | What it catches |
|-------|----------|-----------------|
| Credentials in URL | Critical | `user:pass@` embedded in server URLs |
| Unencrypted HTTP | High | Plain HTTP transport for remote MCP servers |
| Malformed URLs | Medium | Unparseable server endpoints |
| Remote server info | Info | HTTPS remote servers — trust verification reminder |

### Environment (Critical → High)

| Check | Severity | What it catches |
|-------|----------|-----------------|
| Library injection | Critical | `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES` — runs arbitrary code before main process |
| Proxy + credentials | Critical | Proxy env vars + secrets in same server — credential interception risk |
| PATH hijack | Critical | `.` or empty entries in PATH — arbitrary binary execution |
| Runtime hijack | High | `NODE_OPTIONS`, `PYTHONPATH`, `PYTHONSTARTUP`, `JAVA_TOOL_OPTIONS`, `RUBYOPT` |
| Proxy override | High | `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` — traffic interception |
| TLS/SSH interception | High | `CURL_CA_BUNDLE`, `SSL_CERT_FILE`, `GIT_SSH_COMMAND` — MITM vectors |
| Credential reuse | Medium | Same secret value shared across multiple servers |

### Config Hygiene (Critical → Low)

| Check | Severity | What it catches |
|-------|----------|-----------------|
| World-writable config | Critical | Config files writable by any user — attacker can inject servers |
| World-readable config | High | Config files with secrets readable by any user |
| Shadow servers | High | Same name, different command across configs |
| Group-writable config | Medium | Config files writable by group members |
| No command or URL | Medium | Broken server entries that can't start |
| Duplicate definitions | Low | Same server in multiple config files |
| Excess env vars | Low | Too many env vars not referenced in command |

---

## Security Grade

Every audit produces an overall **security grade** (A–F) and per-server scores:

| Grade | Score | Meaning |
|-------|-------|---------|
| **A** | 90–100 | Clean or only informational findings |
| **B** | 75–89 | Minor issues, no critical risks |
| **C** | 50–74 | Multiple medium-severity issues |
| **D** | 25–49 | Significant security concerns |
| **F** | 0–24 | Critical vulnerabilities present |

---

## CLI Options

```
npx mcp-audit                    Scan all MCP configs
npx mcp-audit --verbose          Show paths, recommendations, file locations
npx mcp-audit --json             Machine-readable JSON (with scores and metadata)
npx mcp-audit --markdown         Output as Markdown (for PRs, CI comments)
npx mcp-audit --severity high    Only show high+ findings
npx mcp-audit --policy <path>    Use one specific .mcp-audit.yml policy file
npx mcp-audit --no-policy        Ignore global and project policy files
npx mcp-audit --help             Full help
```

## Example Output

```
  mcp-audit v0.3.0 — security scanner for MCP servers
  ────────────────────────────────────────────────────────

  Servers discovered: 6

  shell-danger  (Claude Code)  stdio  🔵 B (1 issue)
    cmd: bash -c echo hello

  filesystem-root  (Claude Code)  stdio  🔵 B (1 issue)
    cmd: npx @modelcontextprotocol/server-filesystem /

  leaky-server  (Claude Code)  stdio  🔴 F (7 issues)
    cmd: npx some-random-pkg
    env: API_KEY, DATABASE_URL, HTTP_PROXY, NODE_OPTIONS

  http-remote  (Claude Code)  remote  🔵 B (2 issues)
    url: http://dangerous.example.com/mcp

  docker-priv  (Claude Code)  stdio  🟠 D (3 issues)
    cmd: docker run --privileged --network=host some-image

  safe-server  (Claude Code)  stdio  🟢 A
    cmd: npx @modelcontextprotocol/server-brave-search@1.2.0
    env: BRAVE_API_KEY

  Findings: 14

  🛑 CRITICAL [Permissions] Direct shell access
    Server "shell-danger" spawns a shell (bash).
    → Replace with a purpose-built MCP server. Never grant raw shell access.

  🛑 CRITICAL [Secrets] Hardcoded Anthropic secret
    Server "leaky-server" has a hardcoded Anthropic key in env var "API_KEY".
    → Move to an environment variable or secrets manager.

  🛑 CRITICAL [Environment] Proxy + credentials combination
    Server "leaky-server" has proxy and credentials in env. Interception risk.
    → Remove proxy env vars or ensure they use trusted HTTPS endpoints.

  🟠 HIGH [Environment] Dangerous env var: NODE_OPTIONS
    Server "leaky-server" sets NODE_OPTIONS. Risk: flag injection.
    → Remove unless absolutely required.

  🟠 HIGH [Transport] Unencrypted HTTP transport
    Server "http-remote" connects over plain HTTP. Traffic is unencrypted.
    → Use HTTPS (TLS) for all remote MCP connections.

  ... (8 more findings)

  ────────────────────────────────────────────────────────

  🔴 Security Grade: F  (0/100)
  5 of 6 servers have issues
  14 findings (6 critical, 5 high, 3 medium)
  by category: 4 permissions, 4 supply chain, 3 environment, 2 secrets, 1 transport
  3 config paths scanned
```

---

## CI / Automation

Machine-readable JSON (with scores and metadata):

```bash
npx mcp-audit --json
```

Markdown for PR comments:

```bash
npx mcp-audit --markdown >> $GITHUB_STEP_SUMMARY
```

GitHub Actions:

```yaml
- name: Audit MCP servers
  run: npx mcp-audit --severity high

- name: Post audit to PR summary
  run: npx mcp-audit --markdown >> $GITHUB_STEP_SUMMARY
  if: always()
```

## Policy Files

A `.mcp-audit.yml` file codifies what your team considers acceptable, so known-good
setups stop lowering the grade. mcp-audit loads `~/.config/mcp-audit/.mcp-audit.yml`
(or `~/.mcp-audit.yml`) first and then `<project root>/.mcp-audit.yml`; rules from both
apply and the project file wins on conflicting severity keys. Use `--policy <path>` for a
single file or `--no-policy` to ignore them. See [`.mcp-audit.example.yml`](.mcp-audit.example.yml).

```yaml
allow:                       # findings that match are reported as suppressed
  - server: "filesystem"     # server names accept * wildcards
    paths: ["/home/user/projects"]   # every served path must be inside
  - server: "context7"
    check: "unpinned package"        # a category or part of a finding title
deny:                        # always a critical finding, cannot be allowlisted
  - server: "*"
    args_pattern: "--no-sandbox"     # plain substring in args / command / url
severity:                    # override defaults by category or check
  secrets: high
  unpinned package version: medium
```

```bash
npx mcp-audit --policy .mcp-audit.yml --json   # includes policy.files + policy.suppressed
```

Suppressions and overrides are applied *before* grading, so they change the score,
the per-server grades and the exit codes, not just the display. Invalid policy files
fail with a section, key and line number instead of being silently ignored.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No critical or high findings |
| `1` | High-severity findings detected |
| `2` | Critical-severity findings detected |

---

## Roadmap

- [ ] SARIF output for GitHub Security tab integration
- [ ] Auto-fix suggestions (pin versions, move secrets to env)
- [ ] Community-maintained vulnerability database for MCP packages
- [x] Policy file (`.mcp-audit.yml`) for custom rules and allowlists
- [ ] VS Code / Cursor extension
- [ ] Watch mode — re-scan on config changes
- [ ] Scoring system — overall security grade (A–F)

---

## Try the Demo

```bash
git clone https://github.com/gitswagata1/mcp-audit
cd mcp-audit
npm install && npm run build
bash demo/run-demo.sh
```

## Contributing

PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

```bash
git clone https://github.com/gitswagata1/mcp-audit
cd mcp-audit
npm install
npm run dev
```

---

## License

[MIT](LICENSE) — Swagata Banerjee
