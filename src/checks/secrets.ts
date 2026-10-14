import type { McpServer, Finding, Fix } from "../types.js";

const SECRET_KEY_PATTERNS = [
  /api[_-]?key/i,
  /secret/i,
  /\btoken\b/i,
  /password/i,
  /\bpasswd\b/i,
  /credential/i,
  /\bauth\b/i,
  /private[_-]?key/i,
  /access[_-]?key/i,
  /signing[_-]?key/i,
  /encryption[_-]?key/i,
  /master[_-]?key/i,
  /\bdsn\b/i,
  /connection[_-]?string/i,
  /database[_-]?url/i,
  /\bwebhook\b/i,
];

const HARDCODED_VALUE_PATTERNS = [
  { pattern: /^sk-[a-zA-Z0-9]{20,}$/,             name: "OpenAI" },
  { pattern: /^sk-ant-[a-zA-Z0-9-]{20,}$/,        name: "Anthropic" },
  { pattern: /^ghp_[a-zA-Z0-9]{36}$/,             name: "GitHub PAT" },
  { pattern: /^gho_[a-zA-Z0-9]{36}$/,             name: "GitHub OAuth" },
  { pattern: /^github_pat_[a-zA-Z0-9_]{22,}$/,    name: "GitHub fine-grained PAT" },
  { pattern: /^ghs_[a-zA-Z0-9]{36}$/,             name: "GitHub App token" },
  { pattern: /^xoxb-/,                             name: "Slack bot" },
  { pattern: /^xoxp-/,                             name: "Slack user" },
  { pattern: /^xapp-/,                             name: "Slack app" },
  { pattern: /^AKIA[0-9A-Z]{16}$/,                name: "AWS access key" },
  { pattern: /^AIza[0-9A-Za-z_-]{35}$/,           name: "Google API key" },
  { pattern: /^sk_live_[a-zA-Z0-9]{24,}$/,        name: "Stripe live" },
  { pattern: /^rk_live_[a-zA-Z0-9]{24,}$/,        name: "Stripe restricted" },
  { pattern: /^sk_test_[a-zA-Z0-9]{24,}$/,        name: "Stripe test" },
  { pattern: /^SG\.[a-zA-Z0-9_-]{22}\./,          name: "SendGrid" },
  { pattern: /^AC[a-f0-9]{32}$/,                   name: "Twilio account SID" },
  { pattern: /^SK[a-f0-9]{32}$/,                   name: "Twilio API key" },
  { pattern: /^eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\./,  name: "JWT" },
  { pattern: /^npm_[a-zA-Z0-9]{36}$/,             name: "npm token" },
  { pattern: /^pypi-[a-zA-Z0-9_-]{20,}$/,         name: "PyPI token" },
  { pattern: /^sbp_[a-f0-9]{40}$/,                name: "Supabase" },
  { pattern: /^v[0-9]+\.[a-f0-9]{24}$/,           name: "Vercel" },
  { pattern: /^neon_[a-zA-Z0-9_-]{20,}$/,         name: "Neon DB" },
  { pattern: /^DO[A-Z0-9]{40,}$/,                  name: "DigitalOcean" },
  { pattern: /^hf_[a-zA-Z0-9]{34}$/,              name: "Hugging Face" },
  { pattern: /^r8_[a-zA-Z0-9]{38}$/,              name: "Replicate" },
  { pattern: /^AgAAAA[a-zA-Z0-9_-]{30,}$/,        name: "Databricks" },
];

/** Env reference (e.g. ${GITHUB_TOKEN}) that keeps a value out of the config file. */
export function envRef(key: string): string {
  return `\${${key}}`;
}

/**
 * Replace hardcoded secrets in args with env references (${API_KEY}, ${API_KEY_2}, ...)
 * so that fix patches never echo a secret back into reports or JSON output.
 */
export function redactArgs(args: string[]): string[] {
  let n = 0;
  return args.map((a) => {
    if (!HARDCODED_VALUE_PATTERNS.some((p) => p.pattern.test(a))) return a;
    n++;
    return envRef(n === 1 ? "API_KEY" : `API_KEY_${n}`);
  });
}

export function checkSecrets(server: McpServer): Finding[] {
  const findings: Finding[] = [];
  const envRefFix = (key: string): Fix => ({ file: server.sourcePath, patch: { env: { [key]: envRef(key) } } });

  for (const [key, value] of Object.entries(server.env)) {
    if (SECRET_KEY_PATTERNS.some((p) => p.test(key))) {
      const matched = HARDCODED_VALUE_PATTERNS.find((p) => p.pattern.test(value));
      const isEnvRef = value.startsWith("${") || value.startsWith("$");

      if (matched) {
        findings.push({
          severity: "critical",
          category: "secrets",
          title: `Hardcoded ${matched.name} secret`,
          detail: `Server "${server.name}" has a hardcoded ${matched.name} key in env var "${key}". This is stored in plaintext on disk.`,
          recommendation: `Move the value to an environment variable or secrets manager. Reference it as \${${key}} instead.`,
          fix: envRefFix(key),
          server: server.name,
          source: server.source,
        });
      } else if (!isEnvRef && value.length > 10) {
        findings.push({
          severity: "high",
          category: "secrets",
          title: "Possible hardcoded credential",
          detail: `Server "${server.name}" has env var "${key}" with a suspicious inline value (${value.length} chars). Consider using an environment variable reference.`,
          recommendation: `Replace the inline value with an env reference like \${${key}}.`,
          fix: envRefFix(key),
          server: server.name,
          source: server.source,
        });
      } else if (!isEnvRef && value.length > 0) {
        findings.push({
          severity: "info",
          category: "secrets",
          title: "Short secret value",
          detail: `Server "${server.name}" has env var "${key}" with a short inline value. Verify it's not a truncated credential.`,
          recommendation: "Use environment variable references for all secrets, regardless of length.",
          fix: envRefFix(key),
          server: server.name,
          source: server.source,
        });
      }
    }

    const matched = HARDCODED_VALUE_PATTERNS.find((p) => p.pattern.test(value));
    if (matched && !SECRET_KEY_PATTERNS.some((p) => p.test(key))) {
      findings.push({
        severity: "critical",
        category: "secrets",
        title: `${matched.name} key in non-standard env var`,
        detail: `Server "${server.name}" has a ${matched.name} key pattern in env var "${key}" (unusual name hides the secret from simple scans).`,
        recommendation: `Rename to a standard key name and move the value to a secrets manager.`,
        fix: envRefFix(key),
        server: server.name,
        source: server.source,
      });
    }
  }

  for (const arg of server.args) {
    const matched = HARDCODED_VALUE_PATTERNS.find((p) => p.pattern.test(arg));
    if (matched) {
      findings.push({
        severity: "critical",
        category: "secrets",
        title: `${matched.name} secret in command args`,
        detail: `Server "${server.name}" has a ${matched.name} key passed as a command argument. This is visible in process listings and shell history.`,
        recommendation: "Pass secrets via environment variables, never as CLI arguments.",
        fix: { file: server.sourcePath, patch: { args: redactArgs(server.args) } },
        server: server.name,
        source: server.source,
      });
    }
  }

  return findings;
}
