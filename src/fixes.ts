import type { Fix, McpServer, ServerPatch } from "./types.js";
import { redactArgs } from "./checks/secrets.js";

/** Fix that replaces the server's args with a corrected list. Undefined if nothing would change. */
export function argsFix(server: McpServer, transform: (args: string[]) => string[]): Fix | undefined {
  const next = transform([...server.args]);
  if (next.length === server.args.length && next.every((a, i) => a === server.args[i])) return undefined;
  return { file: server.sourcePath, patch: { args: redactArgs(next) } };
}

/** Fix that sets (string) or removes (null) env vars on the server. */
export function envFix(server: McpServer, env: Record<string, string | null>): Fix {
  return { file: server.sourcePath, patch: { env } };
}

/** Fix that replaces the server URL; credentials are always stripped. */
export function urlFix(server: McpServer, opts: { https?: boolean } = {}): Fix | undefined {
  try {
    const url = new URL(server.url);
    url.username = "";
    url.password = "";
    if (opts.https && url.protocol === "http:") url.protocol = "https:";
    return { file: server.sourcePath, patch: { url: url.toString() } };
  } catch {
    return undefined;
  }
}

/** Render a patch as compact JSON, e.g. {"args":["-y","pkg@<version>"]}. */
export function formatPatch(patch: ServerPatch): string {
  return JSON.stringify(patch);
}

/**
 * Copy-pasteable, single-line form of a fix for text and markdown output:
 * the JSON merge patch for the server entry and/or the shell command to run.
 */
export function formatFix(fix: Fix): string {
  const parts: string[] = [];
  if (fix.patch) parts.push(formatPatch(fix.patch));
  if (fix.command) parts.push(fix.command);
  return parts.join("; ");
}
