// The MCP server names Kiro CLI is configured with, so the Kiro dialect can
// split `mcp_<server>_<tool>` (kiro.dev/docs/hooks/types, "MCP tool hooks":
// V3 hook events carry the sanitized internal id). Where Kiro reads MCP
// servers, read 3 Nov 2026: ~/.kiro/settings/mcp.json and the workspace's
// .kiro/settings/mcp.json, `mcpServers` in each (kiro.dev/docs/mcp/
// configuration, "Configuration locations" and "loading priority"), and
// `mcpServers` in an agent profile (kiro.dev/docs/custom-agents/
// configuration-reference). A profile may also be Markdown with its config
// in frontmatter (same page, "Markdown format"), which derm does not parse:
// a `.md` profile makes the list incomplete, as do Powers, which bring
// servers derm cannot list (any `powers` folder under .kiro).
//
// How Kiro sanitizes a server name into the id was not found, so each name
// counts as written and with every character outside [A-Za-z0-9_-] as `_`;
// more names can only make a split ambiguous, never plain. A file that
// cannot be read whole makes the list incomplete.

import { lstatSync, readFileSync, readdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import type { ServerNames } from "./mcpSplit.ts";

const MAX_BYTES = 4 * 1024 * 1024;
const MAX_PROFILES = 256;

function read(file: string): string | undefined | null {
  try {
    const st = lstatSync(file);
    const real = st.isSymbolicLink() ? statSync(file) : st;
    if (!real.isFile() || real.size > MAX_BYTES) return null;
    return readFileSync(file, "utf8");
  } catch (error) {
    return (error as NodeJS.ErrnoException)?.code === "ENOENT" ? undefined : null;
  }
}

function serversIn(text: string): string[] | null {
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof v !== "object" || v === null || Array.isArray(v)) return null;
  const m = (v as Record<string, unknown>).mcpServers;
  if (m === undefined || m === null) return [];
  if (typeof m !== "object" || Array.isArray(m)) return null;
  return Object.keys(m);
}

export function kiroServerNames(env: NodeJS.ProcessEnv, cwd: string | undefined, home: string = env.HOME?.trim() || homedir()): ServerNames {
  const names = new Set<string>();
  let complete = true;
  let why: string | undefined;
  const fail = (reason: string) => {
    complete = false;
    why ??= reason;
  };
  const roots = [path.join(home, ".kiro")];
  if (cwd === undefined || !path.isAbsolute(cwd)) fail("the hook input has no absolute cwd");
  else roots.push(path.join(cwd, ".kiro"));
  for (const root of roots) {
    const files = [path.join(root, "settings", "mcp.json")];
    try {
      const all = readdirSync(path.join(root, "agents"));
      if (all.some((f) => f.endsWith(".md"))) fail("a Markdown agent profile");
      const profiles = all.filter((f) => f.endsWith(".json"));
      if (profiles.length > MAX_PROFILES) fail("too many agent profiles");
      for (const p of profiles.slice(0, MAX_PROFILES)) files.push(path.join(root, "agents", p));
    } catch (error) {
      if ((error as NodeJS.ErrnoException)?.code !== "ENOENT") fail("an agents folder could not be listed");
    }
    try {
      if (statSync(path.join(root, "powers")).isDirectory()) fail("Kiro Powers bring servers derm cannot list");
    } catch {
      // No powers folder.
    }
    for (const f of files) {
      const text = read(f);
      if (text === undefined) continue;
      const got = text === null ? null : serversIn(text);
      if (got === null) fail(`${path.basename(f)} could not be read`);
      else
        for (const n of got) {
          names.add(n);
          names.add(n.replace(/[^A-Za-z0-9_-]/g, "_"));
        }
    }
  }
  return { names: [...names], complete, ...(why !== undefined ? { why } : {}) };
}
