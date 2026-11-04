// The MCP server names Crush is configured with, so the Crush dialect can
// tell `mcp_exa_evil_t` (server `exa_evil`) from `mcp_exa_web_search` (server
// `exa`): Crush names an MCP tool `mcp_<server>_<tool>` with no escaping
// (internal/agent/tools/mcp-tools.go:58-60 at v0.99.0), and a server name may
// hold `_`. Integration w2's re-review W2-R1 left this class of name to the
// agent's own server list.
//
// Where Crush reads its config, at v0.99.0 (internal/config/load.go):
// - /etc/crush/crush.json (config_unix.go:7);
// - GlobalConfig(): $CRUSH_GLOBAL_CONFIG/crush.json, else the user config
//   folder's crush/crush.json (:1365-1370), and the crushrc beside it
//   (:1102, :1372-1377);
// - GlobalConfigData(): $CRUSH_GLOBAL_DATA/crush.json, else
//   $XDG_DATA_HOME/crush/crush.json, else ~/.local/share/crush/crush.json
//   (:1412-1435);
// - from the working folder up to the git work tree's root, or the working
//   folder alone with none: .crushrc, crushrc, .crush.json, crush.json
//   (:1094-1127, :1504-1513).
// A crushrc is Bash run by Crush's interpreter with an `mcp add <name>`
// builtin (internal/shellconfig/mcp.go:10-24). derm reads a crushrc only
// when every line is blank, a comment, or a plain builtin call with no
// expansion, quoting trick, redirection or control flow; anything else, an
// unreadable or invalid JSON file, or a name too odd to match, makes the
// list incomplete, and then every split that is not forced asks.
//
// Every name ever added counts (a later `mcp remove` is ignored): more names
// can only make a split ambiguous, never plain.

import { existsSync, lstatSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";

import type { ServerNames } from "./mcpSplit.ts";

export type { ServerNames };

const MAX_CONFIG_BYTES = 4 * 1024 * 1024;
const MAX_WALK = 64;

function configDir(env: NodeJS.ProcessEnv, home: string): string {
  const g = env.CRUSH_GLOBAL_CONFIG?.trim();
  if (g) return g;
  const xdg = env.XDG_CONFIG_HOME?.trim();
  return path.join(xdg && path.isAbsolute(xdg) ? xdg : path.join(home, ".config"), "crush");
}

function dataFile(env: NodeJS.ProcessEnv, home: string): string {
  const d = env.CRUSH_GLOBAL_DATA?.trim();
  if (d) return path.join(d, "crush.json");
  const xdg = env.XDG_DATA_HOME?.trim();
  if (xdg) return path.join(xdg, "crush", "crush.json");
  return path.join(home, ".local", "share", "crush", "crush.json");
}

/** The folders from `cwd` up to the git work tree's root (a `.git` file or folder), or `cwd` alone. */
export function projectFolders(cwd: string): string[] {
  const out: string[] = [];
  let dir = path.resolve(cwd);
  for (let i = 0; i < MAX_WALK; i++) {
    out.push(dir);
    if (existsSync(path.join(dir, ".git"))) return out;
    const up = path.dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  return [path.resolve(cwd)];
}

function readSmall(file: string): string | undefined | null {
  try {
    const st = lstatSync(file);
    if (st.isSymbolicLink()) {
      const real = statSync(file);
      if (!real.isFile() || real.size > MAX_CONFIG_BYTES) return null;
    } else if (!st.isFile() || st.size > MAX_CONFIG_BYTES) return null;
    return readFileSync(file, "utf8");
  } catch (error) {
    return (error as NodeJS.ErrnoException)?.code === "ENOENT" ? undefined : null;
  }
}

/** The `mcp` keys of one JSON config; null when the file is there and cannot be read whole. */
export function jsonServerNames(text: string): string[] | null {
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof v !== "object" || v === null || Array.isArray(v)) return null;
  const mcp = (v as Record<string, unknown>).mcp;
  if (mcp === undefined || mcp === null) return [];
  if (typeof mcp !== "object" || Array.isArray(mcp)) return null;
  return Object.keys(mcp);
}

const PLAIN_WORD = /^[A-Za-z0-9_@%+=:,./-]+$/;
const QUOTED = /^'[^'\n]*'$/;

/**
 * The names a crushrc's `mcp add` lines give, or null when a line is
 * anything but blank, a comment, or a builtin call made of plain words and
 * single-quoted strings (no `$`, backticks, double quotes, backslashes,
 * redirections, pipes, `;`, `&`, globs, braces or control flow).
 */
export function crushrcServerNames(text: string): string[] | null {
  const names: string[] = [];
  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (line === "" || line.startsWith("#")) continue;
    const words = line.match(/'[^']*'|[^\s']+/g) ?? [];
    if (words.join(" ").length === 0) continue;
    for (const w of words) if (!PLAIN_WORD.test(w) && !QUOTED.test(w)) return null;
    const plain = words.map((w) => (QUOTED.test(w) ? w.slice(1, -1) : w));
    if (plain[0] === "mcp" && plain[1] === "add") {
      if (plain[2] === undefined) return null;
      names.push(plain[2]);
    }
    if (["if", "then", "else", "fi", "for", "while", "case", "function", "source", ".", "eval", "alias", "exec", "export", "set", "unset", "cd", "pushd", "trap", "declare", "local", "readonly"].includes(plain[0] ?? "")) return null;
  }
  return names;
}

/** Every MCP server name Crush may have, with whether the list is whole. */
export function crushServerNames(env: NodeJS.ProcessEnv, cwd: string | undefined, home: string = env.HOME?.trim() || homedir()): ServerNames {
  const names = new Set<string>();
  let complete = true;
  let why: string | undefined;
  const fail = (reason: string) => {
    complete = false;
    why ??= reason;
  };
  const dir = configDir(env, home);
  const jsonFiles = ["/etc/crush/crush.json", path.join(dir, "crush.json"), dataFile(env, home)];
  const rcFiles = [path.join(dir, "crushrc")];
  if (cwd === undefined || cwd === "" || !path.isAbsolute(cwd)) fail("the hook input has no absolute cwd");
  else {
    for (const d of projectFolders(cwd)) {
      rcFiles.push(path.join(d, ".crushrc"), path.join(d, "crushrc"));
      jsonFiles.push(path.join(d, ".crush.json"), path.join(d, "crush.json"));
    }
  }
  for (const f of jsonFiles) {
    const text = readSmall(f);
    if (text === undefined) continue;
    const got = text === null ? null : jsonServerNames(text);
    if (got === null) fail(`${path.basename(f)} could not be read`);
    else for (const n of got) names.add(n);
  }
  for (const f of rcFiles) {
    const text = readSmall(f);
    if (text === undefined) continue;
    const got = text === null ? null : crushrcServerNames(text);
    if (got === null) fail(`a crushrc derm cannot read statically (${path.basename(f)})`);
    else for (const n of got) names.add(n);
  }
  return { names: [...names], complete, ...(why !== undefined ? { why } : {}) };
}
