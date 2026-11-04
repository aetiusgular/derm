// The eight agents' own control files. The shared core's control list
// (src/core/policy.ts CONTROL_PATHS) predates these adapters and does not
// name them; an allowed call whose input names one is asked here instead, the
// same rule the core applies to its own list (lane I's Gemini control.ts is
// the prior art). A request for integration adds them to the core and to
// derm-core, after which this file can go.
//
// Why each one, per agent (sources in plans/parallel/tk_lane_L.md, Research):
// - OpenClaude: `.openclaude/` holds settings.json with `hooks` and
//   `disableAllHooks`; OPENCLAUDE_CONFIG_DIR moves it; `.openclaude.json` is
//   its MCP and state file.
// - Qwen Code: `.qwen/` holds settings.json with `hooks` and
//   `disableAllHooks`; QWEN_HOME moves it and QWEN_CODE_SYSTEM_SETTINGS_PATH
//   names the managed file (0.26.6 bundle strings).
// - Droid: `.factory/` holds settings.json, hooks.json or hooks/hooks.json
//   (which shadow the PreToolUse array of settings.json) and mcp.json;
//   FACTORY_HOME_OVERRIDE moves it (1.3.0 binary strings, j8H()).
// - Command Code: `.commandcode/` holds settings.json with `hooks`.
// - Kimi Code: `.kimi-code/` holds config.toml with `[[hooks]]`; an unknown
//   key in one entry makes it drop the whole hooks section (run, 2.4.1);
//   KIMI_CODE_HOME moves it.
// - Auggie: `.augment/` holds settings.json with `hooks` and
//   `toolPermissions`.
// - Copilot CLI: `.copilot/` holds hooks/*.json and settings.json (with
//   `disableAllHooks`); COPILOT_HOME moves it.
// - Grok Build: `.grok/` holds hooks/*.json and config.toml (`[compat.*]
//   hooks`); GROK_CLAUDE_HOOKS_ENABLED and GROK_CURSOR_HOOKS_ENABLED switch
//   its compat imports.

import { decodeEscapes, fold } from "./core/fold.ts";
import { unquote, type Action } from "./core/policy.ts";

export const AGENT_CONTROL_PATHS = [
  ".openclaude/",
  ".openclaude.json",
  "openclaude_config_dir",
  ".qwen/",
  "qwen_home",
  "qwen_code_system_settings",
  ".factory/",
  "factory_home_override",
  ".commandcode/",
  ".kimi-code/",
  "kimi_code_home",
  ".augment/",
  ".copilot/",
  "copilot_home",
  ".grok/",
  "grok_claude_hooks_enabled",
  "grok_cursor_hooks_enabled",
  "grok_home",
] as const;

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * A folder entry also matches its bare name, so a command that moves or
 * deletes the whole folder (`mv ~/.factory x`, `rm -r .qwen`) is caught
 * (L-S4). The core adds the `/` only to fields other than a shell command
 * (src/core/gate.ts inputTextFor). The name must not run on into a longer
 * one (`.qwenrc`, `.factory-notes`, `.grok_cache`); anything else after it
 * (end, space, quote, `;`, `.bak`) counts, which only ever narrows.
 */
const BARE_FOLDERS = AGENT_CONTROL_PATHS.filter((p) => p.endsWith("/")).map((p) => ({ entry: p, re: new RegExp(`${escape(p.slice(0, -1))}(?![a-z0-9_-])`) }));

/** The first agent control path the input names, read the way the core reads its own list. */
export function agentControlPath(inputText: string): string | undefined {
  const folded = fold(decodeEscapes(inputText));
  const unquoted = unquote(folded);
  const named = AGENT_CONTROL_PATHS.find((p) => folded.includes(p) || unquoted.includes(p));
  if (named) return named;
  return BARE_FOLDERS.find(({ re }) => re.test(folded) || re.test(unquoted))?.entry;
}

/** Narrows an allow to ask when the input names one of the eight agents' control paths. Never widens. */
export function narrowForControl(action: Action, inputText: string): { action: Action; control?: string } {
  if (action !== "allow") return { action };
  const control = agentControlPath(inputText);
  return control ? { action: "ask", control } : { action };
}
