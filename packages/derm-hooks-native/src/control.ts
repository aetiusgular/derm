// The lane N agents' own control files. The core's list (src/core/policy.ts
// CONTROL_PATHS) predates these agents and names none of them; an allowed
// call whose input names one is asked here instead, the same rule the core
// applies to its own list (narrowing only, never widening). A request for
// integration adds them to the core and to derm-core, after which this list
// can shrink to nothing, as lane I's Gemini list did.
//
// Why each one is on the list is in the comment beside it; sources per
// agent are in plans/parallel/tk_lane_N.md, Research.

import { decodeEscapes, fold } from "./core/fold.ts";
import { unquote, type Action } from "./core/policy.ts";

export const NATIVE_CONTROL_PATHS = [
  // Cursor: hooks.json (the gate's registration), cli-config.json (its
  // permission lists), mcp.json; the managed hooks files.
  ".cursor/",
  "cursor/hooks.json",
  // Antigravity: ~/.gemini/config/hooks.json is under ~/.gemini/, already
  // the core's (Gemini CLI shares the folder); the workspace's
  // .agents/hooks.json (CHANGELOG 1.1.1) is not.
  ".agents/hooks.json",
  // goose: the plugin folder that holds derm's hooks.json, its config and
  // permission files, and the variables that move them or switch its mode.
  ".agents/plugins/",
  ".config/goose/",
  "goose_path_root",
  "goose_mode",
  "goose_disable_keyring",
  // Mistral Vibe: hooks.toml, config.toml, trusted folders, and the
  // variable that moves the folder.
  ".vibe/",
  "vibe_home",
  // Crush: crush.json and crushrc (global and project), its data folder,
  // and the variables that move them.
  ".config/crush/",
  ".local/share/crush/",
  "crushrc",
  "crush.json",
  "crush_global_config",
  "crush_global_data",
  // Kiro: agent configs with their hooks, settings, steering.
  ".kiro/",
  "kiro_home",
] as const;

/** The first lane N control path the input names, read the way the core reads its own list. */
export function nativeControlPath(inputText: string): string | undefined {
  const folded = fold(decodeEscapes(inputText));
  const unquoted = unquote(folded);
  return NATIVE_CONTROL_PATHS.find((p) => folded.includes(p) || unquoted.includes(p));
}

/** Narrows an allow to ask when the input names a lane N control path. Never widens. */
export function narrowForControl(action: Action, inputText: string): { action: Action; control?: string } {
  if (action !== "allow") return { action };
  const control = nativeControlPath(inputText);
  return control ? { action: "ask", control } : { action };
}
