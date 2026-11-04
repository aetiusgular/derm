// Case 82: the core's shell checks (case 30's unreadable tokens, the
// control files, the reject list's git keys read as a command) run only on
// the tool names it knows (`SHELL_TOOLS` in src/core/policy.ts). Each lane N
// agent names its shell otherwise, so a dialect maps the agent's shell tools
// to `bash`, and the field that holds the command to `command`, before the
// core sees the call. The names are the preset row's `coverage.shellAliases`
// (crates/derm-cli/src/connect/presets/<id>.json); a test holds the two
// lists equal.

import { isPlainObject } from "./runner.ts";

export type ShellForm = {
  /** The agent's own shell tool names, exactly as its hook input spells them. */
  names: readonly string[];
  /**
   * Fields that may hold the command line, first present wins. An array of
   * strings is joined with spaces (an argv). Every other field stays and is
   * read by the core too (a working folder, an env block).
   */
  commandFields: readonly string[];
};

/** Turns an agent shell call into the core's `bash` call; anything else is left as it came. */
export function asCoreShell(form: ShellForm, tool: string, toolInput: unknown): { tool: string; toolInput: unknown } {
  if (!form.names.includes(tool)) return { tool, toolInput };
  if (!isPlainObject(toolInput)) {
    // A shell call whose input is not an object: the core reads its text as
    // a whole, as `bash` (so case 30 still applies).
    return { tool: "bash", toolInput: { command: typeof toolInput === "string" ? toolInput : JSON.stringify(toolInput ?? null) } };
  }
  const out: Record<string, unknown> = {};
  let command: string | undefined;
  for (const f of form.commandFields) {
    const v = toolInput[f];
    if (typeof v === "string") command = v;
    else if (Array.isArray(v) && v.every((x) => typeof x === "string")) command = v.join(" ");
    if (command !== undefined) break;
  }
  for (const [k, v] of Object.entries(toolInput)) {
    if (k === "command" && command !== undefined) continue;
    out[k] = v;
  }
  // No command field the dialect knows: the whole input becomes the command
  // text, so nothing in it escapes the shell checks.
  out.command = command ?? JSON.stringify(toolInput);
  return { tool: "bash", toolInput: out };
}
