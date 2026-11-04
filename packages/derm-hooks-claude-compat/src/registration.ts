// Where each agent's gate is registered and the exact entry, for lane Q's
// `derm connect <agent> --gate` (which writes it under lane C's rules: user
// level only, a dry run first, a re-read before the write) and for the README.
// This package never writes a config file itself.
//
// Common to all eight (contracts/hook-dialects.md section 1):
// - user-level files only (case 78);
// - the matcher covers every tool, MCP tools included, so one gate sees all;
// - a timeout above the gate's own longest wait (the core caps an ask at 90 s,
//   src/core/gate.ts HOOK_ASK_CAP_SECONDS), because a timeout is the failure
//   most of these agents let through (case 70);
// - the agent's fail-closed switch where it has one;
// - beside an entry Orca or the user already has, never replacing it (case 75).

import { DIALECTS } from "./agents.ts";

export const GATE_TIMEOUT_SECONDS = 120;

export type Registration = {
  agent: string;
  /** The user-level file, `~` for the home folder; `homeEnv` moves the folder it is in. */
  file: string;
  homeEnv?: string;
  format: "json" | "toml";
  /**
   * How the entry goes in: appended to the `hooks.PreToolUse` array of a file
   * that holds other settings (`merge`), a file derm owns alone (`own-file`),
   * or one `[[hooks]]` table appended to a TOML file (`toml-array`).
   */
  shape: "merge" | "own-file" | "toml-array";
  /** The JSON value to merge or write, or the TOML text to append. */
  entry: unknown;
  /** Further settings the gate needs in another file (Grok's compat switches). */
  also?: { file: string; format: "toml"; text: string }[];
  /** Files that must not exist, or the gate is shadowed (Droid's hooks.json). */
  mustNotExist?: string[];
  notes: string[];
};

/** The hook's command line for `agent`, given the absolute path of this package's bin/derm-hook.mjs. */
export function hookCommand(agent: string, hookPath: string): string {
  if (!Object.hasOwn(DIALECTS, agent)) throw new Error(`no dialect for agent ${JSON.stringify(agent)}`);
  if (!hookPath.startsWith("/")) throw new Error("the hook path must be absolute");
  if (/["\\$`]/.test(hookPath)) throw new Error("the hook path holds a character a shell would read");
  // A control character or a line separator would end the command line or
  // make Kimi's TOML invalid, and Kimi then drops its whole hooks section (L-S8).
  if (/[\u0000-\u001f\u007f\u2028\u2029]/.test(hookPath)) throw new Error("the hook path holds a control character");
  return `node --no-warnings "${hookPath}" ${agent} pre`;
}

function claudeGroup(matcher: string, handler: Record<string, unknown>): Record<string, unknown> {
  return { hooks: { PreToolUse: [{ matcher, hooks: [{ type: "command", ...handler }] }] } };
}

const TOML_SHORT: Readonly<Record<string, string>> = { "\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r" };

/** A TOML basic string: `\`, `"` and every control character escaped (TOML 1.0, Basic strings). */
export function tomlString(s: string): string {
  const body = s.replace(/[\\"\u0000-\u001f\u007f]/g, (c) => {
    if (c === "\\") return "\\\\";
    if (c === '"') return '\\"';
    return TOML_SHORT[c] ?? `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`;
  });
  return `"${body}"`;
}

export function registrationFor(agent: string, hookPath: string): Registration {
  const command = hookCommand(agent, hookPath);
  switch (agent) {
    case "openclaude":
      return {
        agent,
        file: "~/.openclaude/settings.json",
        homeEnv: "OPENCLAUDE_CONFIG_DIR",
        format: "json",
        shape: "merge",
        entry: claudeGroup("*", { command, timeout: GATE_TIMEOUT_SECONDS }),
        notes: ["No fail-closed switch: a crashed or timed-out gate lets the call run (case 70)."],
      };
    case "qwen-code":
      return {
        agent,
        file: "~/.qwen/settings.json",
        format: "json",
        shape: "merge",
        entry: claudeGroup("", { command, name: "derm", timeout: GATE_TIMEOUT_SECONDS }),
        notes: ["No fail-closed switch.", "`disableAllHooks`, --safe-mode and --bare run no hook at all."],
      };
    case "droid":
      return {
        agent,
        file: "~/.factory/settings.json",
        format: "json",
        shape: "merge",
        homeEnv: "FACTORY_HOME_OVERRIDE",
        entry: claudeGroup("*", { command, timeout: GATE_TIMEOUT_SECONDS }),
        mustNotExist: ["~/.factory/hooks.json", "~/.factory/hooks/hooks.json"],
        notes: [
          "Droid 1.3.0 merges ~/.factory/hooks.json (else ~/.factory/hooks/hooks.json) over settings.json per event: a PreToolUse array there shadows derm's. derm never creates either file; derm doctor checks them.",
          "Activating a Factory hook-set through sync clears the hooks key of settings.json (clearHookFallbacks): derm status must re-check after a sync.",
          "`hooks.hooksDisabled: true` runs no hook.",
          "No fail-closed switch.",
        ],
      };
    case "command-code":
      return {
        agent,
        file: "~/.commandcode/settings.json",
        format: "json",
        shape: "merge",
        entry: claudeGroup(".*", { command, timeout: GATE_TIMEOUT_SECONDS, failClosed: true }),
        notes: [
          "failClosed: true blocks the call on a crash, a timeout or output it cannot read.",
          "The matcher is a regex on the tool's display name; `.*` takes every tool.",
          "Hooks do not run in plan mode.",
          "Command Code strips DERM_CHAT_TOKEN and DERM_CHAT_TOKEN_FILE from the hook's environment; the hook finds the token file from DERM_CHAT_ID and DERM_DAEMON_SOCKET (src/env.ts).",
        ],
      };
    case "kimi":
      return {
        agent,
        file: "~/.kimi-code/config.toml",
        homeEnv: "KIMI_CODE_HOME",
        format: "toml",
        shape: "toml-array",
        // Exactly `event`, `command` and `timeout`: a key Kimi does not know
        // makes it drop the whole config file. No `matcher`: every tool.
        entry: `[[hooks]]\nevent = "PreToolUse"\ncommand = ${tomlString(command)}\ntimeout = ${GATE_TIMEOUT_SECONDS}\n`,
        notes: ["Kimi reads only a deny; an allow changes nothing.", "No fail-closed switch."],
      };
    case "auggie":
      return {
        agent,
        file: "~/.augment/settings.json",
        format: "json",
        shape: "merge",
        // Timeout in milliseconds (passed to setTimeout). `.*` matches MCP
        // tools too; includeMCPMetadata names the server, which Auggie's
        // `<tool>_<server>` name alone does not settle.
        entry: { hooks: { PreToolUse: [{ matcher: ".*", metadata: { includeMCPMetadata: true }, hooks: [{ type: "command", command, timeout: GATE_TIMEOUT_SECONDS * 1000 }] }] } },
        notes: ["No fail-closed switch for hooks."],
      };
    case "copilot-cli":
      return {
        agent,
        file: "~/.copilot/hooks/derm.json",
        homeEnv: "COPILOT_HOME",
        format: "json",
        shape: "own-file",
        entry: { version: 1, hooks: { preToolUse: [{ type: "command", bash: command, timeoutSec: GATE_TIMEOUT_SECONDS }] } },
        notes: ["A crash or non-zero exit denies; a timeout always lets the call run."],
      };
    case "grok":
      return {
        agent,
        file: "~/.grok/hooks/derm.json",
        format: "json",
        shape: "own-file",
        entry: claudeGroup("*", { command, timeout: GATE_TIMEOUT_SECONDS, failClosed: true }),
        also: [{ file: "~/.grok/config.toml", format: "toml", text: "[compat.claude]\nhooks = false\n\n[compat.cursor]\nhooks = false\n" }],
        notes: [
          "failClosed exists from Grok 1.0.71; 1.0.70 ignores it and fails open.",
          "Grok also runs hooks from Claude Code's and Cursor's files; the compat switches stop a second derm gate (case 75).",
          "User hooks run only in a trusted folder.",
        ],
      };
    default:
      throw new Error(`no registration for ${agent}`);
  }
}
