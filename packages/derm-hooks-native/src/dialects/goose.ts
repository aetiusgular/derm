// goose (block/goose), read and run at v1.57.0, whose hook code equals
// 1.56.0's (plans/parallel/tk_lane_N.md, Research, with each claim's file
// and line; contracts/fixtures/hook-dialects/goose/ for 1.56.0):
// - Registered as a plugin: ~/.agents/plugins/derm/ with plugin.json and
//   hooks/hooks.json, `PreToolUse[{matcher, hooks: [{type: "command",
//   command, timeout, on_failure: "block"}]}]`; the command runs under sh -c.
// - Stdin: {event, session_id, matcher_context, tool_name, tool_input,
//   tool_call_id, working_dir}. No server field.
// - Deny: exit 2 with the reason on stderr, or {"decision": "block",
//   "reason"} on stdout at any exit. This hook does both.
// - Allow: exit 0 with nothing printed. No ask and no input rewrite.
// - A failed hook (timeout, crash, bad JSON) allows unless `on_failure` is
//   "block", which derm's registration sets.
// - The hook gets goose's whole environment; nothing is stripped by name.
// - Names: built-in tools bare (`shell`, `write`, `edit`; the shell is
//   `shell`, run on 1.57.0), extension tools
//   `<extension key>__<tool>`; the key keeps [A-Za-z0-9_-] lowercased, so it
//   can itself hold `__`, and a name with two runs of `__` cannot say where
//   the extension ends: an allow there asks.

import { NONE, chatFrom, oneLine, type Dialect, type HookResult, type ReadCall } from "../runner.ts";
import { asCoreShell, type ShellForm } from "../shell.ts";

export const GOOSE_SHELL: ShellForm = { names: ["shell"], commandFields: ["command"] };

function block(reason: string): HookResult {
  const text = `derm: ${oneLine(reason)}`;
  return { stdout: `${JSON.stringify({ decision: "block", reason: text })}\n`, stderr: `${text}\n`, exitCode: 2 };
}

export function gooseRead(input: Record<string, unknown>, env: NodeJS.ProcessEnv): ReadCall | string {
  if (input.event !== undefined && input.event !== "PreToolUse") return `unexpected hook event ${String(input.event).slice(0, 40)}`;
  const raw = input.tool_name;
  if (typeof raw !== "string" || raw === "") return "hook input has no tool_name";
  const { tool, toolInput } = asCoreShell(GOOSE_SHELL, raw, input.tool_input ?? {});
  const read: ReadCall = { tool, rawTool: raw, toolInput };
  const chat = chatFrom(env, input.session_id);
  if (chat !== undefined) read.chat = chat;
  if (typeof input.tool_call_id === "string" && input.tool_call_id !== "") read.callId = input.tool_call_id;
  const runs = raw.match(/_{2,}/g) ?? [];
  if (runs.length > 1) read.ambiguous = "ambiguous extension name: goose's key can hold __ itself";
  return read;
}

export const goose: Dialect = {
  id: "goose",
  name: "goose",
  read: gooseRead,
  ownAsk: () => false,
  allow: () => NONE,
  deny: block,
  // Never reached: goose shows no prompt for a hook (ownAsk false).
  ask: block,
  canRewrite: false,
};
