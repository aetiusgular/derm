// Mistral Vibe (mistralai/mistral-vibe), read at 3.0.4 in the PyPI wheel
// (mistralai_vibe_local_harness/vibe/) and at 3.0.3 in the repository
// (plans/parallel/tk_lane_N.md, Research; contracts/fixtures/
// hook-dialects/mistral-vibe/):
// - Registered as `[[hooks]]` in ~/.vibe/hooks.toml: name, type
//   "pre_tool", command, timeout, strict = true (a failed hook denies).
// - Stdin: {session_id, transcript_path, cwd, parent_session_id,
//   hook_event_name, tool_name, tool_call_id, tool_input}; tool_name is
//   qualified (`file_system.bash`, `process.start`, `mcp_<server>.<tool>`)
//   and tool_input uses the author-facing argument names
//   (_foreign_hooks.py:197-205).
// - Deny: {"decision": "deny", "reason"} on exit 0. Exit 2 is a failure,
//   not a deny (a deny under strict, but Vibe logs it as a broken hook).
// - Allow: nothing printed. Vibe's own permission check follows; a hook
//   cannot pre-approve, so derm's allow means "not blocked" (case 72).
// - No ask: an ask goes to derm's approver or is denied.
// - Rewrite: hook_specific_output.tool_input replaces the input.
// - Names: `<group>.<tool>`; an MCP group is `mcp_` plus the server name
//   folded to identifier characters, and the tool name folded the same way
//   (_mcp_naming.py:23-25, :102-123), so neither holds a `.`: exactly one
//   `.` splits the name plainly. Built-in tools map to the names Vibe's
//   own matcher gives the model (_hook_matcher.py:61-87); the shell tools
//   (`file_system.bash`, `process.start`, and `process.write`, which types
//   into a running process) become `bash` (case 82).

import { NONE, chatFrom, isPlainObject, oneLine, type Dialect, type HookResult, type ReadCall } from "../runner.ts";
import { asCoreShell, type ShellForm } from "../shell.ts";

export const VIBE_SHELL: ShellForm = { names: ["file_system.bash", "process.start", "process.write"], commandFields: ["command", "text"] };

/** Vibe's built-in names to the names its own matcher gives the model (_hook_matcher.py:61-87). */
export const VIBE_BUILTIN_NAMES: Readonly<Record<string, string>> = {
  "self.wait": "wait",
  "self.sleep": "sleep",
  "file_system.read_file": "read_file",
  "file_system.write_file": "write_file",
  "file_system.edit": "edit",
  "skill.read": "skill",
  "process.output": "process_output",
  "process.list": "process_list",
  "process.stop": "process_stop",
  "agents.list_configs": "agents_list_configs",
  "agents.list": "agents_list",
  "agents.spawn": "agents_spawn",
  "agents.send_message": "agents_send_message",
  "agents.interrupt": "agents_interrupt",
};

function deny(reason: string): HookResult {
  return { stdout: `${JSON.stringify({ decision: "deny", reason: `derm: ${oneLine(reason)}` })}\n`, stderr: "", exitCode: 0 };
}

function allow(_reason: string, updatedInput?: unknown): HookResult {
  if (updatedInput === undefined) return NONE;
  return { stdout: `${JSON.stringify({ hook_specific_output: { tool_input: updatedInput } })}\n`, stderr: "", exitCode: 0 };
}

/** The name the core matches, and whether its server split is in doubt. */
export function vibeName(raw: string): { tool: string; ambiguous?: string } {
  if (raw.startsWith("mcp_")) {
    const dots = raw.split(".").length - 1;
    const dot = raw.indexOf(".");
    if (dots === 1 && dot > 4 && dot < raw.length - 1) return { tool: `mcp__${raw.slice(4, dot)}__${raw.slice(dot + 1)}` };
    return { tool: raw.replaceAll(".", "_"), ambiguous: "ambiguous server name: Vibe's MCP name does not split at one dot" };
  }
  return { tool: VIBE_BUILTIN_NAMES[raw] ?? raw };
}

function decodeWrite(toolInput: unknown): unknown {
  // process.write may carry its text base64-encoded; the gate reads the text.
  if (!isPlainObject(toolInput) || typeof toolInput.bytesBase64 !== "string" || typeof toolInput.text === "string") return toolInput;
  return { ...toolInput, text: Buffer.from(toolInput.bytesBase64, "base64").toString("utf8") };
}

export function vibeRead(input: Record<string, unknown>, env: NodeJS.ProcessEnv): ReadCall | string {
  if (input.hook_event_name !== undefined && input.hook_event_name !== "pre_tool") return `unexpected hook event ${String(input.hook_event_name).slice(0, 40)}`;
  const raw = input.tool_name;
  if (typeof raw !== "string" || raw === "") return "hook input has no tool_name";
  const rawInput = raw === "process.write" ? decodeWrite(input.tool_input ?? {}) : (input.tool_input ?? {});
  const shell = asCoreShell(VIBE_SHELL, raw, rawInput);
  const named = shell.tool === "bash" ? { tool: "bash" } : vibeName(raw);
  const read: ReadCall = { tool: named.tool, rawTool: raw, toolInput: shell.toolInput };
  if (named.ambiguous !== undefined) read.ambiguous = named.ambiguous;
  const chat = chatFrom(env, input.session_id);
  if (chat !== undefined) read.chat = chat;
  if (typeof input.tool_call_id === "string" && input.tool_call_id !== "") read.callId = input.tool_call_id;
  return read;
}

export const mistralVibe: Dialect = {
  id: "mistral-vibe",
  name: "Mistral Vibe",
  read: vibeRead,
  ownAsk: () => false,
  allow,
  deny,
  ask: deny,
  canRewrite: true,
};
