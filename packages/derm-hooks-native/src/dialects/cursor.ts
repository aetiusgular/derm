// Cursor CLI (`agent`), read 3 Nov 2026 in cursor.com/docs/agent/hooks (no
// version stamp; the CLI's changelog tops at v2026.10.22). Not run: the CLI
// needs an account (call 8), so this dialect is fixtures only and its row
// says "unverified". Sources and marks: plans/parallel/tk_lane_N.md,
// Research.
// - Registered in ~/.cursor/hooks.json, `{"version": 1, "hooks": {<event>:
//   [{command, timeout, failClosed: true}]}}`, on two events:
//   preToolUse (every tool: Shell, Read, Write, Grep, Delete, Task and
//   `MCP:<tool>`) and beforeMCPExecution (MCP calls, with the server).
// - preToolUse in: {tool_name, tool_input, tool_use_id, cwd, ...} plus the
//   common fields (conversation_id, hook_event_name, workspace_roots, ...).
//   Out: {permission: "allow" | "deny", user_message, agent_message,
//   updated_input}. "ask" is accepted by its schema and not enforced, so
//   derm never sends it there: an ask goes to derm's approver or is denied.
// - preToolUse names an MCP tool `MCP:<tool>` with no server (case 73), so
//   it denies what the policy denies outright and leaves the rest to
//   beforeMCPExecution, which carries `mcp_server_name` and takes allow,
//   deny and ask (Cursor's own prompt).
// - beforeMCPExecution in: {tool_name, tool_input (a JSON string),
//   mcp_server_name, url | command}. No updated_input there. A missing
//   server name denies, as the docs advise.
// - Exit 2 blocks; any other non-zero exit, a crash, a timeout or no
//   output fails open unless `failClosed: true`, which derm sets. Invalid
//   JSON from a permission hook blocks even without it.
// - Several sources: deny beats ask beats allow, whatever the source, so
//   Orca's or a team's hook beside derm's cannot turn derm's deny into an
//   allow (case 75).

import { chatFrom, oneLine, type Dialect, type HookResult, type ReadCall } from "../runner.ts";
import { asCoreShell, type ShellForm } from "../shell.ts";

export const CURSOR_SHELL: ShellForm = { names: ["Shell"], commandFields: ["command"] };

const out = (o: Record<string, unknown>): HookResult => ({ stdout: `${JSON.stringify(o)}\n`, stderr: "", exitCode: 0 });

function deny(reason: string): HookResult {
  const text = `derm: ${oneLine(reason)}`;
  return out({ permission: "deny", user_message: text, agent_message: text });
}

function allow(_reason: string, updatedInput?: unknown): HookResult {
  return out(updatedInput === undefined ? { permission: "allow" } : { permission: "allow", updated_input: updatedInput });
}

function ask(reason: string): HookResult {
  const text = `derm: ${oneLine(reason)}`;
  return out({ permission: "ask", user_message: text, agent_message: text });
}

function event(input: Record<string, unknown>): string {
  return typeof input.hook_event_name === "string" ? input.hook_event_name : "";
}

export function cursorRead(input: Record<string, unknown>, env: NodeJS.ProcessEnv): ReadCall | string {
  const ev = event(input);
  const chat = chatFrom(env, input.conversation_id);
  const base = (r: ReadCall): ReadCall => {
    if (chat !== undefined) r.chat = chat;
    if (typeof input.tool_use_id === "string" && input.tool_use_id !== "") r.callId = input.tool_use_id;
    else if (typeof input.generation_id === "string" && input.generation_id !== "") r.callId = input.generation_id;
    return r;
  };
  if (ev === "beforeMCPExecution") {
    const server = input.mcp_server_name;
    const tool = input.tool_name;
    if (typeof server !== "string" || server === "") return "Cursor gave no MCP server name";
    if (typeof tool !== "string" || tool === "") return "hook input has no tool_name";
    let toolInput: unknown = input.tool_input ?? {};
    if (typeof toolInput === "string") {
      try {
        toolInput = JSON.parse(toolInput);
      } catch {
        // Not JSON: the gate reads the text as it is.
      }
    }
    return base({ tool: `mcp__${server}__${tool}`, rawTool: `${server}/${tool}`, toolInput });
  }
  if (ev !== "preToolUse") return `unexpected hook event ${ev.slice(0, 40) || "(none)"}`;
  const raw = input.tool_name;
  if (typeof raw !== "string" || raw === "") return "hook input has no tool_name";
  if (raw.startsWith("MCP:")) {
    const bare = raw.slice(4);
    if (bare === "") return "hook input names an MCP tool with no name";
    return base({ tool: bare, rawTool: raw, toolInput: input.tool_input ?? {}, deferUnlessDeny: "MCP call: decided in beforeMCPExecution, which names the server" });
  }
  const { tool, toolInput } = asCoreShell(CURSOR_SHELL, raw, input.tool_input ?? {});
  return base({ tool, rawTool: raw, toolInput });
}

export const cursor: Dialect = {
  id: "cursor",
  name: "Cursor",
  read: cursorRead,
  // Only beforeMCPExecution enforces an ask.
  ownAsk: (input) => event(input) === "beforeMCPExecution",
  allow,
  deny,
  ask,
  // updated_input exists on preToolUse only; MCP calls are decided where
  // it does not, so a redacted MCP input is a deny there (runner.decide).
  canRewrite: false,
};

