// Google Antigravity CLI (`agy`), read 3 Nov 2026 in antigravity.google/
// docs/hooks (no version stamp) and CHANGELOG.md of google-antigravity/
// antigravity-cli at 1.4.12. Not run: no seat in the cloud (call 8), so
// this dialect is fixtures only and its row says "unverified". Sources and
// marks: plans/parallel/tk_lane_N.md, Research.
// - Registered as one named hook, "derm", in ~/.gemini/config/hooks.json, a
//   map of named hooks shared with the app: {"derm": {"PreToolUse":
//   [{"matcher": "*", "hooks": [{"type": "command", "command", "timeout"}]}]}}.
//   derm merges its own name and never touches the others (case 75).
// - Stdin (camelCase): {toolCall: {name, args}, stepIdx, conversationId,
//   workspacePaths, transcriptPath, artifactDirectoryPath, modelName,
//   lastUserInput (1.4.7)}. No call id and no event name.
// - Stdout: {"decision", "reason"}; decision is required: allow, deny,
//   ask (prompts, but a remembered "Always Allow" skips it), force_ask
//   (always prompts), deny_unless_prior_grant. derm's ask is force_ask, so
//   an earlier grant cannot answer derm's question.
// - Exit codes are not documented: every reply, deny included, is the JSON
//   on exit 0. A failed or timed-out PreToolUse hook is reported to block
//   (third parties only, I); not run.
// - No input rewrite documented: a redacted input is a deny.
// - Names: shell `run_command` (args.CommandLine, Cwd), and
//   `manage_task` with Action "send_input" types into a background task
//   (args.Input), so both are `bash` (case 82). How an MCP tool is named
//   was not found in the vendor's docs: one third party says every MCP call
//   goes through `call_mcp_tool`; the gate reads a server and a tool from
//   its args when both are there, and asks on an allow otherwise.

import { chatFrom, isPlainObject, oneLine, type Dialect, type HookResult, type ReadCall } from "../runner.ts";
import { asCoreShell, type ShellForm } from "../shell.ts";

export const ANTIGRAVITY_SHELL: ShellForm = { names: ["run_command", "manage_task"], commandFields: ["CommandLine", "Input"] };

const out = (decision: string, reason: string): HookResult => ({ stdout: `${JSON.stringify({ decision, reason: `derm: ${oneLine(reason)}` })}\n`, stderr: "", exitCode: 0 });

const MCP_DISPATCHER = "call_mcp_tool";

function str(o: Record<string, unknown>, keys: readonly string[]): string | undefined {
  for (const k of keys) {
    const v = o[k];
    if (typeof v === "string" && v !== "") return v;
  }
  return undefined;
}

export function antigravityRead(input: Record<string, unknown>, env: NodeJS.ProcessEnv): ReadCall | string {
  const call = input.toolCall;
  if (!isPlainObject(call)) return "hook input has no toolCall";
  const raw = call.name;
  if (typeof raw !== "string" || raw === "") return "hook input has no toolCall.name";
  const args = call.args ?? {};
  let read: ReadCall;
  if (raw === "manage_task" && !(isPlainObject(args) && args.Action === "send_input")) {
    // Listing, killing or reading a task runs nothing new.
    read = { tool: raw, rawTool: raw, toolInput: args };
  } else if (raw === MCP_DISPATCHER) {
    const a = isPlainObject(args) ? args : {};
    const server = str(a, ["ServerName", "serverName", "server_name", "Server", "server"]);
    const tool = str(a, ["ToolName", "toolName", "tool_name", "Tool", "tool", "Name", "name"]);
    const inner = a.Arguments ?? a.arguments ?? a.Args ?? a.args ?? a;
    read =
      server !== undefined && tool !== undefined
        ? { tool: `mcp__${server}__${tool}`, rawTool: raw, toolInput: inner }
        : { tool: raw, rawTool: raw, toolInput: args, ambiguous: "Antigravity's MCP call names no server derm can read" };
  } else {
    const shell = asCoreShell(ANTIGRAVITY_SHELL, raw, args);
    read = { tool: shell.tool, rawTool: raw, toolInput: shell.toolInput };
  }
  const chat = chatFrom(env, input.conversationId);
  if (chat !== undefined) read.chat = chat;
  if (typeof input.conversationId === "string" && typeof input.stepIdx === "number") read.callId = `${input.conversationId}-${input.stepIdx}`;
  return read;
}

export const antigravity: Dialect = {
  id: "antigravity",
  name: "Antigravity",
  read: antigravityRead,
  ownAsk: () => true,
  allow: (reason) => out("allow", reason),
  deny: (reason) => out("deny", reason),
  ask: (reason) => out("force_ask", reason),
  canRewrite: false,
};
