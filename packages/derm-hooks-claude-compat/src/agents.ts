// The eight dialects. Each entry is the agent's row of contracts/hook-dialects.md
// section 2a, re-read on 3 Nov 2026 at the version in `verifiedAt` (sources per
// claim in plans/parallel/tk_lane_L.md, Research). A field here that is not in
// the row is marked in its comment.

import { claudeShape, exit2, isPlainObject, jsonOut, NONE, oneLine, str, type Dialect, type ReadCall } from "./dialect.ts";

/**
 * Shell tools under other names (case 82): mapped to `bash` before the core
 * sees them, so a `bash` rule and case 30's shell checks apply. Each list
 * equals its preset file's `coverage.shellAliases` (test). Read in each
 * agent's bundle at its `verifiedAt` (status doc, Research): OpenClaude's
 * PowerShell and Monitor (POWERSHELL_TOOL_NAME, MONITOR_TOOL_NAME, Monitor runs
 * its `command` through the shell); Qwen's monitor (ToolNames.MONITOR, a
 * `command`); Command Code's powershell and monitor_command (`command` and
 * `args`); Kimi's PowerShell; Auggie's write-process; Copilot's powershell,
 * write_bash and write_powershell; Grok's Shell (its Cursor preset's name for
 * run_terminal_command, hooks doc 1.0.71).
 */
export const SHELL_ALIASES: Readonly<Record<string, readonly string[]>> = {
  openclaude: ["powershell", "monitor"],
  "qwen-code": ["run_shell_command", "monitor"],
  droid: ["execute"],
  "command-code": ["shell_command", "powershell", "monitor_command"],
  kimi: ["powershell"],
  auggie: ["launch-process", "write-process"],
  "copilot-cli": ["powershell", "write_bash", "write_powershell"],
  grok: ["run_terminal_command", "shell"],
};

type ShellText = (input: Record<string, unknown>) => string | undefined;
const field =
  (key: string): ShellText =>
  (i) =>
    typeof i[key] === "string" ? i[key] : undefined;
/** A program and its arguments as one line, for the shell checks only. */
const commandAndArgs: ShellText = (i) => {
  const args = i.args ?? [];
  if (typeof i.command !== "string" || !Array.isArray(args) || !args.every((a) => typeof a === "string")) return undefined;
  return [i.command, ...args].join(" ");
};

/**
 * Shell tools whose text is not in a `command` field: the text a call writes
 * to a shell another call started (Auggie's write-process `input_text`,
 * "Text to write to the process's stdin", augment.mjs 0.36.0; Copilot's
 * write_bash and write_powershell `{shellId, input}`, cli-main.js 1.0.105
 * schema A3e, subtype "write_shell"), or a program with its arguments apart
 * (Command Code's monitor_command `{command, args}`, dist/cli.mjs 1.88.2).
 * The core sees `{command: <that text>}`, so the shell checks and the reject
 * list read it (L-S2); that input is rebuilt, so no rewrite of it is ever
 * sent back (`inputMapped`).
 */
const SHELL_TEXT: Readonly<Record<string, Readonly<Record<string, ShellText>>>> = {
  auggie: { "write-process": field("input_text") },
  "copilot-cli": { write_bash: field("input"), write_powershell: field("input") },
  "command-code": { monitor_command: commandAndArgs },
};

/** The core's tool name and input for a call the agent named `raw`. */
function shellRead(id: string, raw: string, toolInput: unknown): Pick<ReadCall, "tool" | "toolInput" | "inputMapped" | "unresolved"> {
  const lowered = raw.trim().toLowerCase();
  if (!(SHELL_ALIASES[id] ?? []).includes(lowered)) return { tool: raw, toolInput };
  const text = SHELL_TEXT[id]?.[lowered];
  if (!text) return { tool: "bash", toolInput };
  const t = isPlainObject(toolInput) ? text(toolInput) : undefined;
  if (t === undefined) return { tool: "bash", toolInput, unresolved: `derm could not read the shell text of ${oneLine(raw, 64)}` };
  return { tool: "bash", toolInput: { command: t }, inputMapped: true };
}

/** Two reasons a call cannot be allowed as it is, as one. */
function joinUnresolved(a?: string, b?: string): string | undefined {
  return a && b ? `${a}; ${b}` : (a ?? b);
}

/** The common read for agents whose input is Claude Code's: tool_name, tool_input, tool_use_id, session_id, permission_mode. */
function readClaudeLike(id: string, input: Record<string, unknown>, extra: { callKeys?: string[]; sessionKeys?: string[]; modeKeys?: string[] } = {}): ReadCall | { error: string } {
  const rawTool = str(input, "tool_name");
  if (!rawTool) return { error: "hook input has no tool_name" };
  const callId = str(input, ...(extra.callKeys ?? ["tool_use_id"]));
  const session = str(input, ...(extra.sessionKeys ?? ["session_id"]));
  const mode = str(input, ...(extra.modeKeys ?? ["permission_mode"]));
  return {
    ...shellRead(id, rawTool, input.tool_input ?? {}),
    rawTool,
    ...(callId ? { callId } : {}),
    ...(session ? { session } : {}),
    ...(mode ? { mode } : {}),
  };
}

const claudeReplies = {
  allow: (reason: string, updatedInput?: Record<string, unknown>) => jsonOut(claudeShape("allow", reason, updatedInput)),
  deny: (reason: string) => exit2(reason, claudeShape("deny", reason)),
  ask: (reason: string) => jsonOut(claudeShape("ask", reason)),
};

/** Modes where the agent may not show the prompt an ask requests, or runs the call anyway: fail safe to the approver or deny (cases 71, 83). */
const NO_PROMPT_MODES = new Set(["bypasspermissions", "dontask", "yolo", "auto", "autopilot", "full", "full-access", "fullaccess", "allow-all", "allowall", "off", "acceptall"]);

function modeShowsPrompt(call: ReadCall): boolean {
  if (call.mode === undefined) return true;
  return !NO_PROMPT_MODES.has(call.mode.trim().toLowerCase().replace(/[\s_]/g, ""));
}

export const DIALECTS: Readonly<Record<string, Dialect>> = {
  openclaude: {
    id: "openclaude",
    name: "OpenClaude",
    verifiedAt: "0.34.0",
    events: ["PreToolUse"],
    read: (input) => readClaudeLike("openclaude", input),
    reply: claudeReplies,
    ownAskIn: modeShowsPrompt,
    canRewrite: true,
  },
  "qwen-code": {
    id: "qwen-code",
    name: "Qwen Code",
    verifiedAt: "0.26.6",
    events: ["PreToolUse"],
    read: (input) => readClaudeLike("qwen-code", input, { callKeys: ["tool_use_id", "tool_call_id"] }),
    reply: claudeReplies,
    ownAskIn: modeShowsPrompt,
    canRewrite: true,
  },
  droid: {
    id: "droid",
    name: "Droid",
    verifiedAt: "1.3.0",
    events: ["PreToolUse"],
    read: (input) => readClaudeLike("droid", input),
    // Droid's ask only logs and falls through to its own permission flow: no ask here.
    reply: { allow: claudeReplies.allow, deny: claudeReplies.deny },
    ownAskIn: () => false,
    canRewrite: true,
  },
  "command-code": {
    id: "command-code",
    name: "Command Code",
    verifiedAt: "1.88.2",
    events: ["PreToolUse"],
    read: (input) => readClaudeLike("command-code", input),
    reply: {
      allow: (reason) => jsonOut(claudeShape("allow", reason)),
      deny: claudeReplies.deny,
    },
    ownAskIn: () => false,
    canRewrite: false,
  },
  kimi: {
    id: "kimi",
    name: "Kimi Code",
    verifiedAt: "2.4.1",
    events: ["PreToolUse"],
    read: (input) => readClaudeLike("kimi", input, { callKeys: ["tool_call_id", "tool_use_id"] }),
    // Kimi reads only deny; an allow is no effect, so it prints nothing.
    reply: { allow: () => NONE, deny: (reason) => exit2(reason, { hookSpecificOutput: { permissionDecision: "deny", permissionDecisionReason: `derm: ${oneLine(reason)}` } }) },
    ownAskIn: () => false,
    canRewrite: false,
  },
  auggie: {
    id: "auggie",
    name: "Auggie",
    verifiedAt: "0.36.0",
    events: ["PreToolUse"],
    read: (input) => {
      const r = readClaudeLike("auggie", input, { sessionKeys: ["conversation_id"] });
      if ("error" in r) return r;
      if (input.is_mcp_tool === true) {
        // Auggie names an MCP tool `<tool>_<server>`, which the core cannot
        // split (it reads `<server>_<tool>`); the server is known only from
        // mcp_metadata, sent when the matcher has `includeMCPMetadata`:
        // {mcpDecision, mcpExecutedToolName, mcpExecutedToolServerName, ...}
        // (augment.mjs 0.36.0, c7n, from the tool definition's
        // mcp_tool_name and mcp_server_name).
        const meta = isPlainObject(input.mcp_metadata) ? input.mcp_metadata : undefined;
        const server = meta ? str(meta, "mcpExecutedToolServerName") : undefined;
        const tool = meta ? str(meta, "mcpExecutedToolName") : undefined;
        if (server && tool) return { ...r, tool: `mcp__${server}__${tool}` };
        return { ...r, unresolved: "Auggie did not name the MCP server" };
      }
      return r;
    },
    reply: {
      allow: (reason, updatedInput) => jsonOut(claudeShape("allow", reason, updatedInput)),
      deny: claudeReplies.deny,
    },
    ownAskIn: () => false,
    canRewrite: true,
  },
  "copilot-cli": {
    id: "copilot-cli",
    name: "Copilot CLI",
    verifiedAt: "1.0.105",
    events: ["preToolUse", "PreToolUse"],
    read: (input) => {
      // camelCase preToolUse: toolName, toolArgs (an object or a JSON string),
      // sessionId; the PascalCase variant is Claude Code's shape.
      if (typeof input.toolName === "string") {
        const rawTool = input.toolName;
        let toolInput: unknown = input.toolArgs ?? {};
        if (typeof toolInput === "string") {
          try {
            toolInput = JSON.parse(toolInput);
          } catch {
            // Kept as the string: the core reads a string input as it is.
          }
        }
        const session = str(input, "sessionId");
        return { ...shellRead("copilot-cli", rawTool, toolInput), rawTool, ...(session ? { session } : {}) };
      }
      return readClaudeLike("copilot-cli", input);
    },
    reply: {
      allow: (reason, updatedInput) => jsonOut({ permissionDecision: "allow", permissionDecisionReason: `derm: ${reason}`, ...(updatedInput ? { modifiedArgs: updatedInput } : {}) }),
      deny: (reason) => exit2(reason, { permissionDecision: "deny", permissionDecisionReason: `derm: ${reason}` }),
      ask: (reason) => jsonOut({ permissionDecision: "ask", permissionDecisionReason: `derm: ${reason}` }),
    },
    ownAskIn: modeShowsPrompt,
    canRewrite: true,
  },
  grok: {
    id: "grok",
    name: "Grok Build",
    verifiedAt: "1.0.71",
    events: ["PreToolUse", "pre_tool_use"],
    read: (input) => {
      const rawTool = str(input, "toolName", "tool_name");
      if (!rawTool) return { error: "hook input has no toolName" };
      const callId = str(input, "toolUseId", "tool_use_id");
      const session = str(input, "sessionId", "session_id");
      const mode = str(input, "permissionMode", "permission_mode");
      const shell = shellRead("grok", rawTool, input.toolInput ?? input.tool_input ?? {});
      // An MCP call comes as the bare `<server>__<tool>` (hooks doc 1.0.71:
      // "MCP calls ... appear as the qualified `server__tool` name"; the
      // fixture's github__search_repositories). Given the core's `mcp__`
      // prefix, a server name that itself holds `__` gets the core's split
      // checks instead of reading as its first part (L-S5). No built-in Grok
      // tool name holds `__`.
      const tool = shell.tool === rawTool && rawTool.includes("__") && !/^mcp_/i.test(rawTool) ? `mcp__${rawTool}` : shell.tool;
      // Over 128 KiB Grok cuts each long string to its start and sets
      // toolInputTruncated; "a guard that checks a string's text should deny
      // unless toolInputTruncated is false" (hooks doc 1.0.70 to 1.0.74). The
      // reject list, the control paths and the shell checks would see only
      // the start, so such a call is never allowed as it is (L-S3): it asks,
      // and the person (or the approver) decides on Grok's whole input.
      const cut = input.toolInputTruncated === false ? undefined : "Grok cut the input's long strings (toolInputTruncated), so derm saw only their start";
      const unresolved = joinUnresolved(shell.unresolved, cut);
      return {
        ...shell,
        tool,
        rawTool,
        ...(unresolved ? { unresolved } : {}),
        ...(callId ? { callId } : {}),
        ...(session ? { session } : {}),
        ...(mode ? { mode } : {}),
      };
    },
    reply: {
      allow: (reason, updatedInput) => jsonOut({ decision: "allow", reason: `derm: ${reason}`, ...(updatedInput ? { hookSpecificOutput: { hookEventName: "PreToolUse", updatedInput } } : {}) }),
      deny: (reason) => exit2(reason, { decision: "deny", reason: `derm: ${reason}` }),
      ask: (reason) => jsonOut({ decision: "ask", reason: `derm: ${reason}` }),
    },
    ownAskIn: modeShowsPrompt,
    canRewrite: true,
  },
};
