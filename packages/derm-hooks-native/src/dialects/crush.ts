// Crush (charmbracelet/crush), read and run at v0.99.0 (plans/parallel/
// tk_lane_N.md, Research; contracts/fixtures/hook-dialects/crush/ for
// 0.98.2, whose hook contract 0.99.0 widened):
// - Registered as a flat entry in `hooks.PreToolUse` of
//   ~/.config/crush/crush.json ({name, matcher, command, timeout}; not
//   Claude's nested `hooks`), with an absolute command.
// - Stdin: {event, hook_event_name (0.99.0), session_id, cwd, tool_name,
//   tool_input, tool_use_id (0.99.0)}. No server field.
// - Allow: {"decision": "allow"} on exit 0 pre-approves (Crush skips its own
//   prompt), so derm says it only for a rule's allow (case 72).
// - Deny: exit 2 with the reason on stderr (stdout is ignored then).
// - `ask` and anything but allow or deny read as no opinion, and exit 49 or
//   `halt: true` end the turn (case 79): never used.
// - Fails open, with no switch: a timeout, a crash, another exit or bad JSON
//   are no opinion. The gate stays fast.
// - Input rewrite: `updated_input`, a shallow merge over the input; derm
//   sends every top-level key, so it replaces the whole input.
// - Names: shell `bash`; MCP `mcp_<server>_<tool>` with single underscores,
//   where a server name may hold `_` itself. The split is taken from the MCP
//   server names Crush is configured with (src/crushServers.ts); a name
//   that more than one of them, or none, could start is ambiguous and an
//   allow asks.
// - Sub-agents' calls fire no hook, only the outer call (V); hooks wrap every
//   top-level tool whatever the mode, --yolo and `crush run` included.
// - Several hooks on one event run in parallel and combine in config order,
//   a deny beating an allow (internal/hooks/hooks.go:99-168), so another
//   tool's hook beside derm's cannot undo derm's deny (case 75).

import { chatFrom, oneLine, type Dialect, type HookResult, type ReadCall } from "../runner.ts";
import { asCoreShell, type ShellForm } from "../shell.ts";
import { crushServerNames } from "../crushServers.ts";
import { splitSingleUnderscore, type ServerNames } from "../mcpSplit.ts";

export const CRUSH_SHELL: ShellForm = { names: [], commandFields: ["command"] };

function deny(reason: string): HookResult {
  return { stdout: "", stderr: `derm: ${oneLine(reason)}\n`, exitCode: 2 };
}

function allow(reason: string, updatedInput?: unknown): HookResult {
  const out: Record<string, unknown> = { version: 1, decision: "allow", reason: `derm: ${oneLine(reason)}` };
  if (updatedInput !== undefined) out.updated_input = updatedInput;
  return { stdout: `${JSON.stringify(out)}\n`, stderr: "", exitCode: 0 };
}

/** Crush's `mcp_<server>_<tool>` to the core's form (src/mcpSplit.ts). */
export function crushMcpName(raw: string, names: ServerNames): { tool: string; ambiguous?: string } {
  return splitSingleUnderscore(raw, names, "Crush");
}

export function crushReadWith(serverNames: (input: Record<string, unknown>, env: NodeJS.ProcessEnv) => ServerNames) {
  return (input: Record<string, unknown>, env: NodeJS.ProcessEnv): ReadCall | string => {
    const ev = input.hook_event_name ?? input.event;
    if (ev !== undefined && ev !== "PreToolUse") return `unexpected hook event ${String(ev).slice(0, 40)}`;
    const raw = input.tool_name;
    if (typeof raw !== "string" || raw === "") return "hook input has no tool_name";
    const named = raw.startsWith("mcp_") ? crushMcpName(raw, serverNames(input, env)) : { tool: raw };
    const { tool, toolInput } = asCoreShell(CRUSH_SHELL, named.tool, input.tool_input ?? {});
    const read: ReadCall = { tool, rawTool: raw, toolInput };
    if (named.ambiguous !== undefined) read.ambiguous = named.ambiguous;
    const chat = chatFrom(env, input.session_id);
    if (chat !== undefined) read.chat = chat;
    if (typeof input.tool_use_id === "string" && input.tool_use_id !== "") read.callId = input.tool_use_id;
    return read;
  };
}

export const crush: Dialect = {
  id: "crush",
  name: "Crush",
  read: crushReadWith((input, env) => crushServerNames(env, typeof input.cwd === "string" ? input.cwd : undefined)),
  ownAsk: () => false,
  allow,
  deny,
  ask: deny,
  canRewrite: true,
};
