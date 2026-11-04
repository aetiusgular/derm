// Kiro CLI (`kiro-cli`), read 3 Nov 2026 in kiro.dev/docs/hooks/ (CLI V3,
// the default harness since 3 Nov), /hooks/actions (updated 10 Oct 2026),
// /hooks/types and /tools. Not run: headless Kiro needs KIRO_API_KEY, a
// paid tier (call 8), so this dialect is fixtures only and its row says
// "unverified". Sources and marks: plans/parallel/tk_lane_N.md, Research.
// - Registered as a standalone file ~/.kiro/hooks/derm.json (CLI V3 loads
//   global hooks from there): {"version": "v1", "hooks": [{name, trigger:
//   "PreToolUse", action: {type: "command", command}, timeout}]}; no
//   matcher, which matches every tool.
// - Stdin: {hook_event_name: "PreToolUse", cwd, session_id, tool_name,
//   tool_input}. No call id.
// - Exit 0 allows, and its stdout goes into the agent's context (case 77):
//   derm prints nothing on allow. Any other exit blocks the call and sends
//   stderr to the agent; derm denies with exit 2 and the reason on stderr.
//   (The June CLI page said other exits warn and allow; the October page,
//   for V3, says they block. Exit 2 blocks on both.)
// - No ask and no input rewrite from a PreToolUse command hook: an ask goes
//   to derm's approver or is denied.
// - Names: shell `execute_bash` (`execute_pwsh` on Windows); MCP tools
//   `mcp_<server>_<tool>` with single underscores, split with the server
//   names Kiro is configured with (src/kiroServers.ts, src/mcpSplit.ts).

import { NONE, chatFrom, oneLine, type Dialect, type HookResult, type ReadCall } from "../runner.ts";
import { asCoreShell, type ShellForm } from "../shell.ts";
import { kiroServerNames } from "../kiroServers.ts";
import { splitSingleUnderscore, type ServerNames } from "../mcpSplit.ts";

export const KIRO_SHELL: ShellForm = { names: ["execute_bash", "execute_pwsh"], commandFields: ["command"] };

function deny(reason: string): HookResult {
  return { stdout: "", stderr: `derm: ${oneLine(reason)}\n`, exitCode: 2 };
}

export function kiroReadWith(serverNames: (input: Record<string, unknown>, env: NodeJS.ProcessEnv) => ServerNames) {
  return (input: Record<string, unknown>, env: NodeJS.ProcessEnv): ReadCall | string => {
    const ev = input.hook_event_name;
    if (ev !== undefined && ev !== "PreToolUse" && ev !== "preToolUse") return `unexpected hook event ${String(ev).slice(0, 40)}`;
    const raw = input.tool_name;
    if (typeof raw !== "string" || raw === "") return "hook input has no tool_name";
    const named = raw.startsWith("mcp_") ? splitSingleUnderscore(raw, serverNames(input, env), "Kiro") : { tool: raw };
    const { tool, toolInput } = asCoreShell(KIRO_SHELL, named.tool, input.tool_input ?? {});
    const read: ReadCall = { tool, rawTool: raw, toolInput };
    if (named.ambiguous !== undefined) read.ambiguous = named.ambiguous;
    const chat = chatFrom(env, input.session_id);
    if (chat !== undefined) read.chat = chat;
    return read;
  };
}

export const kiro: Dialect = {
  id: "kiro",
  name: "Kiro",
  read: kiroReadWith((input, env) => kiroServerNames(env, typeof input.cwd === "string" ? input.cwd : undefined)),
  ownAsk: () => false,
  // Nothing on stdout: on exit 0 it would reach the model.
  allow: () => NONE,
  deny,
  ask: deny,
  canRewrite: false,
};
