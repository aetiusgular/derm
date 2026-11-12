// Cline CLI adapter (T2.7): derm's gate for Cline 3.0.74, in two parts that
// share this file. Read in Cline's source at tag cli-v3.0.74 (071e1b2) and run
// against Cline 3.0.74 with a fake chat-completions server; sources per claim
// in plans/parallel/tk_lane_P.md, Research.
//
// 1. The SDK plugin's `beforeTool` hook (plugin.ts), which Cline runs before
//    every tool in every mode, before its own approval policy
//    (sdk/packages/agents/src/agent-runtime.ts:2457-2500):
//    - deny is `{skip: true, reason}`: that call is skipped and the reason goes
//      back to the model; the run goes on (rules case 79). Never `stop`, which
//      ends the run.
//    - ask is `{policy: {autoApprove: false}}`: Cline then asks through its own
//      approval route whatever `--auto-approve` says (the override merges over
//      the configured policy, :2493-2496): its own prompt in the TUI, the
//      approval files in desktop mode, a deny in a run with no one to ask
//      (cases 71, 83). Run: it forced an approval under the default
//      auto-approve, which is what Orca starts Cline with.
//    - allow returns nothing, so Cline's own policy decides: derm's allow
//      never skips a prompt Cline would show (case 72).
//    - It fails open: a hook that throws or takes over 3 s is ignored and the
//      call runs under Cline's own policy (docs/sdk/plugins.mdx, "When a hook
//      fails"; the CLI sets no `hookErrorMode`). So the hook never waits on the
//      daemon: the record is sent and not awaited, and an ask is Cline's.
// 2. The approval-file responder (responder.ts), which answers the request
//    files Cline writes in desktop mode (`CLINE_TOOL_APPROVAL_MODE=desktop`,
//    `CLINE_TOOL_APPROVAL_DIR`; sdk/packages/core/src/runtime/tools/
//    tool-approval.ts:29-102). Cline waits up to 5 minutes and denies with no
//    answer, so this part fails closed. In 3.0.74 a prompt run never reaches
//    it (Look out for in the status doc), so the plugin is the gate that runs.
//
// Shell: `run_commands` with `{commands: [...]}` (a lenient union also takes
// `command` and `cmd`, sdk/packages/core/src/extensions/tools/schemas.ts:
// 149-174) is checked as `bash` on the commands, one per line (case 82). MCP
// tools are `<server>__<tool>`, sanitized and hashed past 64 characters
// (sdk/packages/core/src/extensions/mcp/name-transform.ts:20-35); the matcher
// splits them at the run of underscores.

//
// Wave 5b (lane 5bC): the policy's answer, the approver and the records are
// `derm gate serve`'s (contracts/gate-serve.md); Cline's control files are
// in derm-core's list (`CONTROL_PATHS`), so src/control.ts is no longer on
// the path. Cline turns a plugin off after five failed hook calls in a row
// and then runs every call under its own policy (docs/sdk/plugins.mdx at
// 071e1b2, "Plugin Status and Errors"), and a hook that takes over 3 s is a
// failure ("When a hook fails"). So the hook never throws and never waits
// past its budget: a co-process that is not running, or does not answer in
// time, is a skip with the reason (case 228), which Cline counts as an
// answer, not a failure. The co-process starts at the first call, within
// that call's budget, and stops with the session (`ctx.onDispose`).

import { ownedByTrusted } from "./core/owner.ts";
import { overBudget } from "./budget.ts";
import { approve, decide as serveDecide, event, record, ServeUnavailable, sharedServe, unavailable, type Answer, type Call, type GateServe } from "./serve/client.ts";

export const HARNESS = "cline";

/** Cline's shell tool, checked as `bash`. The preset row's `coverage.shellAliases`; a test holds the two equal. */
export const CLINE_SHELL_TOOLS = ["run_commands"] as const;


/** What a hook may spend before Cline's 3 s: start (once) and one answer. */
export const START_MS = 1200;
export const ANSWER_MS = 1200;

export type Deps = {
  env: NodeJS.ProcessEnv;
  /** The session folder for the policy's and the token's folder checks. */
  cwd: () => string;
  serve: () => GateServe;
};

export function defaultDeps(env: NodeJS.ProcessEnv = process.env, cwd: () => string = () => process.cwd()): Deps {
  return { env, cwd, serve: () => sharedServe({ agent: HARNESS, env, cwd, trusted: ownedByTrusted, startMs: START_MS, requestMs: ANSWER_MS }) };
}

/** The call as derm reads it from Cline's: `bash` for Cline's shell (case 82). */
export type GateCall = { harness: string; tool: string; toolInput: unknown; chat?: string; toolUseId?: string };

function serveCall(call: GateCall): Call {
  return {
    tool: call.tool,
    input: call.toolInput,
    ...(call.chat !== undefined ? { chat: call.chat } : {}),
    ...(call.toolUseId !== undefined ? { toolUseId: call.toolUseId } : {}),
  };
}

/** `FULL_ACCESS_NOTE` (`gate::core`): under full access an ask is a deny (case 83). */
const FULL_ACCESS_NOTE = "the chat runs in full access (DERM_FULL_ACCESS=1), so derm denies what it would ask";

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function chatOf(conversationId: unknown, env: NodeJS.ProcessEnv): string | undefined {
  const fromEnv = env.DERM_CHAT_ID?.trim();
  if (fromEnv) return fromEnv;
  return typeof conversationId === "string" && conversationId !== "" ? conversationId : undefined;
}

/** Thrown for a `run_commands` input derm cannot read the way Cline will; the call is refused. */
export class Unreadable extends Error {}

type CommandEntry = string | { command: string; args: string[] };

function entryOf(v: unknown): CommandEntry | undefined {
  if (typeof v === "string") return v;
  if (!isPlainObject(v) || typeof v.command !== "string" || v.command === "") return undefined;
  for (const k of Object.keys(v)) if (k !== "command" && k !== "args") return undefined;
  if (v.args === undefined) return { command: v.command, args: [] };
  if (!Array.isArray(v.args) || !v.args.every((a) => typeof a === "string")) return undefined;
  return { command: v.command, args: v.args as string[] };
}

function entriesOf(list: unknown[]): CommandEntry[] {
  const out: CommandEntry[] = [];
  for (const v of list) {
    const e = entryOf(v);
    if (e === undefined) throw new Unreadable("run_commands holds an entry derm cannot read");
    out.push(e);
  }
  return out;
}

/**
 * The commands a `run_commands` call runs, as Cline's own normalizer reads
 * them (sdk/packages/core/src/extensions/tools/helpers.ts:137-184
 * normalizeRunCommandsInput, schemas.ts:128-176): a string; a list of
 * strings or `{command, args}` entries; `{commands}` holding either; or
 * `{command, args?}` or `{cmd}`. `commands` wins whenever it is present (lane
 * P review P-S1), so input that also carries `command` or `cmd`, or an entry
 * of any other shape, is refused rather than guessed at.
 */
export function runCommandsOf(input: unknown): CommandEntry[] {
  if (typeof input === "string") return [input];
  if (Array.isArray(input)) return entriesOf(input);
  if (!isPlainObject(input)) throw new Unreadable("run_commands input derm cannot read");
  const keys = ["commands", "command", "cmd"].filter((k) => k in input);
  if (keys.length !== 1) throw new Unreadable(keys.length === 0 ? "run_commands has no commands" : `run_commands names its commands twice (${keys.join(", ")})`);
  if ("commands" in input) return Array.isArray(input.commands) ? entriesOf(input.commands) : entriesOf([input.commands]);
  if ("command" in input) {
    const e = entryOf("args" in input ? { command: input.command, args: input.args } : input.command);
    if (e === undefined) throw new Unreadable("run_commands command derm cannot read");
    return [e];
  }
  if (typeof input.cmd !== "string") throw new Unreadable("run_commands cmd derm cannot read");
  return [input.cmd];
}

/**
 * The commands as text, one per line. An argv entry is its program and
 * arguments joined by spaces, so `git -c core.fsmonitor=x` reads as one
 * command line (P-S3; Cline shows it the same way, helpers.ts
 * formatRunCommandQuery).
 */
export function shellCommandsOf(input: unknown): string {
  const lines = runCommandsOf(input).map((e) => (typeof e === "string" ? e : [e.command, ...e.args].join(" ")));
  if (lines.length === 0) throw new Unreadable("run_commands has no commands");
  return lines.join("\n");
}

/**
 * The tool name and input the gate checks for one Cline call. The chat is
 * `DERM_CHAT_ID`, else Cline's conversation id from the plugin's snapshot;
 * the responder passes none from a request file, which the agent can write
 * (P-S5).
 */
export function gateCallOf(toolName: string, input: unknown, ids: { toolCallId?: unknown; conversationId?: unknown }, env: NodeJS.ProcessEnv): GateCall {
  const chat = chatOf(ids.conversationId, env);
  const base = {
    harness: HARNESS,
    ...(chat !== undefined ? { chat } : {}),
    ...(typeof ids.toolCallId === "string" && ids.toolCallId !== "" ? { toolUseId: ids.toolCallId } : {}),
  };
  if ((CLINE_SHELL_TOOLS as readonly string[]).includes(toolName)) {
    const command = shellCommandsOf(input);
    const rest: Record<string, unknown> = {};
    if (isPlainObject(input)) for (const [k, v] of Object.entries(input)) if (!["commands", "command", "cmd", "args"].includes(k)) rest[k] = v;
    return { ...base, tool: "bash", toolInput: { command, ...rest } };
  }
  return { ...base, tool: toolName, toolInput: input ?? {} };
}

/** Tools whose input leaves the machine as it is: a secret-like value there is rewritten; anywhere else it asks (P-S6). */
export const CLINE_SEND_OUT_TOOLS = ["fetch_web_content"] as const;

/** The policy's answer for one call (the co-process's, posted by no one yet), with Cline's rewrite rule applied. */
export async function decide(call: GateCall, rawTool: string, deps: Pick<Deps, "serve" | "env">): Promise<Answer> {
  const answer = await serveDecide(deps.serve(), serveCall(call), false);
  // Input is rewritten only for a tool that sends it out as it is: an MCP
  // server's tool or a web fetch. Anywhere else (a shell, an editor write, a
  // tool that runs code) a rewrite changes what the call does, so it asks
  // (P-S6). Matched on Cline's own name, not the normalized one.
  const sendsOut = /__/.test(rawTool) || (CLINE_SEND_OUT_TOOLS as readonly string[]).includes(rawTool);
  if (answer.updatedInput !== undefined && !sendsOut) {
    answer.updatedInput = undefined;
    if (answer.action === "allow") {
      answer.action = "ask";
      answer.reason = "secret-like value in input";
    }
  }
  if (answer.action === "ask" && deps.env.DERM_FULL_ACCESS === "1") {
    answer.action = "deny";
    answer.reason = `${answer.reason}; ${FULL_ACCESS_NOTE}`;
  }
  return answer;
}

// ------------------------------------------------------------ the SDK plugin

/** What Cline passes `beforeTool`, as plain data (docs/sdk/plugins.mdx; sdk/packages/shared/src/agent.ts:426-431). */
export type BeforeToolContext = {
  snapshot?: { conversationId?: string; runId?: string; agentId?: string };
  toolCall?: { toolCallId?: string; toolName?: string; input?: unknown };
  input?: unknown;
};

/** The subset of `AgentBeforeToolResult` derm answers with (sdk/packages/shared/src/agent.ts:433-446). */
export type BeforeToolResult = { skip: true; reason: string } | { policy: { autoApprove: false } } | { input: unknown } | undefined;

export async function beforeTool(context: BeforeToolContext, deps: Deps): Promise<BeforeToolResult> {
  let call: GateCall | undefined;
  let answer: Answer | undefined;
  let result: BeforeToolResult;
  try {
    const toolName = context?.toolCall?.toolName;
    if (typeof toolName !== "string" || toolName === "") return { skip: true, reason: "derm: tool call has no tool name" };
    const input = context.input !== undefined ? context.input : context.toolCall?.input;
    // Before the co-process sees it: Cline gives this hook 3 s (P-S2).
    const heavy = overBudget(input);
    if (heavy) return { skip: true, reason: `derm: ${heavy}` };
    call = gateCallOf(toolName, input, { toolCallId: context.toolCall?.toolCallId, conversationId: context.snapshot?.conversationId }, deps.env);
    answer = await decide(call, toolName, deps);
    if (answer.action === "deny") result = { skip: true, reason: `derm: ${answer.reason}` };
    else if (answer.action === "ask") result = { policy: { autoApprove: false } };
    else if (answer.updatedInput !== undefined) result = { input: answer.updatedInput };
    else result = undefined;
  } catch (error) {
    result = {
      skip: true,
      reason:
        error instanceof Unreadable
          ? `derm: ${error.message}`
          : error instanceof ServeUnavailable
            ? `derm: ${unavailable(error)}`
            : `derm: hook error: ${(error as Error)?.message ?? String(error)}`,
    };
  }
  if (call && answer) {
    const decision = result === undefined || (result !== undefined && "input" in result) ? "allow" : "skip" in result ? "deny" : "ask";
    // Not awaited: Cline gives a hook 3 s and ignores it after that, so the
    // record must never hold the answer. An ask goes on to Cline's approval,
    // which the approval-file responder answers and records with its
    // installs; so the plugin records them only for a call it decided.
    void record(deps.serve(), serveCall(call), answer, decision, {
      label: decision === "ask" ? "ask (Cline's approval)" : decision,
      via: "plugin",
      reason: answer.reason,
      ...(decision === "ask" ? { installs: false } : {}),
      wait: false,
    });
  }
  return result;
}

// ------------------------------------------------- the approval-file answer

/** A request file's content (tool-approval.ts:54-72). */
export type ApprovalRequest = {
  requestId?: unknown;
  sessionId?: unknown;
  toolCallId?: unknown;
  toolName?: unknown;
  input?: unknown;
  conversationId?: unknown;
};

/** The decision file's content (tool-approval.ts:79-87): only `approved: true` runs the call. */
export type ApprovalAnswer = { approved: boolean; reason?: string };

/**
 * derm's answer to one request Cline wrote. Unlike the plugin it can wait: an
 * ask goes to the derm daemon's approver, and anything but an approver's yes
 * within the ask timeout is a deny (Cline's own prompt is not reachable from
 * here).
 */
export async function answerRequest(request: ApprovalRequest, deps: Deps): Promise<ApprovalAnswer> {
  let call: GateCall | undefined;
  let answer: Answer | undefined;
  let out: ApprovalAnswer;
  try {
    if (!isPlainObject(request) || typeof request.toolName !== "string" || request.toolName === "") {
      out = { approved: false, reason: "derm: approval request has no tool name" };
    } else {
      const heavy = overBudget(request.input);
      if (heavy) return { approved: false, reason: `derm: ${heavy}` };
      // No chat from the file: the agent can write it (P-S5).
      call = gateCallOf(request.toolName, request.input, { toolCallId: request.toolCallId }, deps.env);
      answer = await decide(call, request.toolName, deps);
      if (answer.action === "allow" && answer.updatedInput !== undefined) {
        // An approval file cannot rewrite the input: ask instead.
        answer.action = "ask";
        answer.reason = `${answer.reason} (derm cannot redact it here)`;
      }
      if (answer.action === "allow") out = { approved: true };
      else if (answer.action === "deny") out = { approved: false, reason: `derm: ${answer.reason}` };
      else {
        const r = await approve(deps.serve(), serveCall(call), answer, false, false);
        out = r.kind === "allow" ? { approved: true } : { approved: false, reason: `derm: ${r.reason}` };
      }
    }
  } catch (error) {
    out = {
      approved: false,
      reason:
        error instanceof Unreadable
          ? `derm: ${error.message}`
          : error instanceof ServeUnavailable
            ? `derm: ${unavailable(error)}`
            : `derm: responder error: ${(error as Error)?.message ?? String(error)}`,
    };
  }
  if (call && answer) {
    await record(deps.serve(), serveCall(call), answer, out.approved ? "allow" : "deny", { via: "approval-file", reason: out.reason ?? answer.reason });
  }
  return out;
}
