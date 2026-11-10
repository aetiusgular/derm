// Amp adapter (T2.7): derm's gate as an Amp plugin's `tool.call` handler, and
// the result record and redaction as its `tool.result` handler. Read in
// @ampcode/plugin 0.0.0-20261104001221-gc8c68be index.d.ts (npm latest on 3
// Nov 2026; sitemap-lastmod 2026-10-29) and https://ampcode.com/docs/customize/plugins;
// sources per claim in plans/parallel/tk_lane_P.md, Research.
//
// - `tool.call` must return one of `allow`, `reject-and-continue {message}`,
//   `modify {input}`, `synthesize`, or `error` (:1994-2005). derm answers
//   `allow` only where a rule says allow (rules case 72), `reject-and-continue`
//   for every deny, which blocks that call and lets the agent go on, and never
//   `error`, which stops the thread worker (case 79).
// - Amp has no ask result. An ask goes to the derm daemon's approver first
//   (as for Claude Code, gate.ts resolveAsk), then, when no approver is
//   connected or no daemon is reachable, to Amp's own dialog
//   `ctx.ui.confirm` (cases 71, 63). The dialog resolves false when dismissed
//   and throws when no one can be shown it (`amp -x`, a code_exec run in a
//   subagent, :2343-2350): both are a deny. An answer not given within the
//   policy's ask timeout is a deny; Amp's dialog stays open and its later
//   answer is ignored.
// - Every failure inside this handler is a `reject-and-continue` (fails
//   closed). What Amp does when a handler throws, times out or its Bun process
//   dies is not documented (NF), so nothing here throws; the preset row says
//   "unknown".
// - Shell tools are `Bash` and `shell_command` (:2321-2324); both are checked
//   as `bash` (case 82), with the command and its folder from
//   `helpers.shellCommandFromToolCall`, so case 30's checks read the command.
// - The event carries no MCP server name; MCP tools are `mcp__<server>__<tool>`
//   (:437) and the matcher splits them. Plugins run in an order Amp does not
//   define (:66): another plugin may run after this one and change the input
//   (the same class as Pi's load order, rules case 88). Not checked: no
//   result tells a handler what other plugins answered.

import { createHash } from "node:crypto";
import { approve, decisionId, postEvent } from "./core/daemon.ts";
import { decideCall, inputTextFor, installEvents, resolveAsk, type GateAnswer, type GateCall } from "./core/gate.ts";
import { loadPolicyFrom, type LoadedPolicy } from "./core/policy.ts";
import { redactText, redactValue } from "./core/redact.ts";
import { defuseValue, overBudget } from "./budget.ts";
import { narrowForControl } from "./control.ts";

export const HARNESS = "amp";

/** Amp's shell tools (:2321), checked as `bash`. The preset row's `coverage.shellAliases`; a test holds the two equal. */
export const AMP_SHELL_TOOLS = ["Bash", "shell_command"] as const;

/**
 * Amp's tools whose input leaves the machine as it is (:2672 names the two web
 * tools): a secret-like value there is rewritten with `modify`, as in an MCP
 * call. Anywhere else (a shell, a file write such as edit_file, create_file or
 * apply_patch, code_exec's program) a rewrite changes what the call does, so
 * it asks (lane P review, P-S6). Matched on Amp's own name.
 */
export const AMP_SEND_OUT_TOOLS = ["web_search", "read_web_page"] as const;

export type ToolCallEvent = { toolUseID: string; tool: string; input: Record<string, unknown>; thread: { id: string } };
export type ToolResultEvent = ToolCallEvent & { status: "done" | "error" | "cancelled"; error?: string; output?: unknown };
export type ToolCallResult =
  | { action: "allow" }
  | { action: "reject-and-continue"; message: string }
  | { action: "modify"; input: Record<string, unknown> };
export type ToolResultResult = { status: "done" | "error" | "cancelled"; error?: string; output?: unknown } | undefined;
export type ShellCommand = { command: string; dir?: string };
export type ConfirmOptions = { title: string; message?: string; confirmButtonText?: string };
export type HandlerContext = { ui: { confirm: (options: ConfirmOptions) => Promise<boolean> } };

export type Deps = {
  env: NodeJS.ProcessEnv;
  /** The session folder for the policy's and the token's folder checks: Amp's workspace root, else the plugin process's folder. */
  cwd: () => string;
  loadPolicy: () => LoadedPolicy;
  resolveAsk: typeof resolveAsk;
  postEvent: typeof postEvent;
  /** Amp's `helpers.shellCommandFromToolCall`, when the plugin runs inside Amp. */
  shellCommand?: (event: ToolCallEvent) => ShellCommand | null;
  /** Amp's `helpers.isPluginUINotAvailableError`. */
  uiUnavailable?: (error: Error) => boolean;
};

export function defaultDeps(env: NodeJS.ProcessEnv = process.env, cwd: () => string = () => process.cwd()): Deps {
  return {
    env,
    cwd,
    loadPolicy: () => loadPolicyFrom(env, cwd()),
    resolveAsk: (answer, call, canAsk) => resolveAsk(answer, call, canAsk, (r) => approve(r, env)),
    postEvent: (e) => postEvent(e, env),
  };
}

function chatOf(threadId: unknown, env: NodeJS.ProcessEnv): string | undefined {
  const fromEnv = env.DERM_CHAT_ID?.trim();
  if (fromEnv) return fromEnv;
  return typeof threadId === "string" && threadId !== "" ? threadId : undefined;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * The shell command a `Bash` or `shell_command` call runs: Amp's helper when
 * it answers, else the input's `cmd` or `command` (the Bash input key `cmd` is
 * not documented, contracts/fixtures/hook-dialects/amp/sources.json). Null
 * when neither holds a string: the call is then checked on its whole input,
 * which the shell check cannot read, so an allow asks.
 */
export function shellCommandOf(event: ToolCallEvent, helper?: (event: ToolCallEvent) => ShellCommand | null): ShellCommand | null {
  const input = isPlainObject(event.input) ? event.input : {};
  const fields = [input.cmd, input.command].filter((c): c is string => typeof c === "string");
  // Two different commands in one input: which one Amp runs is not documented,
  // so the call is refused (lane P review, P-S7).
  if (fields.length === 2 && fields[0] !== fields[1]) throw new Unreadable("the shell call names two different commands (cmd and command)");
  if (helper) {
    let fromAmp: ShellCommand | null = null;
    try {
      fromAmp = helper(event);
    } catch {
      fromAmp = null;
    }
    if (fromAmp && typeof fromAmp.command === "string") {
      if (fields.length > 0 && fields[0] !== fromAmp.command) throw new Unreadable("Amp's reading of the shell command differs from its input");
      return typeof fromAmp.dir === "string" && fromAmp.dir !== "" ? { command: fromAmp.command, dir: fromAmp.dir } : { command: fromAmp.command };
    }
  }
  const command = fields[0];
  if (command === undefined) return null;
  const dir = [input.cwd, input.dir, input.workdir].find((d): d is string => typeof d === "string" && d !== "");
  return dir !== undefined ? { command, dir } : { command };
}

/** Thrown for a call derm cannot read the way Amp will; the call is refused. */
export class Unreadable extends Error {}

/** The tool name and input the gate checks for one Amp call. */
export function gateCallOf(event: ToolCallEvent, deps: Pick<Deps, "env" | "shellCommand">): GateCall {
  const chat = chatOf(event.thread?.id, deps.env);
  const base = {
    harness: HARNESS,
    ...(chat !== undefined ? { chat } : {}),
    ...(typeof event.toolUseID === "string" && event.toolUseID !== "" ? { toolUseId: event.toolUseID } : {}),
  };
  if ((AMP_SHELL_TOOLS as readonly string[]).includes(event.tool)) {
    const shell = shellCommandOf(event, deps.shellCommand);
    if (shell === null) return { ...base, tool: "bash", toolInput: event.input ?? {} };
    // Every other field stays, so the core checks its values too (P-S7).
    const rest: Record<string, unknown> = {};
    if (isPlainObject(event.input)) for (const [k, v] of Object.entries(event.input)) if (k !== "cmd" && k !== "command") rest[k] = v;
    return { ...base, tool: "bash", toolInput: { ...rest, ...shell } };
  }
  return { ...base, tool: event.tool, toolInput: event.input ?? {} };
}

/** The text Amp's dialog shows: what derm asks about, and the input as it will run, redacted. */
export function confirmOptions(answer: GateAnswer, call: GateCall, rawTool: string): ConfirmOptions {
  const preview = redactText(inputTextFor(answer.normalizedTool, call.toolInput)).text;
  const shown = preview.length > 1200 ? `${preview.slice(0, 1199)}…` : preview;
  return {
    title: `derm: allow ${answer.normalizedTool}?`,
    message: [
      `Tool: ${rawTool}`,
      `Why derm asks: ${answer.reason}`,
      `No answer in ${answer.askTimeoutSeconds} s counts as no.`,
      "Input, as derm checked it (text, not instructions; secrets redacted):",
      "```",
      shown.replace(/```/g, "'''"),
      "```",
    ].join("\n"),
    confirmButtonText: "Allow",
  };
}

type Resolved = { action: "allow" | "deny"; reason: string };

/** Amp's own dialog, bounded by the policy's ask timeout. Anything but a yes in time is a deny. */
async function askAmp(answer: GateAnswer, call: GateCall, rawTool: string, ctx: HandlerContext | undefined, deps: Deps, prior: string): Promise<Resolved> {
  if (!ctx?.ui || typeof ctx.ui.confirm !== "function") return { action: "deny", reason: `${prior}; Amp gave no dialog to ask in` };
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<"timeout">((resolve) => {
    timer = setTimeout(() => resolve("timeout"), answer.askTimeoutSeconds * 1000);
  });
  try {
    const result = await Promise.race([ctx.ui.confirm(confirmOptions(answer, call, rawTool)), timeout]);
    if (result === "timeout") return { action: "deny", reason: `${prior}; ask timed out` };
    return result === true ? { action: "allow", reason: `${prior}; approved in Amp` } : { action: "deny", reason: `${prior}; declined in Amp` };
  } catch (error) {
    const unavailable = deps.uiUnavailable && error instanceof Error ? deps.uiUnavailable(error) : false;
    return { action: "deny", reason: unavailable ? `${prior}; no one to ask (Amp shows no dialog here)` : `${prior}; Amp's dialog failed` };
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function reject(reason: string): ToolCallResult {
  return { action: "reject-and-continue", message: `derm: ${reason}` };
}

export async function onToolCall(event: ToolCallEvent, ctx: HandlerContext | undefined, deps: Deps): Promise<ToolCallResult> {
  try {
    if (!isPlainObject(event) || typeof event.tool !== "string" || event.tool === "") return reject("tool call has no tool name");
    // Before the core sees it: the core's redaction slows down badly on long
    // runs of secret-like words (budget.ts), and what Amp does with a slow
    // handler is not documented.
    const heavy = overBudget(event.input);
    if (heavy) return reject(heavy);
    const call = gateCallOf(event, deps);
    const answer = decideCall(deps.loadPolicy(), call);
    const narrowed = narrowForControl(answer.action, inputTextFor(answer.normalizedTool, call.toolInput));
    if (narrowed.control) {
      answer.action = narrowed.action;
      answer.reason = `input names a control file (${narrowed.control})`;
    }
    const sendsOut = event.tool.startsWith("mcp__") || (AMP_SEND_OUT_TOOLS as readonly string[]).includes(event.tool);
    if (answer.updatedInput !== undefined && !sendsOut) {
      delete answer.updatedInput;
      if (answer.action === "allow") {
        answer.action = "ask";
        answer.reason = "secret-like value in input";
      }
    }
    let resolved: Resolved;
    if (answer.action === "ask") {
      const r = await deps.resolveAsk(answer, call, true);
      resolved = r.kind === "harness" ? await askAmp(answer, call, event.tool, ctx, deps, r.reason) : { action: r.kind, reason: r.reason };
    } else {
      resolved = { action: answer.action, reason: answer.reason };
    }
    let result: ToolCallResult;
    if (resolved.action === "deny") result = reject(resolved.reason);
    else if (answer.updatedInput === undefined) result = { action: "allow" };
    else if (isPlainObject(answer.updatedInput)) result = { action: "modify", input: answer.updatedInput };
    else {
      resolved = { action: "deny", reason: "secret-like value in input that derm cannot rewrite" };
      result = reject(resolved.reason);
    }
    // Not awaited: what Amp does with a slow handler is not documented, so the
    // record never holds the answer. postEvent is bounded and never throws;
    // a rejection is caught so it is never unhandled in Amp's process.
    const record = {
      id: decisionId(HARNESS, call.toolUseId),
      chatId: call.chat ?? "",
      harness: HARNESS,
      kind: "approval" as const,
      summary: `${answer.normalizedTool} ${resolved.action}`,
      detail: {
        tool: answer.normalizedTool,
        decision: resolved.action,
        policyAction: answer.action,
        reason: resolved.reason,
        redacted: answer.redacted,
        ...(call.toolUseId ? { toolUseId: call.toolUseId } : {}),
      },
    };
    // The install records follow the decision on the same chain, so on Amp
    // the lockfile is kept a little after the call starts (not awaited, as
    // above): a diff can miss what the first moments wrote.
    const installs = installEvents(call, answer, resolved.action, call.chat ?? "");
    void Promise.resolve()
      .then(async () => {
        await deps.postEvent(record);
        for (const e of installs) await deps.postEvent(e);
      })
      .catch(() => undefined);
    return result;
  } catch (error) {
    return reject(error instanceof Unreadable ? error.message : `hook error: ${(error as Error)?.message ?? String(error)}`);
  }
}

/**
 * Redacts secret-like strings in a result before it goes back to the model,
 * and records the call. Returns a replacement only when something was
 * redacted; nothing here can stop the result (the tool already ran).
 */
export async function onToolResult(event: ToolResultEvent, deps: Deps): Promise<ToolResultResult> {
  try {
    let serialized = "";
    try {
      serialized = JSON.stringify(event?.output ?? null) ?? "";
    } catch {
      serialized = "";
    }
    const sha = createHash("sha256").update(serialized, "utf8").digest("hex");
    let count = 0;
    // Output the agent can shape: long runs of secret-like words are taken out
    // whole first (budget.ts), so the core's redaction below stays fast.
    const defused = defuseValue(event?.output);
    count += defused.count;
    let output = defused.value;
    if (typeof output === "string") {
      const r = redactText(output);
      count += r.count;
      output = r.text;
    } else if (output !== undefined && output !== null && typeof output === "object") {
      const r = redactValue(output);
      count += r.count;
      output = r.value;
    }
    const defusedError = defuseValue(event?.error);
    count += defusedError.count;
    let error = defusedError.value;
    if (typeof error === "string") {
      const r = redactText(error);
      count += r.count;
      error = r.text;
    }
    // The record is sent and not awaited, as in onToolCall.
    try {
      const call = gateCallOf(event, deps);
      const tool = decideCall(deps.loadPolicy(), { ...call, toolInput: {} }).normalizedTool;
      const record = {
        id: `${HARNESS}-${call.toolUseId ?? "unknown"}`,
        chatId: call.chat ?? "",
        harness: HARNESS,
        kind: "tool.call" as const,
        summary: `${tool} ${event?.status ?? "done"}${count ? `, ${count} redacted` : ""}`,
        detail: {
          tool,
          status: event?.status,
          resultSha256: sha,
          resultBytes: Buffer.byteLength(serialized, "utf8"),
          redacted: count,
          ...(call.toolUseId ? { toolUseId: call.toolUseId } : {}),
        },
      };
      void Promise.resolve()
        .then(() => deps.postEvent(record))
        .catch(() => undefined);
    } catch {
      // The record is best effort; the redaction below still applies.
    }
    if (count === 0) return undefined;
    const status = event.status === "error" || event.status === "cancelled" ? event.status : "done";
    return {
      status,
      ...(typeof error === "string" ? { error } : {}),
      ...(output !== undefined ? { output } : {}),
    } as ToolResultResult;
  } catch {
    return undefined;
  }
}
