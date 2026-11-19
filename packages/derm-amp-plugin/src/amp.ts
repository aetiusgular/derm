// Amp adapter (T2.7): what is Amp's own in derm's gate for Amp. The handlers
// are in serve.ts and the decision is `derm gate serve`'s; until 19 Nov 2026
// this file also held a TypeScript gate, which is gone. Here: Amp's event
// shapes, the shell command a call runs, the call as the gate reads it,
// Amp's own dialog for an ask, and the reject shape. Read in
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
//   (the co-process's `approve`), then, when no approver is
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
import { redactText } from "./core/redact.ts";
import { inputTextFor, type GateCall } from "./preview.ts";

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
  /** The session folder: Amp's workspace root, else the plugin process's folder. */
  cwd: () => string;
  /** Amp's `helpers.shellCommandFromToolCall`, when the plugin runs inside Amp. */
  shellCommand?: (event: ToolCallEvent) => ShellCommand | null;
  /** Amp's `helpers.isPluginUINotAvailableError`. */
  uiUnavailable?: (error: Error) => boolean;
};

function chatOf(threadId: unknown, env: NodeJS.ProcessEnv): string | undefined {
  const fromEnv = env.DERM_CHAT_ID?.trim();
  if (fromEnv) return fromEnv;
  return typeof threadId === "string" && threadId !== "" ? threadId : undefined;
}

export function isPlainObject(v: unknown): v is Record<string, unknown> {
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
/** What Amp's dialog needs of `derm gate serve`'s answer (serve.ts). */
export type AskAnswer = { normalizedTool: string; reason: string; askTimeoutSeconds: number };

export function confirmOptions(answer: AskAnswer, call: GateCall, rawTool: string): ConfirmOptions {
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

export type Resolved = { action: "allow" | "deny"; reason: string };

/** Amp's own dialog, bounded by the policy's ask timeout. Anything but a yes in time is a deny. */
export async function askAmp(answer: AskAnswer, call: GateCall, rawTool: string, ctx: HandlerContext | undefined, deps: Pick<Deps, "uiUnavailable">, prior: string): Promise<Resolved> {
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

export function reject(reason: string): ToolCallResult {
  return { action: "reject-and-continue", message: `derm: ${reason}` };
}
