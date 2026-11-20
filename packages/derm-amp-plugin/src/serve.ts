// Amp on `derm gate serve` (fix pass 6; note BE section 3.3, option A, Tony's
// call of 15 Nov 2026). The same handlers as amp.ts, with the decision, the
// approver, the records and the redaction the co-process's
// (contracts/gate-serve.md), as OpenCode's, Kilo's, OpenClaw's, Pi's and
// Cline's are: one decide path (`gate::core::decide_call`, case 229), so Amp
// gets taint, the light log and Windows policy parity.
//
// Built and tested against the real `derm gate serve`. It is the plugin's
// only gate since 19 Nov 2026 (Tony's call): the TypeScript gate that
// amp.ts held, and the switch `DERM_AMP_GATE_SERVE` that chose between them,
// are gone. No real Amp run has passed with this path yet (BBR-13); what it
// does when it cannot decide is refuse the call (reject-and-continue).
//
// What stays Amp's, and so stays here: the shell command Amp's helper reads
// (amp.ts gateCallOf), Amp's own dialog for an ask no approver answered
// (amp.ts askAmp; `approve` with canAsk true answers `harness` then), the
// reject-and-continue shape for every deny (case 79), and a rewrite only for
// a tool that sends its input out as it is (MCP, web_search,
// read_web_page; lane P review, P-S6). Amp's control files are in derm-core's
// control list (crates/derm-core/src/policy.rs, `.config/amp/` and the rest),
// so the narrowing control.ts did is the co-process's.

import { createHash } from "node:crypto";
import { AMP_SEND_OUT_TOOLS, HARNESS, askAmp, gateCallOf, isPlainObject, reject, Unreadable, type HandlerContext, type Resolved, type ShellCommand, type ToolCallEvent, type ToolCallResult, type ToolResultEvent, type ToolResultResult } from "./amp.ts";
import { defuseValue, overBudget } from "./budget.ts";
import { ownedByTrusted } from "./core/owner.ts";
import { redactText, redactValue } from "./core/redact.ts";
import { approve, decide, event, record, redact, ServeUnavailable, sharedServe, unavailable, type Call, type GateServe } from "./serve/client.ts";

export type ServeDeps = {
  env: NodeJS.ProcessEnv;
  serve: () => GateServe;
  shellCommand?: (event: ToolCallEvent) => ShellCommand | null;
  uiUnavailable?: (error: Error) => boolean;
};

export function serveDeps(env: NodeJS.ProcessEnv = process.env, cwd: () => string = () => process.cwd()): ServeDeps {
  return { env, serve: () => sharedServe({ agent: HARNESS, env, cwd, trusted: ownedByTrusted }) };
}

function callOf(event: ToolCallEvent, deps: ServeDeps): Call {
  const g = gateCallOf(event, deps);
  return {
    tool: g.tool,
    input: g.toolInput ?? {},
    ...(g.chat !== undefined ? { chat: g.chat } : {}),
    ...(g.toolUseId !== undefined ? { toolUseId: g.toolUseId } : {}),
  };
}

export async function onToolCallServe(event: ToolCallEvent, ctx: HandlerContext | undefined, deps: ServeDeps): Promise<ToolCallResult> {
  try {
    if (!isPlainObject(event) || typeof event.tool !== "string" || event.tool === "") return reject("tool call has no tool name");
    // Bounded before it crosses to the co-process, as amp.ts bounds it.
    const heavy = overBudget(event.input);
    if (heavy) return reject(heavy);
    const call = callOf(event, deps);
    const s = deps.serve();
    // The plugin settles the outcome (Amp's dialog, the rewrite rule
    // below), so it records it: `record: false` here, `record` at the end.
    const answer = await decide(s, call, false);
    const sendsOut = event.tool.startsWith("mcp__") || (AMP_SEND_OUT_TOOLS as readonly string[]).includes(event.tool);
    let updatedInput = answer.updatedInput;
    let action = answer.action;
    let reason = answer.reason;
    if (updatedInput !== undefined && !sendsOut) {
      updatedInput = undefined;
      if (action === "allow") {
        action = "ask";
        reason = "secrets, secret-like value in input";
      }
    }
    const asked = { ...answer, action, reason, updatedInput };
    let resolved: Resolved;
    if (action === "ask") {
      const r = await approve(s, call, asked, true, false);
      resolved = r.kind === "harness" ? await askAmp(asked, { harness: HARNESS, tool: call.tool, toolInput: call.input, ...(call.chat ? { chat: call.chat } : {}) }, event.tool, ctx, deps, r.reason) : { action: r.kind, reason: r.reason };
    } else {
      resolved = { action, reason };
    }
    let result: ToolCallResult;
    if (resolved.action === "deny") result = reject(resolved.reason);
    else if (updatedInput === undefined) result = { action: "allow" };
    else if (isPlainObject(updatedInput)) result = { action: "modify", input: updatedInput };
    else {
      resolved = { action: "deny", reason: "secrets, secret-like value in input that derm cannot rewrite" };
      result = reject(resolved.reason);
    }
    // Queued, not waited for (`wait: false`): what Amp does with a slow
    // handler is not documented (amp.ts). record never throws.
    await record(s, call, asked, resolved.action, { reason: resolved.reason, wait: false });
    return result;
  } catch (error) {
    if (error instanceof Unreadable) return reject(error.message);
    if (error instanceof ServeUnavailable) return reject(unavailable(error));
    return reject(`hook error: ${(error as Error)?.message ?? String(error)}`);
  }
}

/**
 * The co-process's redaction of a result before it goes back to the model,
 * and the call's record. With no co-process the TypeScript redactor still
 * runs: a secret is never let through for want of one (the tool already ran,
 * so nothing here can stop it).
 */
export async function onToolResultServe(event: ToolResultEvent, deps: ServeDeps): Promise<ToolResultResult> {
  try {
    let serialized = "";
    try {
      serialized = JSON.stringify(event?.output ?? null) ?? "";
    } catch {
      serialized = "";
    }
    const sha = createHash("sha256").update(serialized, "utf8").digest("hex");
    let count = 0;
    const defused = defuseValue(event?.output);
    const defusedError = defuseValue(event?.error);
    count += defused.count + defusedError.count;
    let output = defused.value;
    let error = defusedError.value;
    let s: GateServe | undefined;
    try {
      s = deps.serve();
      const r = await redact(s, { output: output ?? null, error: error ?? null });
      if (r.count > 0 && isPlainObject(r.value)) {
        count += r.count;
        if (output !== undefined) output = r.value.output;
        if (error !== undefined) error = r.value.error;
      }
    } catch {
      s = undefined;
      if (typeof output === "string") {
        const r = redactText(output);
        count += r.count;
        output = r.text;
      } else if (output !== undefined && output !== null && typeof output === "object") {
        const r = redactValue(output);
        count += r.count;
        output = r.value;
      }
      if (typeof error === "string") {
        const r = redactText(error);
        count += r.count;
        error = r.text;
      }
    }
    if (s !== undefined) {
      try {
        const call = callOf(event, deps);
        const tool = (await decide(s, { tool: call.tool, input: {} }, false)).normalizedTool;
        await event_(s, {
          id: `${HARNESS}-${call.toolUseId ?? "unknown"}`,
          chatId: call.chat ?? "",
          kind: "tool.call",
          summary: `${tool} ${event?.status ?? "done"}${count ? `, ${count} redacted` : ""}`,
          detail: {
            tool,
            status: event?.status,
            resultSha256: sha,
            resultBytes: Buffer.byteLength(serialized, "utf8"),
            redacted: count,
            ...(call.toolUseId ? { toolUseId: call.toolUseId } : {}),
          },
        });
      } catch {
        // The record is best effort; the redaction below still applies.
      }
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

/** `event` with `wait: false`, named apart from the handler's own `event` argument. */
function event_(s: GateServe, e: Record<string, unknown>): Promise<void> {
  return event(s, e, false);
}
