// OpenCode adapter (T2.3; wave 5b lane 5bC: the decision is `derm gate
// serve`'s). Read in OpenCode's source at v1.19.4 (148842ef), see
// plans/parallel/tk_lane_F.md, Research:
// - tool.execute.before(input {tool, sessionID, callID}, output {args}) runs
//   before every built-in and MCP tool (session/tools.ts:105-110, 401-405).
//   A throw stops the call: the trigger awaits each hook inside the tool's
//   effect (plugin/index.ts:291-295), before item.execute runs.
// - output.args is the very object the tool then runs with; replacing
//   output.args changes nothing, so redaction edits it in place.
// - tool.execute.after(input {tool, sessionID, callID, args}, output): for a
//   built-in tool output is {title, output, metadata, attachments}; for an
//   MCP tool it is the MCP result {content: [...]}. It is edited in place.
// - MCP tools are named sanitize(server) + "_" + sanitize(tool)
//   (mcp/catalog.ts:117-119): the policy's `servers` list splits them.
// - OpenCode has no ask a hook can raise, so a policy ask goes to the derm
//   daemon's approver; anything but an approver's yes is a deny
//   (contracts/policy.md section 5).
//
// The policy's answer, the approver and the records are the co-process's
// (contracts/gate-serve.md): this file keeps OpenCode's glue, the in-place
// rewrite and the throw. A co-process that is not running is a throw too
// (case 228).

import { createHash, randomUUID } from "node:crypto";
import { ownedByTrusted } from "./core/owner.ts";
import { approve, decide, event, record, redact, ServeUnavailable, sharedServe, unavailable, type Call, type GateServe } from "./serve/client.ts";

export const HARNESS = "opencode";

export type BeforeInput = { tool: string; sessionID: string; callID: string };
export type BeforeOutput = { args: unknown };
export type AfterInput = { tool: string; sessionID: string; callID: string; args?: unknown };

export type Deps = {
  env: NodeJS.ProcessEnv;
  serve: () => GateServe;
};

export function defaultDeps(env: NodeJS.ProcessEnv = process.env, cwd: () => string = () => process.cwd(), harness: string = HARNESS): Deps {
  return { env, serve: () => sharedServe({ agent: harness, env, cwd, trusted: ownedByTrusted }) };
}

/** The error a blocked call throws; OpenCode shows its message as the tool's failure. */
export class DermBlocked extends Error {
  constructor(reason: string) {
    super(`derm: ${reason}`);
    this.name = "DermBlocked";
  }
}

function chatOf(sessionID: unknown, env: NodeJS.ProcessEnv): string | undefined {
  const fromEnv = env.DERM_CHAT_ID?.trim();
  if (fromEnv) return fromEnv;
  return typeof sessionID === "string" && sessionID !== "" ? sessionID : undefined;
}

function container(v: unknown): boolean {
  return typeof v === "object" && v !== null;
}

/** Replaces the contents of `target` with `source`, keeping the same object. */
function replaceInPlace(target: unknown, source: unknown): boolean {
  if (!container(target) || !container(source)) return false;
  if (Array.isArray(target) && Array.isArray(source)) {
    target.splice(0, target.length, ...source);
    return true;
  }
  if (Array.isArray(target) || Array.isArray(source)) return false;
  const t = target as Record<string, unknown>;
  for (const k of Object.keys(t)) delete t[k];
  Object.assign(t, source);
  return true;
}

function callOf(harness: string, input: BeforeInput, args: unknown, env: NodeJS.ProcessEnv): Call {
  const chat = chatOf(input.sessionID, env);
  return {
    tool: input.tool,
    input: args ?? {},
    ...(chat !== undefined ? { chat } : {}),
    ...(typeof input.callID === "string" && input.callID !== "" ? { toolUseId: input.callID } : {}),
  };
}

export async function before(input: BeforeInput, output: BeforeOutput, deps: Deps): Promise<void> {
  try {
    if (typeof input?.tool !== "string" || input.tool === "") throw new DermBlocked("tool call has no tool name");
    const s = deps.serve();
    const call = callOf(HARNESS, input, output?.args, deps.env);
    // Input that is not an object cannot be rewritten in place: the plugin
    // then settles the outcome and records it itself.
    const inPlace = container(output?.args);
    const answer = await decide(s, call, inPlace);
    let action = answer.action;
    let reason = answer.reason;
    if (action === "ask") {
      const r = await approve(s, call, answer, false, inPlace);
      action = r.kind === "allow" ? "allow" : "deny";
      reason = r.reason;
    }
    if (action === "allow" && answer.updatedInput !== undefined && !replaceInPlace(output.args, answer.updatedInput)) {
      action = "deny";
      reason = "secret-like value in input that derm cannot rewrite";
    }
    if (!inPlace) await record(s, call, answer, action, { reason });
    if (action === "deny") throw new DermBlocked(reason);
  } catch (error) {
    if (error instanceof DermBlocked) throw error;
    if (error instanceof ServeUnavailable) throw new DermBlocked(unavailable(error));
    throw new DermBlocked(`hook error: ${(error as Error)?.message ?? String(error)}`);
  }
}

export async function after(input: AfterInput, output: unknown, deps: Deps): Promise<void> {
  try {
    let serialized = "";
    try {
      serialized = JSON.stringify(output) ?? "";
    } catch {
      serialized = "";
    }
    const sha = createHash("sha256").update(serialized, "utf8").digest("hex");
    const s = deps.serve();
    let count = 0;
    if (typeof output === "object" && output !== null) {
      const o = output as Record<string, unknown>;
      const parts: Record<string, unknown> = {};
      for (const k of ["output", "content", "metadata"]) if (k in o) parts[k] = o[k];
      const r = await redact(s, parts);
      if (r.count > 0 && typeof r.value === "object" && r.value !== null) {
        const v = r.value as Record<string, unknown>;
        if (typeof o.output === "string" && typeof v.output === "string") o.output = v.output;
        for (const k of ["content", "metadata"]) if (container(o[k])) replaceInPlace(o[k], v[k]);
        count = r.count;
      }
    }
    const chat = chatOf(input?.sessionID, deps.env);
    const callId = typeof input?.callID === "string" ? input.callID : undefined;
    const tool = (await decide(s, { tool: String(input?.tool ?? "") || "unknown", input: {} }, false)).normalizedTool;
    await event(s, {
      id: `${HARNESS}-${callId ?? `unknown-${randomUUID()}`}`,
      chatId: chat ?? "",
      kind: "tool.call",
      summary: `${tool} done${count ? `, ${count} redacted` : ""}`,
      detail: { tool, resultSha256: sha, resultBytes: Buffer.byteLength(serialized, "utf8"), redacted: count, ...(callId ? { toolUseId: callId } : {}) },
    });
  } catch {
    // After the call nothing is gained by failing: the tool already ran.
  }
}
