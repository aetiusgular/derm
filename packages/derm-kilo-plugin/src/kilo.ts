// Kilo Code CLI adapter (T2.4): lane F's OpenCode adapter with Kilo's id,
// paths and control files. Kilo is a fork of OpenCode; read in Kilo's source
// at v7.8.18 (b8176153), see plans/parallel/tk_lane_I.md, Research:
// - tool.execute.before(input {tool, sessionID, callID}, output {args}) runs
//   before each built-in and MCP tool (packages/opencode/src/session/tools.ts:
//   198, 268, 348, 425, 493); the trigger awaits every plugin's hook in load
//   order (plugin/index.ts:294-307), so a throw stops the call before
//   item.execute runs. A later plugin (a project's .kilo/plugin/, which loads
//   with no trust prompt, config/config.ts:786-796) runs after this one and
//   can change output.args after derm decided: the same class as Pi's load order
//   (rules case 88).
// - output.args is the object the tool runs with: redaction edits it in place.
// - MCP tools are sanitize(server) + "_" + sanitize(tool), sanitize keeping
//   [a-zA-Z0-9_-] (mcp/catalog.ts:117-119): the policy's `servers` list
//   splits them, `-` included (the normalizer folds `-` to `_` on both sides).
// - Kilo never fires permission.ask (note AQ section 4c), so a policy ask goes
//   to the derm daemon's approver; anything but an approver's yes is a deny.
// - No runtime 
//
// Wave 5b (lane 5bC): the policy's answer, the approver and the records are
// `derm gate serve`'s (contracts/gate-serve.md); Kilo's control files are in
// derm-core's list (`CONTROL_PATHS`, folded in by integration w2), so the
// co-process narrows for them and src/control.ts is no longer on the path.
// This file keeps Kilo's glue: the in-place rewrite and the throw.

import { createHash, randomUUID } from "node:crypto";
import { ownedByTrusted } from "./core/owner.ts";
import { approve, decide, event, record, redact, ServeUnavailable, sharedServe, unavailable, type Call, type GateServe } from "./serve/client.ts";

export const HARNESS = "kilo";

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

/** The error a blocked call throws; Kilo shows its message as the tool's failure. */
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
