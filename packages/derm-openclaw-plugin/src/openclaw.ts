// OpenClaw adapter (T2.4). Read in the npm package openclaw 2026.10.8
// (dc2523e: docs/ and dist/ as shipped; plans/parallel/tk_lane_I.md, Research):
// - `api.on("before_tool_call", handler, {priority, timeoutMs})`; higher
//   priority runs first, default 0 (docs/plugins/hooks/reference.md:16-45;
//   dist/hooks-kvgtfJyA.mjs getHooksForName sorts by priority, higher first).
// - The handler gets {toolName, params, toolKind?, toolCallId?, runId?} and
//   ctx {sessionKey, sessionId, ...} (docs/plugins/hooks/tool-policy.md:16-40).
//   toolName is normalized first: `bash` arrives as `exec`.
// - It returns {block: true, blockReason}, which is final; {params}, where the
//   last returned params win and every handler sees the original event, not an
//   earlier rewrite; or {requireApproval: {...}}, where the first one wins and
//   freezes the params (tool-policy.md:44-85).
// - A throw or a timeout blocks: the global runner sets before_tool_call to
//   fail-closed (dist/hook-runner-global-BED4qrKY.mjs:96-107).
//
// So derm registers at the lowest priority and runs after every other plugin.
// It decides on the original call and, when it allows, returns those params:
// the last params win, so the call that runs is the call derm checked (rules
// case 88; a higher-priority plugin's rewrite is replaced by the original, and
// Codex's native relay reads returning the same params as no rewrite,
// dist/native-hook-relay-6I61vqHJ.mjs:178-181). Not covered: a higher-priority
// plugin that already asked for approval froze its own params snapshot.
//
// Wave 5b (lane 5bC): the policy's answer, the approver and the records are
// `derm gate serve`'s (contracts/gate-serve.md); OpenClaw's control files are
// in derm-core's list (`CONTROL_PATHS`), so src/control.ts is no longer on
// the path. A co-process that is not running blocks the call (case 228), as
// a throw does.

import { createHash } from "node:crypto";
import { ownedByTrusted } from "./core/owner.ts";
import { approve, decide, event, record, redact, ServeUnavailable, sharedServe, unavailable, type Call, type GateServe } from "./serve/client.ts";

export const HARNESS = "openclaw";
/** Lower than any plugin's ordinary priority, so derm runs last. */
export const DERM_PRIORITY = -1_000_000;
/** OpenClaw's default per-handler budget is 15 s (hooks-kvgtfJyA.mjs:351-360); derm's ask may wait longer. */
export const DERM_TIMEOUT_MS = 120_000;

export type Deps = {
  env: NodeJS.ProcessEnv;
  serve: () => GateServe;
};

export function defaultDeps(env: NodeJS.ProcessEnv = process.env, cwd: () => string = () => process.cwd()): Deps {
  return { env, serve: () => sharedServe({ agent: HARNESS, env, cwd, trusted: ownedByTrusted }) };
}

export type BeforeEvent = { toolName?: unknown; params?: unknown; toolKind?: unknown; toolCallId?: unknown; runId?: unknown };
export type BeforeCtx = { sessionKey?: unknown; sessionId?: unknown } | undefined;
export type BeforeResult =
  | { block: true; blockReason: string }
  | { params: Record<string, unknown> }
  | { requireApproval: { title: string; description: string; severity: "warning"; timeoutMs: number; allowedDecisions: ("allow-once" | "deny")[] } };

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function chatOf(ctx: BeforeCtx, env: NodeJS.ProcessEnv): string | undefined {
  const fromEnv = env.DERM_CHAT_ID?.trim();
  if (fromEnv) return fromEnv;
  const id = ctx?.sessionId ?? ctx?.sessionKey;
  return typeof id === "string" && id !== "" ? id : undefined;
}

/**
 * The name the gate matches. OpenClaw's shell tool is `exec` (`bash` is
 * normalized to it), which the core's shell list does not name, so a shell
 * `exec` is gated as `bash` and gets the shell-text check (rules case 82).
 * Code Mode's outer `exec` (toolKind code_mode_exec) is a code tool and keeps
 * its own name.
 */
export function toolForGate(event: BeforeEvent): string {
  const name = String(event.toolName ?? "");
  if (name === "exec" && event.toolKind !== "code_mode_exec") return "bash";
  return name;
}

function block(reason: string): BeforeResult {
  return { block: true, blockReason: `derm: ${reason.replace(/\s+/g, " ").trim() || "blocked"}` };
}

export async function beforeToolCall(event: BeforeEvent, ctx: BeforeCtx, deps: Deps): Promise<BeforeResult> {
  try {
    if (typeof event?.toolName !== "string" || event.toolName === "") return block("tool call has no tool name");
    const params = isPlainObject(event.params) ? event.params : {};
    const chat = chatOf(ctx, deps.env);
    const id = typeof event.toolCallId === "string" && event.toolCallId !== "" ? event.toolCallId : undefined;
    const call: Call = { tool: toolForGate(event), input: params, ...(chat !== undefined ? { chat } : {}), ...(id !== undefined ? { toolUseId: id } : {}) };
    const s = deps.serve();
    // OpenClaw's own approval can still decide an ask, so this plugin settles
    // the outcome and records it.
    const answer = await decide(s, call, false);
    let action: "allow" | "deny" | "approval" = answer.action === "ask" ? "approval" : answer.action;
    let reason = answer.reason;
    if (answer.action === "ask") {
      const r = await approve(s, call, answer, true, false);
      action = r.kind === "allow" ? "allow" : r.kind === "deny" ? "deny" : "approval";
      reason = r.reason;
    }
    if (action !== "deny" && answer.updatedInput !== undefined && !isPlainObject(answer.updatedInput)) {
      action = "deny";
      reason = "secret-like value in input that derm cannot rewrite on OpenClaw";
    }
    await record(s, call, answer, action === "approval" ? "ask" : action, { reason });
    if (action === "deny") return block(reason);
    if (action === "approval") {
      return {
        requireApproval: {
          title: `derm: allow ${answer.normalizedTool}?`,
          description: `derm asks: ${reason}`,
          severity: "warning",
          timeoutMs: answer.askTimeoutSeconds * 1000,
          allowedDecisions: ["allow-once", "deny"],
        },
      };
    }
    // Allow: hand back the params derm checked (redacted where it redacted), so
    // they are the ones that run.
    return { params: (isPlainObject(answer.updatedInput) ? answer.updatedInput : params) as Record<string, unknown> };
  } catch (error) {
    if (error instanceof ServeUnavailable) return block(unavailable(error));
    return block(`hook error: ${(error as Error)?.message ?? String(error)}`);
  }
}

export type AfterEvent = { toolName?: unknown; result?: unknown; error?: unknown; toolCallId?: unknown };

/** after_tool_call only observes (tool-policy.md:266-309): derm records the call, with no content. */
export async function afterToolCall(event: AfterEvent, ctx: BeforeCtx, deps: Deps): Promise<void> {
  try {
    let serialized = "";
    try {
      serialized = JSON.stringify(event?.result ?? event?.error ?? null) ?? "";
    } catch {
      serialized = "";
    }
    const sha = createHash("sha256").update(serialized, "utf8").digest("hex");
    const s = deps.serve();
    const { count } = await redact(s, event?.result ?? null);
    const chat = chatOf(ctx, deps.env);
    const id = typeof event?.toolCallId === "string" ? event.toolCallId : undefined;
    const tool = (await decide(s, { tool: toolForGate(event as BeforeEvent) || "unknown", input: {} }, false)).normalizedTool;
    await event_(s, {
      id: `${HARNESS}-${id ?? "unknown"}`,
      chatId: chat ?? "",
      kind: "tool.call",
      summary: `${tool} done${count ? `, ${count} secret-like` : ""}`,
      detail: { tool, resultSha256: sha, resultBytes: Buffer.byteLength(serialized, "utf8"), secretLike: count, ...(id ? { toolUseId: id } : {}) },
    });
  } catch {
    // The tool already ran.
  }
}

/** The client's `event`, named apart from this hook's `event` argument. */
const event_ = event;
