// Claude Code adapter (T2.1). Maps PreToolUse and PostToolUse hook input to
// the shared gate and the gate's answer back to Claude Code's hook output.
//
// Contract read at Claude Code 2.1.311 docs (hooks.md, permissions.md; see
// plans/parallel/tk_lane_F.md, Research):
// - PreToolUse output: hookSpecificOutput.permissionDecision allow | deny |
//   ask, permissionDecisionReason, updatedInput (replaces the whole input).
// - A hook's allow never overrides a deny or ask rule in settings.
// - Several hooks: deny > defer > ask > allow.
// - PostToolUse: hookSpecificOutput.updatedToolOutput replaces what Claude
//   sees, in the tool's own output shape.

import { createHash, randomUUID } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import path from "node:path";
import { approve, decisionId, postEvent } from "./core/daemon.ts";
import { decideCall, resolveAsk, type GateAnswer, type GateCall } from "./core/gate.ts";
import { loadPolicyFrom, type LoadedPolicy } from "./core/policy.ts";
import { redactValue } from "./core/redact.ts";

export const HARNESS = "claude-code";
const MAX_STDIN_BYTES = 32 * 1024 * 1024;

export type HookResult = { stdout: string; stderr: string; exitCode: number };

type Deps = {
  env: NodeJS.ProcessEnv;
  loadPolicy: () => LoadedPolicy;
  resolveAsk: typeof resolveAsk;
  postEvent: typeof postEvent;
};

function defaultDeps(env: NodeJS.ProcessEnv): Deps {
  return {
    env,
    loadPolicy: () => loadPolicyFrom(env),
    resolveAsk: (answer, call, canAsk) => resolveAsk(answer, call, canAsk, (r) => approve(r, env)),
    postEvent: (e) => postEvent(e, env),
  };
}

/** Modes where Claude Code may not show the prompt a hook's ask requests (not documented; fail safe). */
const NO_PROMPT_MODES = new Set(["bypassPermissions", "dontAsk"]);

function chatOf(input: Record<string, unknown>, env: NodeJS.ProcessEnv): string | undefined {
  const fromEnv = env.DERM_CHAT_ID?.trim();
  if (fromEnv) return fromEnv;
  return typeof input.session_id === "string" && input.session_id !== "" ? input.session_id : undefined;
}

function preOutput(decision: "allow" | "deny" | "ask", reason: string, updatedInput?: unknown): HookResult {
  const out: Record<string, unknown> = {
    hookEventName: "PreToolUse",
    permissionDecision: decision,
    permissionDecisionReason: `derm: ${reason}`,
  };
  if (updatedInput !== undefined) out.updatedInput = updatedInput;
  return { stdout: `${JSON.stringify({ hookSpecificOutput: out })}\n`, stderr: "", exitCode: 0 };
}

/** Exit 2 blocks the call on PreToolUse; stderr is the reason Claude reads. */
export function blockPre(reason: string): HookResult {
  return { stdout: "", stderr: `derm: ${reason}\n`, exitCode: 2 };
}

export async function handlePre(input: Record<string, unknown>, deps: Deps): Promise<HookResult> {
  if (typeof input.tool_name !== "string" || input.tool_name === "") return blockPre("hook input has no tool_name");
  const chat = chatOf(input, deps.env);
  const call: GateCall = {
    harness: HARNESS,
    tool: input.tool_name,
    toolInput: input.tool_input ?? {},
    ...(chat !== undefined ? { chat } : {}),
    ...(typeof input.tool_use_id === "string" ? { toolUseId: input.tool_use_id } : {}),
  };
  const answer: GateAnswer = decideCall(deps.loadPolicy(), call);
  let final: { decision: "allow" | "deny" | "ask"; reason: string } = { decision: answer.action, reason: answer.reason };
  if (answer.action === "ask") {
    const promptless = NO_PROMPT_MODES.has(String(input.permission_mode ?? ""));
    const r = await deps.resolveAsk(answer, call, !promptless);
    if (r.kind === "allow") final = { decision: "allow", reason: r.reason };
    else if (r.kind === "deny") final = { decision: "deny", reason: r.reason };
    else final = { decision: "ask", reason: r.reason };
  }
  await deps.postEvent({
    // A decision is written once per chat and id (the daemon, S9), so
    // one with no call id gets its own id instead of a shared "unknown".
    id: decisionId(HARNESS, call.toolUseId),
    chatId: chat ?? "",
    harness: HARNESS,
    kind: "approval",
    summary: `${answer.normalizedTool} ${final.decision}`,
    detail: {
      tool: answer.normalizedTool,
      decision: final.decision,
      policyAction: answer.action,
      reason: final.reason,
      redacted: answer.redacted,
      ...(call.toolUseId ? { toolUseId: call.toolUseId } : {}),
    },
  });
  const updated = final.decision === "deny" ? undefined : answer.updatedInput;
  return preOutput(final.decision, final.reason, updated);
}

export async function handlePost(input: Record<string, unknown>, deps: Deps): Promise<HookResult> {
  const toolName = typeof input.tool_name === "string" ? input.tool_name : "";
  const toolUseId = typeof input.tool_use_id === "string" ? input.tool_use_id : undefined;
  const response = input.tool_response;
  let serialized = "";
  try {
    serialized = JSON.stringify(response) ?? "";
  } catch {
    serialized = "";
  }
  const sha = createHash("sha256").update(serialized, "utf8").digest("hex");
  const { value, count } = redactValue(response);
  const chat = chatOf(input, deps.env);
  const policy = deps.loadPolicy();
  await deps.postEvent({
    id: `${HARNESS}-${toolUseId ?? "unknown"}`,
    chatId: chat ?? "",
    harness: HARNESS,
    kind: "tool.call",
    summary: `${decideCallName(toolName, policy)} done${count ? `, ${count} redacted` : ""}`,
    detail: {
      tool: decideCallName(toolName, policy),
      resultSha256: sha,
      resultBytes: Buffer.byteLength(serialized, "utf8"),
      redacted: count,
      ...(toolUseId ? { toolUseId } : {}),
    },
  });
  if (count === 0) return { stdout: "", stderr: "", exitCode: 0 };
  return {
    stdout: `${JSON.stringify({ hookSpecificOutput: { hookEventName: "PostToolUse", updatedToolOutput: value } })}\n`,
    stderr: "",
    exitCode: 0,
  };
}

function decideCallName(tool: string, loaded: LoadedPolicy): string {
  return decideCall(loaded, { harness: HARNESS, tool, toolInput: {} }).normalizedTool;
}

// Cursor's CLI runs Claude Code's hooks as "third-party hooks"
// (https://cursor.com/docs/reference/third-party-hooks, read 4 Nov 2026: from
// the three Claude settings files, on by default, `PreToolUse` mapped to
// `preToolUse`; exit 2 blocks), and runs an enabled plugin's hook too (seen
// by run on Cursor CLI 2026.10.22, Mac test w4, MW4-5), with
// `hook_event_name: "preToolUse"` and `cursor_version`. Cursor's own gate is
// derm's Cursor dialect (`packages/derm-hooks-native`) in ~/.cursor/hooks.json.
// When that is registered, failing closed, this hook gives no decision (`{}`,
// the answer Orca's Cursor hook gives) and posts nothing, so derm's gate runs
// once per call (case 75). When it is not, this hook blocks, as before, and
// names the fix: it never lets a Cursor call through ungated.

/** Input Cursor sends when it runs this hook, not Claude Code. */
export function runByCursor(input: Record<string, unknown>): boolean {
  return input.hook_event_name === "preToolUse" || input.hook_event_name === "postToolUse" || typeof input.cursor_version === "string";
}

const MAX_CURSOR_HOOKS_BYTES = 1024 * 1024;

/** derm's two Cursor entries (`connect/gates.json`) in ~/.cursor/hooks.json, each failClosed. */
export function cursorGateRegistered(env: NodeJS.ProcessEnv): boolean {
  const home = env.HOME;
  if (!home || !path.isAbsolute(home)) return false;
  const file = path.join(home, ".cursor", "hooks.json");
  try {
    const st = statSync(file);
    if (!st.isFile() || st.size > MAX_CURSOR_HOOKS_BYTES) return false;
    const v = JSON.parse(readFileSync(file, "utf8")) as { hooks?: Record<string, unknown> };
    return ["preToolUse", "beforeMCPExecution"].every((event) => {
      const list = v?.hooks?.[event];
      if (!Array.isArray(list)) return false;
      const ours = list.filter((e) => {
        const c = (e as { command?: unknown } | null)?.command;
        return typeof c === "string" && c.includes("derm-hook.mjs") && c.trimEnd().endsWith(" cursor");
      });
      return ours.length > 0 && ours.every((e) => (e as { failClosed?: unknown }).failClosed === true);
    });
  } catch {
    return false;
  }
}

function cursorRun(pre: boolean, env: NodeJS.ProcessEnv): HookResult {
  if (!pre) return { stdout: "", stderr: "", exitCode: 0 };
  if (cursorGateRegistered(env)) return { stdout: "{}\n", stderr: "", exitCode: 0 };
  return blockPre(
    "Cursor ran derm's Claude Code hook (Cursor's third-party hooks), and derm's own Cursor gate is not registered in ~/.cursor/hooks.json; run derm connect cursor --gate --hook <derm-hooks-native folder> --write, or turn off Third-Party Imports in Cursor's settings",
  );
}

/** Runs one hook invocation. `event` is "pre" or "post", from hooks.json. Never throws. */
export async function runHook(event: string, stdinText: string, env: NodeJS.ProcessEnv = process.env, deps?: Partial<Deps>): Promise<HookResult> {
  const d: Deps = { ...defaultDeps(env), ...deps };
  const pre = event === "pre";
  try {
    if (Buffer.byteLength(stdinText, "utf8") > MAX_STDIN_BYTES) return pre ? blockPre("hook input too large") : { stdout: "", stderr: "", exitCode: 0 };
    let input: unknown;
    try {
      input = JSON.parse(stdinText);
    } catch {
      return pre ? blockPre("hook input is not JSON") : { stdout: "", stderr: "", exitCode: 0 };
    }
    if (typeof input !== "object" || input === null || Array.isArray(input)) return pre ? blockPre("hook input is not an object") : { stdout: "", stderr: "", exitCode: 0 };
    const obj = input as Record<string, unknown>;
    if (runByCursor(obj)) return cursorRun(pre, d.env);
    if (pre) {
      if (obj.hook_event_name !== undefined && obj.hook_event_name !== "PreToolUse") return blockPre(`unexpected hook event ${String(obj.hook_event_name)}`);
      return await handlePre(obj, d);
    }
    if (event === "post") return await handlePost(obj, d);
    return { stdout: "", stderr: `derm: unknown hook event ${event}\n`, exitCode: 0 };
  } catch (error) {
    return pre ? blockPre(`hook error: ${(error as Error)?.message ?? String(error)}`) : { stdout: "", stderr: "", exitCode: 0 };
  }
}

/** Entry from bin/derm-hook.mjs: reads stdin, writes the result, returns the exit code. */
export async function main(event: string): Promise<number> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    const b = chunk as Buffer;
    size += b.length;
    if (size > MAX_STDIN_BYTES + 1) break;
    chunks.push(b);
  }
  const result = await runHook(event, Buffer.concat(chunks).toString("utf8"));
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  return result.exitCode;
}
