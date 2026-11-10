// The one hook for the eight Claude-format agents (T2.5). bin/derm-hook.mjs
// runs `main(<agent id>, <event>)`; the agent's dialect (src/agents.ts) reads
// its input and writes its reply; everything between is the synced core's.
//
// The rules every dialect keeps are contracts/hook-dialects.md section 1:
// one decision, the core's; allow only where a rule says allow (case 72); an
// ask goes to the agent's own prompt where it shows one in this mode, else to
// the derm approver, else it is a deny, never "no decision" (cases 71, 83);
// a deny blocks one call, never the run (case 79); nothing is printed but the
// agent's decision, and the tool input is never echoed (case 77).

import { createHash } from "node:crypto";
import { approve, decisionId, postEvent } from "./core/daemon.ts";
import { decideCall, inputTextFor, installEvents, resolveAsk, type GateAnswer, type GateCall } from "./core/gate.ts";
import { loadPolicyFrom, type LoadedPolicy } from "./core/policy.ts";
import { DIALECTS } from "./agents.ts";
import { narrowForControl } from "./control.ts";
import { isPlainObject, oneLine, type Dialect, type HookResult, type ReadCall } from "./dialect.ts";
import { hookEnv } from "./env.ts";

export type { HookResult } from "./dialect.ts";

const MAX_STDIN_BYTES = 32 * 1024 * 1024;

export type Deps = {
  env: NodeJS.ProcessEnv;
  loadPolicy: () => LoadedPolicy;
  resolveAsk: typeof resolveAsk;
  postEvent: typeof postEvent;
};

/** `socketDirs` is where a token file may be derived (env.ts); tests name their fake daemon's folder. */
export function defaultDeps(rawEnv: NodeJS.ProcessEnv, socketDirs?: readonly string[]): Deps {
  const env = hookEnv(rawEnv, socketDirs);
  return {
    env,
    loadPolicy: () => loadPolicyFrom(env),
    resolveAsk: (answer, call, canAsk) => resolveAsk(answer, call, canAsk, (r) => approve(r, env)),
    postEvent: (e) => postEvent(e, env),
  };
}

/**
 * A key for a call the agent gives no id (Droid, Auggie, Copilot): the
 * session, the tool and its input. Only joins records; a decision's own id
 * still ends in 128 random bits (decisionId).
 */
export function callKey(dialect: Dialect, call: ReadCall): string {
  let args = "";
  try {
    args = JSON.stringify(call.toolInput ?? {}) ?? "";
  } catch {
    args = "";
  }
  return createHash("sha256").update(`${dialect.id}\n${call.session ?? ""}\n${call.rawTool}\n${args}`, "utf8").digest("hex").slice(0, 16);
}

export type Outcome = { decision: "allow" | "deny" | "ask"; reason: string; answer: GateAnswer; agentAsks: boolean };

/** The decision for one call, before the reply is written. Exported for tests. */
export async function decide(dialect: Dialect, call: ReadCall, deps: Deps): Promise<Outcome> {
  const chat = deps.env.DERM_CHAT_ID?.trim() || call.session;
  const gateCall: GateCall = {
    harness: dialect.id,
    tool: call.tool,
    toolInput: call.toolInput,
    ...(chat ? { chat } : {}),
    ...(call.callId ? { toolUseId: call.callId } : {}),
  };
  const answer = decideCall(deps.loadPolicy(), gateCall);

  // Narrowing only, in this order; each turns an allow into an ask.
  const narrowed = narrowForControl(answer.action, inputTextFor(answer.normalizedTool, call.toolInput));
  if (narrowed.control) {
    answer.action = narrowed.action;
    answer.reason = `input names a control file (${narrowed.control})`;
  }
  if (call.unresolved && answer.action === "allow") {
    answer.action = "ask";
    answer.reason = `${answer.reason}; ${call.unresolved}`;
  }
  const needsRewrite = answer.updatedInput !== undefined;
  const canRewrite = dialect.canRewrite && !call.inputMapped && isPlainObject(answer.updatedInput);
  if (needsRewrite && !canRewrite && answer.action === "allow") {
    answer.action = "ask";
    answer.reason = `secret-like value in input that derm cannot rewrite on ${dialect.name}`;
  }

  if (answer.action === "deny") return { decision: "deny", reason: answer.reason, answer, agentAsks: false };
  if (answer.action === "allow") return { decision: "allow", reason: answer.reason, answer, agentAsks: false };

  const own = dialect.reply.ask !== undefined && dialect.ownAskIn(call, deps.env);
  const r = await deps.resolveAsk(answer, gateCall, own);
  if (r.kind === "allow") return { decision: "allow", reason: r.reason, answer, agentAsks: false };
  if (r.kind === "deny") return { decision: "deny", reason: r.reason, answer, agentAsks: false };
  return { decision: "ask", reason: r.reason, answer, agentAsks: true };
}

export async function handlePre(dialect: Dialect, input: Record<string, unknown>, deps: Deps): Promise<HookResult> {
  // A hook registered for one event and run for another (a copy of the
  // registration under PostToolUse, say) decides nothing: it blocks.
  for (const key of ["hook_event_name", "hookEventName"]) {
    const v = input[key];
    if (v !== undefined && !(typeof v === "string" && dialect.events.includes(v))) return dialect.reply.deny(`unexpected hook event ${oneLine(String(v), 64)}`);
  }
  const read = dialect.read(input);
  if ("error" in read) return dialect.reply.deny(read.error);
  const out = await decide(dialect, read, deps);
  const chat = deps.env.DERM_CHAT_ID?.trim() || read.session;
  await deps.postEvent({
    id: decisionId(dialect.id, read.callId ?? callKey(dialect, read)),
    chatId: chat ?? "",
    harness: dialect.id,
    kind: "approval",
    summary: `${out.answer.normalizedTool} ${out.decision}`,
    detail: {
      tool: out.answer.normalizedTool,
      decision: out.decision,
      policyAction: out.answer.action,
      reason: out.reason,
      redacted: out.answer.redacted,
      ...(read.callId ? { toolUseId: read.callId } : { callKey: callKey(dialect, read) }),
    },
  });
  // With no call id the records join by the call key, so the install record
  // carries it as its toolUseId.
  const installCall: GateCall = { harness: dialect.id, tool: read.tool, toolInput: read.toolInput, toolUseId: read.callId ?? callKey(dialect, read) };
  for (const e of installEvents(installCall, out.answer, out.decision, chat ?? "")) await deps.postEvent(e);
  if (out.decision === "deny") return dialect.reply.deny(out.reason);
  if (out.decision === "ask") {
    // decide() returns "ask" only when the dialect has an ask of its own.
    const ask = dialect.reply.ask;
    return ask ? ask(out.reason) : dialect.reply.deny(`${out.reason}; ${dialect.name} cannot ask`);
  }
  const updated = dialect.canRewrite && !read.inputMapped && isPlainObject(out.answer.updatedInput) ? out.answer.updatedInput : undefined;
  return dialect.reply.allow(out.reason, updated);
}

/** Runs one hook invocation. Never throws; any failure on the pre event is that agent's deny. */
export async function runHook(agent: string, event: string, stdinText: string, env: NodeJS.ProcessEnv = process.env, deps?: Partial<Deps>): Promise<HookResult> {
  const dialect = DIALECTS[agent];
  if (!dialect) return { stdout: "", stderr: `derm: unknown agent ${oneLine(agent, 64)}\n`, exitCode: 2 };
  if (event !== "pre") return { stdout: "", stderr: `derm: unknown hook event ${oneLine(event, 64)}\n`, exitCode: 2 };
  const d: Deps = { ...defaultDeps(env), ...deps };
  try {
    if (Buffer.byteLength(stdinText, "utf8") > MAX_STDIN_BYTES) return dialect.reply.deny("hook input too large");
    let input: unknown;
    try {
      input = JSON.parse(stdinText);
    } catch {
      return dialect.reply.deny("hook input is not JSON");
    }
    if (!isPlainObject(input)) return dialect.reply.deny("hook input is not an object");
    return await handlePre(dialect, input, d);
  } catch (error) {
    return dialect.reply.deny(`hook error: ${(error as Error)?.message ?? String(error)}`);
  }
}

/** Entry from bin/derm-hook.mjs: reads stdin, writes the result, returns the exit code. */
export async function main(agent: string, event: string): Promise<number> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    const b = chunk as Buffer;
    size += b.length;
    if (size > MAX_STDIN_BYTES + 1) break;
    chunks.push(b);
  }
  const result = await runHook(agent, event, Buffer.concat(chunks).toString("utf8"));
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  return result.exitCode;
}
