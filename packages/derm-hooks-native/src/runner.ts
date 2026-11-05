// The part every lane N dialect shares (contracts/hook-dialects.md section
// 1): read the agent's stdin, turn it into the core's call through the
// agent's dialect, decide with the synced core (src/core/, never edited here),
// resolve an ask, record the decision, and print the agent's own reply.
//
// What differs per agent lives in src/dialects/<preset id>.ts: how the call
// is read (tool name, input, chat, call id), which shell tools become `bash`
// (case 82), and how allow, ask and deny are written (cases 71, 72, 77, 79).

import { approve, decisionId, postEvent } from "./core/daemon.ts";
import { decideCall, inputTextFor, installEvents, resolveAsk, type GateAnswer, type GateCall } from "./core/gate.ts";
import { loadPolicyFrom, type LoadedPolicy } from "./core/policy.ts";
import { narrowForControl } from "./control.ts";

export const MAX_STDIN_BYTES = 32 * 1024 * 1024;

export type HookResult = { stdout: string; stderr: string; exitCode: number };

export const NONE: HookResult = { stdout: "", stderr: "", exitCode: 0 };

/** What a dialect reads out of the agent's pre-tool input. */
export type ReadCall = {
  /** The tool name the gate matches (shell tools already mapped to `bash`). */
  tool: string;
  /** The name the agent sent, kept for the record. */
  rawTool: string;
  toolInput: unknown;
  chat?: string;
  callId?: string;
  /**
   * Set when the dialect could not settle which server an MCP name belongs
   * to: an allow then asks (the same rule as the core's ambiguous split).
   */
  ambiguous?: string;
  /**
   * Set when another hook event of the same agent decides this call in full
   * (Cursor's beforeMCPExecution after a preToolUse that names no server):
   * this event then denies only what the core denies outright and lets the
   * rest on to that event, without asking anyone.
   */
  deferUnlessDeny?: string;
};

export type Dialect = {
  /** The agent's preset id, which is also the harness id the policy sees. */
  id: string;
  /** The agent's display name for messages. */
  name: string;
  /** Reads the call, or returns why it cannot (a block). */
  read(input: Record<string, unknown>, env: NodeJS.ProcessEnv): ReadCall | string;
  /** True when the agent shows its own prompt for this call when the hook asks. */
  ownAsk(input: Record<string, unknown>): boolean;
  /** The reply for a policy allow; `updatedInput` set when derm redacted the input. */
  allow(reason: string, updatedInput?: unknown): HookResult;
  /** The reply that denies this one call and lets the run go on (case 79). */
  deny(reason: string): HookResult;
  /** The reply that hands the call to the agent's own prompt. Only called when `ownAsk` is true. */
  ask(reason: string): HookResult;
  /** Whether the agent takes a rewritten input from a hook. */
  canRewrite: boolean;
};

export type Deps = {
  env: NodeJS.ProcessEnv;
  loadPolicy: () => LoadedPolicy;
  resolveAsk: typeof resolveAsk;
  postEvent: typeof postEvent;
};

export function defaultDeps(env: NodeJS.ProcessEnv): Deps {
  return {
    env,
    loadPolicy: () => loadPolicyFrom(env),
    resolveAsk: (answer, call, canAsk) => resolveAsk(answer, call, canAsk, (r) => approve(r, env)),
    postEvent: (e) => postEvent(e, env),
  };
}

export function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** One line of text, never empty. A reason is derm's own text plus rule names; never the tool input. */
export function oneLine(reason: string): string {
  const text = reason.replace(/\s+/g, " ").trim();
  return text === "" ? "blocked" : text;
}

/** The chat a record belongs to: `DERM_CHAT_ID` from derm run, else the agent's session id. */
export function chatFrom(env: NodeJS.ProcessEnv, sessionId: unknown): string | undefined {
  const fromEnv = env.DERM_CHAT_ID?.trim();
  if (fromEnv) return fromEnv;
  return typeof sessionId === "string" && sessionId !== "" ? sessionId : undefined;
}

export type Outcome = { decision: "allow" | "ask" | "deny"; reason: string; answer: GateAnswer };

/** Decides one read call: the core, the agent's control files, then the ask. */
export async function decide(dialect: Dialect, input: Record<string, unknown>, read: ReadCall, deps: Deps): Promise<Outcome> {
  const call: GateCall = {
    harness: dialect.id,
    tool: read.tool,
    toolInput: read.toolInput,
    ...(read.chat !== undefined ? { chat: read.chat } : {}),
    ...(read.callId !== undefined ? { toolUseId: read.callId } : {}),
  };
  const answer = decideCall(deps.loadPolicy(), call);
  if (answer.updatedInput !== undefined && !answer.normalizedTool.includes("/")) {
    // The core redacts the input of any tool it does not know writes or
    // runs. On these agents that includes built-in tools under their own
    // names (Vibe's `write_file`, goose's `write`): rewriting one changes
    // what it does, so a secret-like value there asks instead, as the core
    // does for its own write tools. MCP tools (`server/tool`) keep the
    // redaction, which keeps the secret from the server.
    delete answer.updatedInput;
    if (answer.action === "allow") {
      answer.action = "ask";
      answer.reason = "secret-like value in input";
    }
  }
  if (answer.action === "allow" && read.ambiguous !== undefined) {
    answer.action = "ask";
    answer.reason = read.ambiguous;
  }
  const narrowed = narrowForControl(answer.action, inputTextFor(answer.normalizedTool, read.toolInput));
  if (narrowed.control) {
    answer.action = narrowed.action;
    answer.reason = `input names a control file (${narrowed.control})`;
  }
  if (answer.action === "allow" && answer.updatedInput !== undefined && !dialect.canRewrite) {
    return { decision: "deny", reason: `secret-like value in input that derm cannot rewrite on ${dialect.name}`, answer };
  }
  if (answer.action !== "ask") return { decision: answer.action, reason: answer.reason, answer };
  // Case 71: the agent's own prompt where it shows one, else the daemon
  // approver within the hook's time, else deny; never "no decision".
  const r = await deps.resolveAsk(answer, call, dialect.ownAsk(input));
  if (r.kind === "allow") {
    if (answer.updatedInput !== undefined && !dialect.canRewrite) {
      return { decision: "deny", reason: `secret-like value in input that derm cannot rewrite on ${dialect.name}`, answer };
    }
    return { decision: "allow", reason: r.reason, answer };
  }
  if (r.kind === "deny") return { decision: "deny", reason: r.reason, answer };
  return { decision: "ask", reason: r.reason, answer };
}

/** Handles one pre-tool input that is already parsed. */
export async function handlePre(dialect: Dialect, input: Record<string, unknown>, deps: Deps): Promise<HookResult> {
  const read = dialect.read(input, deps.env);
  if (typeof read === "string") return dialect.deny(read);
  let out: Outcome;
  if (read.deferUnlessDeny !== undefined) {
    const answer = decideCall(deps.loadPolicy(), {
      harness: dialect.id,
      tool: read.tool,
      toolInput: read.toolInput,
      ...(read.chat !== undefined ? { chat: read.chat } : {}),
      ...(read.callId !== undefined ? { toolUseId: read.callId } : {}),
    });
    delete answer.updatedInput;
    out = answer.action === "deny" ? { decision: "deny", reason: answer.reason, answer } : { decision: "allow", reason: read.deferUnlessDeny, answer };
  } else out = await decide(dialect, input, read, deps);
  await deps.postEvent({
    id: decisionId(dialect.id, read.callId),
    chatId: read.chat ?? "",
    harness: dialect.id,
    kind: "approval",
    summary: `${out.answer.normalizedTool} ${out.decision}`,
    detail: {
      tool: out.answer.normalizedTool,
      decision: read.deferUnlessDeny !== undefined && out.decision === "allow" ? "deferred" : out.decision,
      policyAction: out.answer.action,
      reason: out.reason,
      redacted: out.answer.redacted,
      ...(read.callId !== undefined ? { toolUseId: read.callId } : {}),
    },
  });
  // A deferral decides nothing (Cursor's preToolUse for an MCP call), so it
  // records no install; the hook that decides does.
  if (read.deferUnlessDeny === undefined || out.decision === "deny") {
    const call: GateCall = {
      harness: dialect.id,
      tool: read.tool,
      toolInput: read.toolInput,
      ...(read.callId !== undefined ? { toolUseId: read.callId } : {}),
    };
    for (const e of installEvents(call, out.answer, out.decision, read.chat ?? "")) await deps.postEvent(e);
  }
  if (out.decision === "deny") return dialect.deny(out.reason);
  if (out.decision === "ask") return dialect.ask(out.reason);
  return dialect.allow(out.reason, out.answer.updatedInput);
}

/** Parses stdin and handles it; every failure it can see is the dialect's deny. */
export async function runPre(dialect: Dialect, stdinText: string, env: NodeJS.ProcessEnv = process.env, deps?: Partial<Deps>): Promise<HookResult> {
  try {
    const d: Deps = { ...defaultDeps(env), ...deps };
    if (Buffer.byteLength(stdinText, "utf8") > MAX_STDIN_BYTES) return dialect.deny("hook input too large");
    let input: unknown;
    try {
      input = JSON.parse(stdinText);
    } catch {
      return dialect.deny("hook input is not JSON");
    }
    if (!isPlainObject(input)) return dialect.deny("hook input is not an object");
    return await handlePre(dialect, input, d);
  } catch (error) {
    return dialect.deny(`hook error: ${(error as Error)?.message ?? String(error)}`);
  }
}

/** Reads stdin with the size cap. */
export async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    const b = chunk as Buffer;
    size += b.length;
    chunks.push(b);
    if (size > MAX_STDIN_BYTES) break;
  }
  return Buffer.concat(chunks).toString("utf8");
}
