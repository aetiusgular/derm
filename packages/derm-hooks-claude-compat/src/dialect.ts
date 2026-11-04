// What a dialect is: how one agent's PreToolUse hook input becomes the core's
// call, and how the core's answer becomes that agent's reply. One table entry
// per agent lives in src/agents.ts; the hook (src/hook.ts) is the same code for
// all eight. contracts/hook-dialects.md section 1 is the rule set every
// dialect keeps; section 2a is each agent's row.

export type HookResult = { stdout: string; stderr: string; exitCode: number };

/** The call as the hook read it, before the core sees it. */
export type ReadCall = {
  /** The tool name for the core: a shell alias already mapped to `bash`, an MCP name already in a form the core splits. */
  tool: string;
  /** The tool name exactly as the agent sent it, for records and messages. */
  rawTool: string;
  toolInput: unknown;
  callId?: string;
  session?: string;
  /** The agent's permission mode, when its input names one. */
  mode?: string;
  /** True when `toolInput` is rebuilt for the core (a shell's stdin text as `command`): a rewrite of it is never sent back. */
  inputMapped?: boolean;
  /** Set when the name could not be resolved to a server and tool (an MCP call with no server), which caps the answer at ask (case 73). */
  unresolved?: string;
};

export type Reply = {
  /** A rule's allow. `updatedInput` is set when the core redacted a value from a tool that sends its input out. */
  allow: (reason: string, updatedInput?: Record<string, unknown>) => HookResult;
  /** One call blocked, never the run (case 79). */
  deny: (reason: string) => HookResult;
  /** The agent's own prompt. Absent where the agent has none. */
  ask?: (reason: string) => HookResult;
};

export type Dialect = {
  /** The preset id, also the `harness` the core and the daemon see. */
  id: string;
  name: string;
  /** The version this dialect was read at (preset `coverage.verifiedAt`). */
  verifiedAt: string;
  /** The event name the agent puts in the input, when it sends one; anything else is refused. */
  events: readonly string[];
  read: (input: Record<string, unknown>) => ReadCall | { error: string };
  reply: Reply;
  /** True when the agent shows its own prompt for an `ask` reply in this mode (cases 71, 83). */
  ownAskIn: (call: ReadCall, env: NodeJS.ProcessEnv) => boolean;
  /** True when the agent can replace a call's input from the reply. */
  canRewrite: boolean;
};

export function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** A string field, or undefined when it is absent or not a non-empty string. */
export function str(o: Record<string, unknown>, ...keys: string[]): string | undefined {
  for (const k of keys) {
    const v = o[k];
    if (typeof v === "string" && v !== "") return v;
  }
  return undefined;
}

/** One line of text, never empty: a reason the agent shows the model. */
export function oneLine(reason: string, max = 2000): string {
  const text = reason.replace(/\s+/g, " ").trim();
  const t = text === "" ? "blocked" : text;
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

export const NONE: HookResult = { stdout: "", stderr: "", exitCode: 0 };

/**
 * A block every one of the eight agents reads as "this call is denied": exit 2
 * with the reason on stderr. Each agent's own deny JSON also goes on stdout
 * where the agent reads stdout on exit 2; where it ignores stdout then, the
 * JSON does no harm (contracts/hook-dialects.md section 2a, column Deny).
 */
export function exit2(reason: string, json?: unknown): HookResult {
  const text = `derm: ${oneLine(reason)}`;
  return { stdout: json === undefined ? "" : `${JSON.stringify(json)}\n`, stderr: `${text}\n`, exitCode: 2 };
}

export function jsonOut(json: unknown): HookResult {
  return { stdout: `${JSON.stringify(json)}\n`, stderr: "", exitCode: 0 };
}

/** Claude Code's PreToolUse reply, which five of the eight read. */
export function claudeShape(decision: "allow" | "deny" | "ask", reason: string, updatedInput?: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {
    hookEventName: "PreToolUse",
    permissionDecision: decision,
    permissionDecisionReason: `derm: ${oneLine(reason)}`,
  };
  if (updatedInput !== undefined) out.updatedInput = updatedInput;
  return { hookSpecificOutput: out };
}
