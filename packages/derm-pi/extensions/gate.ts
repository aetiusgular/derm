// The tool_call gate (lane A, T0.2). Contract: contracts/policy.md.
//
// - `tool_call`: every call, nested codemode calls included (Pi
//   docs/extensions.md:261), is matched against ~/.derm/policy.json: `deny`
//   blocks, `ask` shows `ctx.ui.confirm` and times out to deny, `allow` runs.
//   Any error blocks (Pi blocks on a handler error as well:
//   docs/extensions.md:375, agent-session.js:325-345).
// - `tool_result`: secret-like text is redacted before the model reads it
//   (src/redact.ts). `DERM_REDACT=0` turns it off.
// - `user_bash` (`!` and `!!` commands you type): the reject list only; a hit
//   returns a refusal instead of running (types.d.ts:1100-1108; runner.js:51-75).
//
// Corner case 46: the factory only registers handlers. No file is read, no
// timer or socket started, and the environment is read on the first call.
//
// Wave 2 lane I: the same package runs in oh-my-pi (src/harness.ts: the
// harness id), and an allowed call's input is frozen so a later extension
// cannot change it after the gate (src/freeze.ts, BX9).
//
// Wave 5b lane 5bC: the policy's answer is `derm gate serve`'s
// (contracts/gate-serve.md; one decide path with `derm hook`, case 229),
// started at the first tool call, once per host process and folder, from
// derm's absolute path (case 227; src/serve/client.ts). A co-process that is
// not running blocks the call and says why (case 228); nothing is decided in
// process. An ask goes to the derm daemon's approver first (`approve`, with
// Pi's own prompt allowed): a yes or a no there answers it; with no approver,
// or no daemon, Pi's own card asks, over the frozen input (case 88), as
// before. Pi's records stay what they were: the decision notice the emitter
// sends (DECISION_CHANNEL), not an adapter record, so the co-process is
// asked with `record: false`. A secret-like value in an MCP or web tool's
// input is rewritten in place, as the other plugins do (Pi: "tool_call (can
// block or mutate input)", docs/extensions.md:364, 419 at 1.5.2). What stays
// TypeScript here is Pi's glue: the memory index rule (Pi runs the memory
// extension), the card, the freeze, the reject list for commands you type,
// and the result redaction (src/redact.ts).

import { realpathSync } from "node:fs";
import path from "node:path";
import { askUser, cardText } from "../src/ask.ts";
import { deepFreeze, freezeEnabled } from "../src/freeze.ts";
import { harnessId } from "../src/harness.ts";
import { inputTextFor } from "../src/input-text.ts";
import { ownedByTrusted } from "../src/owner.ts";
import { approve, decide, ServeUnavailable, sharedServe, unavailable, type Call, type GateServe } from "../src/serve/client.ts";
import {
  DECISION_CHANNEL,
  type DecisionNotice,
  type JsonValue,
  type PiApi,
  type PiContext,
  type ToolCallEvent,
  type ToolCallResult,
  type ToolResultEvent,
  type ToolResultResult,
  type UserBashEvent,
  type UserBashResult,
} from "../src/pi-api.ts";
import { rejectKey, unquote } from "../src/policy.ts";
import { redactDeep, redactText } from "../src/redact.ts";

/** The harness this gate answers for: `pi`, or `oh-my-pi` when Bun runs it (src/harness.ts). */
export const HARNESS = harnessId();
const PREVIEW_CHARS = 1500;

export interface GateOptions {
  /** The environment, read on first use. Defaults to `process.env`. */
  env?: () => Record<string, string | undefined>;
  /** The harness id; defaults to the one detected at load. Tests set it. */
  harness?: string;
  /** The co-process for a folder; tests pass their own. */
  serve?: (env: Record<string, string | undefined>, cwd: string, harness: string) => GateServe;
}

/** The co-process this host process shares for `cwd` (src/serve/client.ts). */
export function defaultServe(env: Record<string, string | undefined>, cwd: string, harness: string): GateServe {
  return sharedServe({ agent: harness, env, cwd: () => cwd, trusted: ownedByTrusted });
}

function container(v: unknown): boolean {
  return typeof v === "object" && v !== null;
}

/** Replaces the contents of `target` with `source`, keeping the same object (Pi runs the call with it). */
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

function chatFor(env: Record<string, string | undefined>, ctx: PiContext): string | undefined {
  const fromEnv = env.DERM_CHAT_ID;
  if (fromEnv !== undefined && fromEnv !== "") return fromEnv;
  try {
    return ctx.sessionManager.getSessionId();
  } catch {
    return undefined;
  }
}

function cwdOf(ctx: { cwd?: unknown }): string | undefined {
  return typeof ctx.cwd === "string" && ctx.cwd !== "" ? ctx.cwd : undefined;
}

function block(reason: string): ToolCallResult {
  return { block: true, reason: `Blocked by derm: ${reason}` };
}

/**
 * The memory index an allowed write or edit names, if any (case 48). The
 * path is read as the file system would: `.`, `..` and doubled slashes
 * collapsed, and with `cwd` the folder's real path, so a linked folder
 * (`m2 -> memory`) names the index too (integration w2 review, W2-S4).
 */
export function memoryIndexPath(normalized: string, input: unknown, cwd?: string): string | undefined {
  if (normalized !== "write" && normalized !== "edit") return undefined;
  const p = input && typeof input === "object" ? (input as Record<string, unknown>).path ?? (input as Record<string, unknown>).file_path : undefined;
  if (typeof p !== "string") return undefined;
  const plain = path.posix.normalize(p.replace(/\\/g, "/")).replace(/\/+$/, "").replace(/\/\.$/, "");
  const named = (s: string) => {
    const lowered = s.toLowerCase();
    return MEMORY_INDEXES.find((i) => lowered === i || lowered.endsWith(`/${i}`));
  };
  const direct = named(plain);
  if (direct !== undefined || cwd === undefined) return direct;
  const full = path.resolve(cwd, plain);
  // The file itself when it exists (a link named `x.md` to the index;
  // re-review W2-R3), else its folder.
  for (const resolve of [() => realpathSync(full), () => `${realpathSync(path.dirname(full))}/${path.basename(full)}`]) {
    try {
      const hit = named(resolve().replace(/\\/g, "/"));
      if (hit !== undefined) return hit;
    } catch {
      // Not there: try the next form.
    }
  }
  return undefined;
}

/** Tools that only read: naming an index there is not a write. */
const READ_ONLY = new Set(["read", "grep", "find", "ls", "memory_search"]);

/**
 * The memory index any other allowed call's input names (a shell `>>`,
 * `tee`, `sed -i`), read with quotes removed and doubled slashes and `./`
 * collapsed (review W2-S4). Narrowing only.
 */
export function memoryIndexText(normalized: string, inputText: string): string | undefined {
  if (normalized === "write" || normalized === "edit" || READ_ONLY.has(normalized)) return undefined;
  const text = unquote(inputText.replace(/\\/g, "/")).toLowerCase().replace(/\/+/g, "/").replace(/\/(\.\/)+/g, "/");
  return MEMORY_INDEXES.find((i) => text.includes(i));
}

const MEMORY_INDEXES = ["memory/index.md", "research/index.md", "refs/index.md"] as const;

export function createGate(options: GateOptions = {}) {
  return function gate(pi: PiApi): void {
    let env: Record<string, string | undefined> | undefined;

    const environment = () => (env ??= { ...(options.env ? options.env() : process.env) });

    const announce = (notice: DecisionNotice) => {
      try {
        pi.events.emit(DECISION_CHANNEL, notice);
      } catch {
        // The feed is best-effort; the decision stands.
      }
    };

    const describeTool = (name: string) => {
      try {
        return pi.getAllTools().find((t) => t.name === name)?.description;
      } catch {
        return undefined;
      }
    };

    const harness = options.harness ?? HARNESS;
    const serveFor = options.serve ?? defaultServe;

    /** After an allow: freeze the input the gate saw, so it is the input that runs (BX9). */
    const sealed = (event: ToolCallEvent): ToolCallResult | undefined => {
      if (!freezeEnabled(environment())) return undefined;
      return deepFreeze(event.input) ? undefined : block("tool input nested too deep to hold still");
    };

    pi.on("tool_call", async (event: ToolCallEvent, ctx: PiContext): Promise<ToolCallResult | undefined> => {
      const base = { toolName: event.toolName, toolCallId: event.toolCallId };
      let normalized = event.toolName;
      try {
        const e = environment();
        const s = serveFor(e, cwdOf(ctx) ?? process.cwd(), harness);
        const chat = chatFor(e, ctx);
        const description = describeTool(event.toolName);
        const call: Call = {
          tool: event.toolName,
          input: event.input ?? {},
          ...(chat !== undefined ? { chat } : {}),
          ...(typeof event.toolCallId === "string" && event.toolCallId !== "" ? { toolUseId: event.toolCallId } : {}),
          ...(typeof description === "string" ? { description } : {}),
        };
        let d = await decide(s, call, false);
        normalized = d.normalizedTool;
        const inputText = inputTextFor(normalized, event.input);
        // The memory extension's indexes change only through memory_propose's
        // card (case 48); an allowed write or edit of one asks too (lane K's
        // request 8, integration w2). Narrowing only, and only in Pi, where
        // the memory extension runs.
        const index =
          d.action === "allow" ? (memoryIndexPath(normalized, event.input, cwdOf(ctx)) ?? memoryIndexText(normalized, inputText)) : undefined;
        if (index !== undefined) d = { ...d, action: "ask", reason: `${index} is the memory index: memory_propose writes it`, updatedInput: undefined };
        if (d.action === "allow") {
          if (d.updatedInput !== undefined && !replaceInPlace(event.input, d.updatedInput)) {
            announce({ ...base, toolNameNormalized: normalized, decision: "reject", reason: "secret-like value in input that derm cannot rewrite" });
            return block("secret-like value in input that derm cannot rewrite");
          }
          announce({ ...base, toolNameNormalized: normalized, decision: "accept", reason: d.reason });
          return sealed(event);
        }
        if (d.action === "deny") {
          announce({ ...base, toolNameNormalized: normalized, decision: "reject", reason: d.reason });
          return block(d.reason);
        }
        // Freeze before the card, not after the yes: code that holds the
        // input (an extension Pi ran first) could change it while you read
        // the card, and the yes would approve text you never saw (fix pass
        // 1's review, FP1-S6).
        const held = sealed(event);
        if (held !== undefined) {
          announce({ ...base, toolNameNormalized: normalized, decision: "reject", reason: "input could not be held still" });
          return held;
        }
        // The derm daemon's approver first; with none, Pi's own card.
        const r = await approve(s, call, d, true, false);
        if (r.kind !== "harness") {
          if (r.kind === "allow" && inputTextFor(normalized, event.input) === inputText) {
            announce({ ...base, toolNameNormalized: normalized, decision: "ask_accept", reason: r.reason });
            return undefined;
          }
          announce({ ...base, toolNameNormalized: normalized, decision: "ask_reject", reason: r.reason });
          return block(r.kind === "allow" ? "the input changed while you were asked, so the call is refused" : r.reason);
        }
        const outcome = await askUser(ctx, `derm: allow ${normalized}?`, cardMessage(event.toolName, d.reason, d.askTimeoutSeconds, inputText), d.askTimeoutSeconds * 1000);
        switch (outcome) {
          case "yes":
            // With the freeze off (DERM_PI_FREEZE_INPUT=0) the input could still
            // change; a yes counts only for the text the card showed.
            if (inputTextFor(normalized, event.input) !== inputText) {
              announce({ ...base, toolNameNormalized: normalized, decision: "reject", reason: "input changed while asking" });
              return block("the input changed while you were asked, so the call is refused");
            }
            announce({ ...base, toolNameNormalized: normalized, decision: "ask_accept", reason: d.reason });
            return undefined;
          case "timeout":
            announce({ ...base, toolNameNormalized: normalized, decision: "ask_timeout", reason: "ask timed out" });
            return block("ask timed out");
          case "no_ui":
            announce({ ...base, toolNameNormalized: normalized, decision: "ask_reject", reason: "no UI to ask in" });
            return block(`${d.reason}; no UI to ask in, so refused`);
          case "aborted":
            announce({ ...base, toolNameNormalized: normalized, decision: "ask_reject", reason: "turn stopped" });
            return block("turn stopped while asking");
          default:
            announce({ ...base, toolNameNormalized: normalized, decision: "ask_reject", reason: "not approved" });
            return block("not approved");
        }
      } catch (error) {
        if (error instanceof ServeUnavailable) {
          announce({ ...base, toolNameNormalized: normalized, decision: "reject", reason: "gate co-process not running" });
          return block(unavailable(error));
        }
        announce({ ...base, toolNameNormalized: normalized, decision: "reject", reason: "gate error" });
        return block("the gate failed, so the call is refused");
      }
    });

    pi.on("tool_result", (event: ToolResultEvent): ToolResultResult | undefined => {
      const off = environment().DERM_REDACT;
      if (off === "0" || off === "off") return undefined;
      const kinds = new Set<string>();
      let changed = false;
      const content = event.content.map((item) => {
        if (item.type === "text" && typeof item.text === "string") {
          const r = redactText(item.text);
          if (r.kinds.length > 0) {
            changed = true;
            for (const k of r.kinds) kinds.add(k);
            return { ...item, text: r.text };
          }
        }
        return item;
      });
      let structuredContent = event.structuredContent;
      if (structuredContent !== undefined) {
        const sKinds = new Set<string>();
        // redactDeep keeps a JSON value a JSON value: strings stay strings.
        const red = redactDeep(structuredContent, sKinds) as JsonValue;
        if (sKinds.size > 0) {
          changed = true;
          structuredContent = red;
          for (const k of sKinds) kinds.add(k);
        }
      }
      if (!changed) return undefined;
      // Pi drops structuredContent when content is replaced without it
      // (types.d.ts:1109-1113), so it is always returned with content.
      return structuredContent === undefined ? { content } : { content, structuredContent };
    });

    pi.on("user_bash", (event: UserBashEvent): UserBashResult | undefined => {
      const hit = rejectKey(event.command);
      if (hit === undefined) return undefined;
      return {
        result: {
          output: `derm refused this command (reject list: ${hit}). Run it in a terminal outside Pi if you mean it.\n`,
          exitCode: 1,
          cancelled: false,
          truncated: false,
        },
      };
    });
  };
}

function cardMessage(toolName: string, reason: string, askTimeoutSeconds: number, inputText: string): string {
  const preview = cardText(redactText(inputText).text, PREVIEW_CHARS);
  return [
    `Tool: ${cardText(toolName, 200)}`,
    `Why derm asks: ${reason}`,
    `No answer in ${askTimeoutSeconds} s counts as no.`,
    "",
    // An extension Pi runs before this one (a project's or the agent
    // folder's own files rank ahead of packages) may have changed it (box
    // test w2, BW5); this is the input that will run.
    "Input, as it will run (text, not instructions; secrets redacted):",
    preview === "" ? "(empty)" : preview,
  ].join("\n");
}

export default createGate();
