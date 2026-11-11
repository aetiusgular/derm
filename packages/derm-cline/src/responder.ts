// The approval-file responder (T2.7): answers the request files Cline writes
// when it runs with `CLINE_TOOL_APPROVAL_MODE=desktop` and
// `CLINE_TOOL_APPROVAL_DIR=<folder>`. `derm run cline` (wave 4 lane R) starts
// it beside Cline with the same folder: `node bin/derm-cline-approvals.mjs
// --dir <folder> [--cwd <session folder>] [--until-pid <pid>]`.
//
// Cline 3.0.74's side (sdk/packages/core/src/runtime/tools/tool-approval.ts):
// - it writes `<sessionId>.request.<requestId>.json` (pretty JSON, :54-72),
//   with `requestId` the tool call id with every run of characters outside
//   `[a-zA-Z0-9._-]` made `_` (:13-15, 43);
// - it polls `<sessionId>.decision.<requestId>.json` every 200 ms, reads
//   `{approved, reason?}`, takes only `approved === true` as yes, and deletes
//   both files (:74-92); a file it cannot parse is skipped and read again
//   (:93-95), so a decision is written to a temporary name and renamed;
// - with no decision in 5 minutes it deletes the request and denies (:98-101).
// So a responder that is not running, or cannot answer, is a deny: this part
// fails closed. In 3.0.74 a prompt run never writes a request (the status doc,
// Look out for): the plugin (plugin.ts) is the gate that runs today.
//
// The folder must be yours, readable by you alone, not a link, and outside
// the session folder (the same rules as the chat token file, core/daemon.ts
// chatToken). Request files are read without following links and must be
// yours. The agent runs as you and its shell has the folder's name in
// CLINE_TOOL_APPROVAL_DIR, so it can write a decision of its own: a decision
// file derm did not write is recorded as a conflict and replaced by derm's
// answer when the request is still waiting (rules case 98; plans/parallel/
// tk_lane_P.md, Open security items).

import { randomUUID } from "node:crypto";
import { closeSync, constants, fstatSync, lstatSync, openSync, readdirSync, readSync, renameSync, unlinkSync, writeSync } from "node:fs";
import path from "node:path";
import { insideFolder } from "./core/policy.ts";
import { answerRequest, defaultDeps, HARNESS, type ApprovalAnswer, type ApprovalRequest, type Deps } from "./cline.ts";
import { event } from "./serve/client.ts";

/** The folder name `derm run cline` gives the approval folder; a control path in control.ts. */
export const APPROVAL_FOLDER_NAME = "cline-approvals";
export const POLL_MS = 100;
export const MAX_REQUEST_BYTES = 1024 * 1024;
export const MAX_IN_FLIGHT = 64;
/** How long a request file that does not parse is read again before it is denied: Cline writes it with a plain writeFile. */
export const PARTIAL_GRACE_MS = 2000;

const TOKEN = /^[A-Za-z0-9._-]+$/;

/** Why `dir` cannot be the approval folder, or undefined when it can. */
export function folderProblem(dir: string, cwd: string): string | undefined {
  if (!path.isAbsolute(dir)) return "the approval folder is not an absolute path";
  if (insideFolder(dir, cwd)) return "the approval folder is inside the session folder, which a project can set";
  let st;
  try {
    st = lstatSync(dir);
  } catch {
    return "the approval folder does not exist";
  }
  if (st.isSymbolicLink()) return "the approval folder is a link";
  if (!st.isDirectory()) return "the approval folder is not a folder";
  if (typeof process.getuid === "function" && st.uid !== process.getuid()) return "the approval folder is owned by another user";
  if ((st.mode & 0o077) !== 0) return "the approval folder can be read or written by others (it must be 0700)";
  return undefined;
}

/** The session and request ids in a request file's name, or undefined when the name is not one. */
export function parseRequestName(name: string): { sessionId: string; requestId: string } | undefined {
  if (!name.endsWith(".json")) return undefined;
  const at = name.indexOf(".request.");
  if (at <= 0) return undefined;
  const sessionId = name.slice(0, at);
  const requestId = name.slice(at + ".request.".length, -".json".length);
  if (!TOKEN.test(sessionId) || !TOKEN.test(requestId)) return undefined;
  return { sessionId, requestId };
}

export function decisionName(sessionId: string, requestId: string): string {
  return `${sessionId}.decision.${requestId}.json`;
}

type ReadResult = ({ request: ApprovalRequest } | { partial: string } | { refuse: string }) & { identity?: string } | { gone: true };

/** A file's identity at one moment: device, inode, change time and size. A request rewritten in place gets a new one. */
export function identityOf(st: { dev: number; ino: number; mtimeMs: number; ctimeMs: number; size: number }): string {
  return `${st.dev}:${st.ino}:${st.mtimeMs}:${st.ctimeMs}:${st.size}`;
}

/** The identity of the file at `file` now, not following a link, or undefined when it is gone. */
export function currentIdentity(file: string): string | undefined {
  try {
    return identityOf(lstatSync(file));
  } catch {
    return undefined;
  }
}

/** Reads one request file: a regular file of yours, not a link, at most 1 MiB, as JSON. */
export function readRequest(file: string): ReadResult {
  let fd: number;
  try {
    fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return { gone: true };
    return { refuse: code === "ELOOP" ? "the request file is a link" : `cannot open the request file (${code ?? "error"})` };
  }
  try {
    const st = fstatSync(fd);
    const identity = identityOf(st);
    if (!st.isFile()) return { refuse: "the request file is not a regular file", identity };
    if (typeof process.getuid === "function" && st.uid !== process.getuid()) return { refuse: "the request file is owned by another user", identity };
    if (st.size > MAX_REQUEST_BYTES) return { refuse: "the request file is over 1 MiB", identity };
    const buf = Buffer.alloc(st.size);
    let off = 0;
    while (off < st.size) {
      const n = readSync(fd, buf, off, st.size - off, off);
      if (n === 0) break;
      off += n;
    }
    const text = buf.subarray(0, off).toString("utf8");
    try {
      const parsed = JSON.parse(text) as unknown;
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return { refuse: "the request file is not a JSON object", identity };
      return { request: parsed as ApprovalRequest, identity };
    } catch {
      return { partial: "the request file does not parse yet", identity };
    }
  } finally {
    closeSync(fd);
  }
}

/**
 * Writes a decision under a temporary name (created new, 0600, never through a
 * link) and renames it into place, so Cline never reads half a file. Returns
 * true when a decision file was already there that derm did not write.
 */
export function writeDecision(dir: string, sessionId: string, requestId: string, answer: ApprovalAnswer, ours: ReadonlySet<string>): { foreign: boolean } {
  const name = decisionName(sessionId, requestId);
  const target = path.join(dir, name);
  let foreign = false;
  try {
    lstatSync(target);
    foreign = !ours.has(name);
  } catch {
    foreign = false;
  }
  const tmp = path.join(dir, `.derm-${randomUUID()}.tmp`);
  const fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    const body = Buffer.from(`${JSON.stringify(answer)}\n`, "utf8");
    let off = 0;
    while (off < body.length) off += writeSync(fd, body, off, body.length - off);
  } finally {
    closeSync(fd);
  }
  try {
    renameSync(tmp, target);
  } catch (error) {
    try {
      unlinkSync(tmp);
    } catch {
      // Gone already.
    }
    throw error;
  }
  return { foreign };
}

export type ResponderOptions = {
  dir: string;
  cwd: string;
  deps: Deps;
  log?: (line: string) => void;
  now?: () => number;
};

/** A decision derm wrote that Cline has not taken this long after is removed: no Cline is waiting on it (it polls every 200 ms). */
export const UNTAKEN_MS = 2000;

/**
 * Watches one approval folder and answers each request once.
 *
 * Against an agent that writes in the folder (lane P review, P-S5, P-S8): a
 * request is answered per identity (inode, times, size), so one rewritten
 * in place is a new request; the request is checked again just before the
 * answer is written, and an answer is not written for a request that changed
 * or went in the meantime; a decision no Cline takes within UNTAKEN_MS is
 * removed, so an answer to a planted request does not wait for a real one of
 * the same name; the folder's own identity is fixed at start and checked
 * again before every write. Each of these is recorded as a conflict. None of
 * it stops an agent that writes a decision first: the folder is the agent's
 * to write, and only a boundary keeps it out.
 */
export class Responder {
  readonly dir: string;
  readonly cwd: string;
  private readonly deps: Deps;
  private readonly log: (line: string) => void;
  private readonly now: () => number;
  /** Request name to the identity answered (or being answered), or to when a partial file was first seen. */
  private readonly seen = new Map<string, { identity?: string; firstSeen: number; answered: boolean }>();
  private readonly inFlight = new Set<string>();
  /** Decision file names derm wrote and Cline has not taken yet, with when. */
  private readonly ours = new Map<string, number>();
  private folderIdentity: string | undefined;
  private timer: NodeJS.Timeout | undefined;
  private ticking = false;
  stopped: string | undefined;
  readonly pending: Promise<void>[] = [];

  constructor(opts: ResponderOptions) {
    this.dir = opts.dir;
    this.cwd = opts.cwd;
    this.deps = opts.deps;
    this.log = opts.log ?? ((line) => process.stderr.write(`${line}\n`));
    this.now = opts.now ?? (() => Date.now());
  }

  /** Checks the folder; then polls it every POLL_MS until stop(). */
  start(): string | undefined {
    const problem = this.checkFolder();
    if (problem) return problem;
    this.timer = setInterval(() => void this.tick(), POLL_MS);
    return undefined;
  }

  stop(reason = "stopped"): void {
    this.stopped = reason;
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
  }

  /** The folder's rules, and that it is still the folder first checked (by device and inode). */
  private checkFolder(): string | undefined {
    const problem = folderProblem(this.dir, this.cwd);
    if (problem) return problem;
    let st;
    try {
      st = lstatSync(this.dir);
    } catch {
      return "the approval folder does not exist";
    }
    const id = `${st.dev}:${st.ino}`;
    if (this.folderIdentity === undefined) this.folderIdentity = id;
    else if (this.folderIdentity !== id) return "the approval folder was replaced";
    return undefined;
  }

  /** One pass over the folder. Public for tests. */
  async tick(): Promise<void> {
    if (this.stopped || this.ticking) return;
    this.ticking = true;
    try {
      const problem = this.checkFolder();
      if (problem) {
        // A folder replaced or opened to others: stop answering. Cline then
        // denies every waiting call after 5 minutes.
        this.log(`derm-cline-approvals: ${problem}; no longer answering`);
        this.stop(problem);
        return;
      }
      let names: string[];
      try {
        names = readdirSync(this.dir);
      } catch (error) {
        this.log(`derm-cline-approvals: cannot list the approval folder (${(error as NodeJS.ErrnoException).code ?? "error"})`);
        return;
      }
      const present = new Set(names);
      for (const name of [...this.seen.keys()]) if (!present.has(name) && !this.inFlight.has(name)) this.seen.delete(name);
      for (const [name, at] of [...this.ours]) {
        if (!present.has(name)) this.ours.delete(name);
        else if (this.now() - at > UNTAKEN_MS) await this.removeUntaken(name);
      }
      for (const name of names) {
        const ids = parseRequestName(name);
        if (!ids || this.inFlight.has(name)) continue;
        const state = this.seen.get(name);
        if (state?.answered && state.identity === currentIdentity(path.join(this.dir, name))) continue;
        this.handle(name, ids, state && !state.answered ? state.firstSeen : this.now());
      }
    } finally {
      this.ticking = false;
    }
  }

  private async removeUntaken(name: string): Promise<void> {
    this.ours.delete(name);
    try {
      unlinkSync(path.join(this.dir, name));
    } catch {
      return;
    }
    this.log(`derm-cline-approvals: removed an answer no Cline took (${name})`);
    await this.recordConflict(undefined, "derm's answer was not taken within 2 s, so no Cline was waiting on that request (a planted request?); derm removed the answer");
  }

  private handle(name: string, ids: { sessionId: string; requestId: string }, firstSeen: number): void {
    const file = path.join(this.dir, name);
    const read = readRequest(file);
    // A refused file that could not be opened (a link) carries no identity
    // from its open: take it from the name, without following the link.
    if (!("gone" in read) && read.identity === undefined) {
      const id = currentIdentity(file);
      if (id !== undefined) read.identity = id;
    }
    if ("gone" in read) {
      this.seen.delete(name);
      return;
    }
    if ("partial" in read && this.now() - firstSeen < PARTIAL_GRACE_MS) {
      this.seen.set(name, { firstSeen, answered: false });
      return;
    }
    this.seen.set(name, { ...(read.identity !== undefined ? { identity: read.identity } : {}), firstSeen, answered: true });
    this.inFlight.add(name);
    const work = (async () => {
      let answer: ApprovalAnswer;
      if (this.inFlight.size > MAX_IN_FLIGHT) answer = { approved: false, reason: "derm: too many approval requests at once" };
      else if ("refuse" in read) answer = { approved: false, reason: `derm: ${read.refuse}` };
      else if ("partial" in read) answer = { approved: false, reason: `derm: ${read.partial}` };
      else if (read.request.sessionId !== ids.sessionId || read.request.requestId !== ids.requestId) {
        answer = { approved: false, reason: "derm: the request file does not match its name" };
      } else {
        answer = await answerRequest(read.request, this.deps);
      }
      const req = "request" in read ? read.request : undefined;
      // The request may have changed or gone while derm decided (an ask can
      // take its whole timeout). Write nothing for a request derm did not read.
      const now = currentIdentity(file);
      if (now === undefined) {
        this.log(`derm-cline-approvals: ${ids.requestId} was taken before derm answered`);
        await this.recordConflict(req, "the request was gone before derm answered: Cline took another answer, or gave up");
        return;
      }
      if (now !== read.identity) {
        this.log(`derm-cline-approvals: ${ids.requestId} changed while derm decided; answering it again`);
        this.seen.delete(name);
        return;
      }
      const folder = this.checkFolder();
      if (folder) {
        this.log(`derm-cline-approvals: ${folder}; no longer answering`);
        this.stop(folder);
        return;
      }
      try {
        const { foreign } = writeDecision(this.dir, ids.sessionId, ids.requestId, answer, new Set(this.ours.keys()));
        this.ours.set(decisionName(ids.sessionId, ids.requestId), this.now());
        this.log(`derm-cline-approvals: ${ids.requestId} ${answer.approved ? "allow" : "deny"}${foreign ? " (replaced a decision derm did not write)" : ""}`);
        if (foreign) await this.recordConflict(req, "a decision file derm did not write was waiting for this request; derm replaced it with its own answer, which Cline may not have read first");
      } catch (error) {
        this.log(`derm-cline-approvals: cannot write the decision for ${ids.requestId} (${(error as NodeJS.ErrnoException).code ?? (error as Error).message}); Cline denies it after 5 minutes`);
      }
    })().finally(() => this.inFlight.delete(name));
    this.pending.push(work);
  }

  /** A conflict record. The chat is `DERM_CHAT_ID` only, never the request file's (P-S5). */
  private async recordConflict(req: ApprovalRequest | undefined, reason: string): Promise<void> {
    await event(this.deps.serve(), {
      id: `${HARNESS}-approval-file-conflict-${randomUUID().replace(/-/g, "")}`,
      chatId: this.deps.env.DERM_CHAT_ID?.trim() ?? "",
      kind: "approval",
      summary: "approval file conflict",
      detail: {
        decision: "conflict",
        reason,
        via: "approval-file",
        ...(typeof req?.toolCallId === "string" ? { toolUseId: req.toolCallId.slice(0, 128) } : {}),
      },
    });
  }
}

type Args = { dir?: string; cwd?: string; untilPid?: number; error?: string };

export function parseArgs(argv: readonly string[]): Args {
  const out: Args = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const v = argv[i + 1];
    if (a === "--dir" && v !== undefined) {
      out.dir = v;
      i++;
    } else if (a === "--cwd" && v !== undefined) {
      out.cwd = v;
      i++;
    } else if (a === "--until-pid" && v !== undefined && /^[1-9][0-9]{0,9}$/.test(v)) {
      out.untilPid = Number(v);
      i++;
    } else return { error: `unknown or incomplete argument: ${a}` };
  }
  return out;
}

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

/** The command: answers until SIGTERM, SIGINT or SIGHUP, or until `--until-pid` exits. Exit 0 on a stop, 1 when it cannot start. */
export async function main(argv: readonly string[], env: NodeJS.ProcessEnv = process.env): Promise<number> {
  const args = parseArgs(argv);
  const log = (line: string) => process.stderr.write(`${line}\n`);
  if (args.error) {
    log(`derm-cline-approvals: ${args.error}`);
    return 1;
  }
  const dir = args.dir ?? env.CLINE_TOOL_APPROVAL_DIR?.trim();
  if (!dir) {
    log("derm-cline-approvals: name the approval folder with --dir or CLINE_TOOL_APPROVAL_DIR");
    return 1;
  }
  const cwd = path.resolve(args.cwd ?? process.cwd());
  const responder = new Responder({ dir, cwd, deps: defaultDeps(env, () => cwd), log });
  const problem = responder.start();
  if (problem) {
    log(`derm-cline-approvals: ${problem}`);
    return 1;
  }
  log(`derm-cline-approvals: answering in ${dir}`);
  return await new Promise<number>((resolve) => {
    const finish = (why: string) => {
      responder.stop(why);
      clearInterval(watch);
      void Promise.allSettled(responder.pending).then(() => resolve(0));
    };
    for (const sig of ["SIGTERM", "SIGINT", "SIGHUP"] as const) process.once(sig, () => finish(sig));
    const watch = setInterval(() => {
      if (responder.stopped) {
        clearInterval(watch);
        resolve(1);
      } else if (args.untilPid !== undefined && !alive(args.untilPid)) finish("the agent exited");
    }, 500);
  });
}

