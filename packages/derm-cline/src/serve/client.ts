// The client of `derm gate serve` (contracts/gate-serve.md), for the plugins
// whose hosts load JavaScript only. Canonical copy: packages/derm-pi/src/
// serve/client.ts; the other five plugins carry the same bytes (each has a
// test that says so).
//
// - derm is found by an absolute path, never on PATH (case 227): `DERM_BIN`
//   (which `derm run` sets to itself), else the places derm's own install
//   puts it (docs/install/linux.md, macos.md, Homebrew). Each candidate is
//   used only when its real path is a regular, executable file whose owner is
//   trusted, that no one else may write, in a folder no one else may write
//   (case 109's rule; "no one else" as `refuseCandidate` reads it: a group
//   write bit only for macOS's admin group when you are in it, and on macOS
//   no access list that lets anyone write; MW5B-1, MW5B-2), and outside the
//   session's folder, which a project controls. On Windows Node cannot read who may write a file (libuv
//   v1.52.1 src/win/fs.c:1956-1960; WW5-3), so only `DERM_BIN` is taken
//   there, and it is not checked: an open item (tk_lane_5bC.md).
// - The co-process starts at the first request, once per session, and is
//   asked to say hello within the start budget. Replies come in request
//   order (contract section 2); each is matched to its request's id.
// - It fails closed (case 228): a co-process that cannot start, exits,
//   writes a line that is not a reply, or does not answer in time is
//   stopped, every waiting request is rejected with the reason, and the next
//   request starts it again. The caller turns a rejection into a deny and
//   never decides in process.
//
// Node's child_process (v22): `spawn` reports a program that cannot start
// through the `error` event and an exit through `exit`; stdio pipes are
// net.Socket instances with `unref` (https://nodejs.org/docs/latest-v22.x/
// api/child_process.html). This file imports nothing from the package, so
// the copies stay byte-equal; the plugin passes its trusted-owner rule in.

import { spawn as nodeSpawn, spawnSync, type ChildProcess, type SpawnOptions } from "node:child_process";
import { lstatSync, readlinkSync, realpathSync, statSync } from "node:fs";
import os from "node:os";
import path from "node:path";

export const PROTOCOL = 1;

/** A reply the co-process wrote (contract section 2). */
export type Reply = { id: unknown; ok: boolean; error?: string; [k: string]: unknown };

/** Why the co-process could not answer: the caller denies. */
export class ServeUnavailable extends Error {
  constructor(reason: string) {
    super(reason);
    this.name = "ServeUnavailable";
  }
}

export type Located = { path: string } | { problem: string };

export interface LocateDeps {
  env: Record<string, string | undefined>;
  /** The session's folder: a derm inside it is never used. */
  cwd: string;
  platform: NodeJS.Platform;
  home: string;
  /** Whether a file owned by this uid may be trusted (root always is). */
  trusted: (uid: number) => boolean;
  stat?: (p: string) => { uid: number; gid?: number; mode: number; isFile: boolean; isDir: boolean };
  realpath?: (p: string) => string;
  /** Whether a path is itself a link, not followed (FP1-S2). */
  lstat?: (p: string) => { isLink: boolean };
  readlink?: (p: string) => string;
  /** macOS: your groups as `/usr/bin/id -G` lists them (MW5B-2). */
  groups?: () => number[] | undefined;
  /** macOS: `/bin/ls -lden` of a path, or undefined when it cannot be read (MW5B-1). */
  acl?: (p: string) => string | undefined;
}

/**
 * macOS's `admin` group. Homebrew's installer gives its prefix folders
 * `g+rwx` with this group when you are in it, and drops the group bit when
 * your group is `staff`, which other accounts share (Homebrew/install
 * install.sh at 7986efa, lines 182-192). A group write bit is trusted only
 * for this group, only on macOS, only when you are in it (MW5B-2; sudo's
 * secure_path trusts one named group the same way). derm connect and the
 * plugins' launcher read it the same way (case 112).
 */
export const MACOS_ADMIN_GID = 80;

/** The permissions macOS's `ls -le` prints that let their holder change a file or a folder (Apple file_cmds-479, ls/print.c:243-262). */
export const ACL_WRITE_PERMS = ["write", "append", "delete", "add_file", "add_subdirectory", "delete_child", "writeattr", "writeextattr", "writesecurity", "chown"];

/**
 * Whether `ls -lden`'s output for one path holds an access list entry that
 * lets anyone write (MW5B-1): each line after the first is
 * ` <n>: <uuid>[ inherited] <allow|deny> <perm,...>` (file_cmds-479,
 * ls/print.c:322-385). An entry that is not a deny and names a write-class
 * permission is open, whoever it names; a line that cannot be placed is open.
 */
export function aclGrantsWrite(ls: string): boolean {
  const lines = ls.split("\n");
  if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  return lines.slice(1).some((line) => {
    const w = line.split(/\s+/).filter((x) => x !== "");
    if (!(w[0] ?? "").endsWith(":")) return true;
    let i = 2;
    let kind = w[i];
    if (kind === "inherited") kind = w[++i];
    if (kind === undefined) return true;
    if (kind === "deny") return false;
    const perms = w[i + 1];
    return perms !== undefined && perms.split(",").some((x) => ACL_WRITE_PERMS.includes(x));
  });
}

/** `/usr/bin/id -G`'s groups, or undefined when a word is not a number. */
export function parseGroups(text: string): number[] | undefined {
  const words = text.split(/\s+/).filter((x) => x !== "");
  if (words.length === 0 || !words.every((x) => /^[0-9]+$/.test(x))) return undefined;
  return words.map(Number);
}

function idGroups(): number[] | undefined {
  const r = spawnSync("/usr/bin/id", ["-G"], { env: {}, encoding: "utf8" });
  return r.status === 0 && typeof r.stdout === "string" ? parseGroups(r.stdout) : undefined;
}

function lsAcl(p: string): string | undefined {
  const r = spawnSync("/bin/ls", ["-lden", "--", p], { env: {}, encoding: "utf8" });
  return r.status === 0 && typeof r.stdout === "string" ? r.stdout : undefined;
}

/** Where derm's own installs put it, by OS (docs/install/*.md; Homebrew's prefixes). */
export function installCandidates(platform: NodeJS.Platform, home: string): string[] {
  if (platform === "win32") return [];
  const local = path.posix.join(home, ".local", "bin", "derm");
  const brew = platform === "darwin" ? ["/opt/homebrew/bin/derm", "/usr/local/bin/derm"] : ["/home/linuxbrew/.linuxbrew/bin/derm", "/usr/local/bin/derm"];
  return [local, ...brew, "/usr/bin/derm"];
}

function realStat(p: string): { uid: number; gid?: number; mode: number; isFile: boolean; isDir: boolean } {
  const s = statSync(p);
  return { uid: s.uid, gid: s.gid, mode: s.mode, isFile: s.isFile(), isDir: s.isDirectory() };
}

function inside(file: string, folder: string): boolean {
  const rel = path.relative(folder, file);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

/**
 * Why `candidate` may not be run, or undefined when it may (case 109's
 * rule): its real path is a regular, executable file owned by a trusted
 * user or root with no group or other write bit, in a folder the same holds
 * for, the folder it is named in too, and none of it inside the session's
 * folder.
 */
export function refuseCandidate(candidate: string, d: LocateDeps): string | undefined {
  const r = examine(candidate, d);
  return "why" in r ? r.why : undefined;
}

/**
 * The file `candidate` leads to, or why it may not run. Each link is
 * followed one hop at a time, at most 8, and each hop's real folder is held
 * to the rule, as the launcher holds it (`hooks/derm-gate.sh`, `refuse`;
 * FP1-S2); the file it ends at must be named derm, as derm connect
 * registers only one, and that real path is the one started, so nothing
 * between the check and the start re-reads the links.
 */
function examine(candidate: string, d: LocateDeps): { file: string } | { why: string } {
  const stat = d.stat ?? realStat;
  const real = d.realpath ?? ((p: string) => realpathSync(p));
  const isLink = d.lstat ?? ((p: string) => ({ isLink: lstatSync(p).isSymbolicLink() }));
  const readlink = d.readlink ?? ((p: string) => readlinkSync(p));
  if (!path.isAbsolute(candidate)) return { why: "not an absolute path" };
  let file: string;
  const folders: string[] = [];
  try {
    let cur = candidate;
    for (let hops = 0; ; hops++) {
      const dir = real(path.dirname(cur));
      if (!folders.includes(dir)) folders.push(dir);
      const at = path.join(dir, path.basename(cur));
      if (!isLink(at).isLink) {
        file = at;
        break;
      }
      if (hops >= 8) return { why: "too many links" };
      const to = readlink(at);
      cur = path.isAbsolute(to) ? to : path.join(dir, to);
    }
    real(file);
  } catch {
    return { why: "not there" };
  }
  let cwdReal = d.cwd;
  try {
    cwdReal = real(d.cwd);
  } catch {
    // The session's folder as written.
  }
  if (inside(candidate, d.cwd) || inside(file, cwdReal)) return { why: "inside the session's folder, which a project can write" };
  if (d.platform === "win32") return { file: candidate };
  const owned = (uid: number) => uid === 0 || d.trusted(uid);
  const macos = d.platform === "darwin";
  let groups: number[] | undefined | null = null;
  const inAdmin = () => {
    if (groups === null) groups = (d.groups ?? idGroups)();
    return groups !== undefined && groups.includes(MACOS_ADMIN_GID);
  };
  // No other write bit; a group write bit only on a folder whose group is
  // macOS's admin when you are in it (MW5B-2; Homebrew gives the bit to
  // folders only, FP1-S8); on macOS no access list entry that lets anyone
  // write (MW5B-1), read on the same real path as the mode. On Linux the
  // group bits are an access list's mask (acl(5)), so the mode bits bound it.
  const open = (p: string, s: { gid?: number; mode: number; isDir: boolean }) => {
    if ((s.mode & 0o002) !== 0) return true;
    if ((s.mode & 0o020) !== 0 && !(s.isDir && macos && s.gid === MACOS_ADMIN_GID && inAdmin())) return true;
    if (macos) {
      const ls = (d.acl ?? lsAcl)(p);
      if (ls === undefined || aclGrantsWrite(ls)) return true;
    }
    return false;
  };
  try {
    const f = stat(file);
    if (!f.isFile) return { why: "not a regular file" };
    if (path.basename(file) !== "derm") return { why: "not named derm" };
    if ((f.mode & 0o111) === 0) return { why: "not executable" };
    if (!owned(f.uid)) return { why: "owned by someone derm does not trust" };
    if (open(file, f)) return { why: "others may write it" };
    for (const folder of folders) {
      const s = stat(folder);
      if (!s.isDir || !owned(s.uid) || open(folder, s)) return { why: `others may write ${folder}` };
    }
  } catch {
    return { why: "cannot be read" };
  }
  return { file };
}

/** The derm to start, by its real path, or why none (case 227: never PATH). */
export function locateDerm(d: LocateDeps): Located {
  const tried: string[] = [];
  const fromEnv = d.env.DERM_BIN?.trim();
  const candidates = fromEnv ? [fromEnv] : [];
  if (d.platform !== "win32") candidates.push(...installCandidates(d.platform, d.home));
  for (const c of candidates) {
    const r = examine(c, d);
    if ("file" in r) return { path: r.file };
    tried.push(`${c}: ${r.why}`);
  }
  if (candidates.length === 0) return { problem: "no derm to run: DERM_BIN is not set (derm run sets it)" };
  return { problem: `no derm derm can trust (${tried.join("; ")})` };
}

export interface ServeOptions {
  /** The harness id, `--agent`. */
  agent: string;
  env: Record<string, string | undefined>;
  /** The session's folder: the co-process starts there, so a policy inside it is refused. */
  cwd: () => string;
  trusted: (uid: number) => boolean;
  /** How long start and hello may take. */
  startMs?: number;
  /** How long any other request may take; `approve` adds its ask's timeout. */
  requestMs?: number;
  /** Tests replace these. */
  locate?: (d: LocateDeps) => Located;
  spawn?: (cmd: string, args: string[], o: SpawnOptions) => ChildProcess;
  platform?: NodeJS.Platform;
  home?: () => string;
}

type Pending = { id: number; resolve: (r: Reply) => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> };

const MAX_STDERR = 2048;
const MAX_LINE = 1024 * 1024;

export class GateServe {
  readonly options: ServeOptions;
  child: ChildProcess | undefined;
  starting: Promise<ChildProcess> | undefined;
  pending: Pending[] = [];
  nextId = 1;
  buffered = "";
  stderr = "";
  /** Why the last co-process stopped, for the next deny. */
  lastProblem: string | undefined;
  /** The `hello` reply's policy object. */
  policy: unknown;
  closed = false;

  constructor(options: ServeOptions) {
    this.options = options;
  }

  /** Sends one request and resolves with its reply; rejects with ServeUnavailable. */
  async request(op: string, body: Record<string, unknown> = {}, extraMs = 0): Promise<Reply> {
    if (this.closed) throw new ServeUnavailable("the session ended");
    const child = await this.ensure();
    return this.send(child, op, body, (this.options.requestMs ?? 5000) + extraMs);
  }

  /** Stops the co-process (session end): its stdin closes and it exits. */
  close(): void {
    this.closed = true;
    this.stop("the session ended");
  }

  private ensure(): Promise<ChildProcess> {
    if (this.child !== undefined) return Promise.resolve(this.child);
    this.starting ??= this.start().finally(() => {
      this.starting = undefined;
    });
    return this.starting;
  }

  private async start(): Promise<ChildProcess> {
    const o = this.options;
    const platform = o.platform ?? process.platform;
    const cwd = o.cwd();
    const located = (o.locate ?? locateDerm)({ env: o.env, cwd, platform, home: o.home ? o.home() : os.homedir(), trusted: o.trusted });
    if ("problem" in located) {
      this.lastProblem = located.problem;
      throw new ServeUnavailable(located.problem);
    }
    const env: Record<string, string> = {};
    for (const [k, v] of Object.entries(o.env)) if (v !== undefined) env[k] = v;
    // Each reason names the program it ran (BW5B-5: two derm builds can
    // print the same version, and the last candidate is a system derm).
    const prog = `${located.path} gate serve`;
    let child: ChildProcess;
    try {
      child = (o.spawn ?? nodeSpawn)(located.path, ["gate", "serve", "--agent", o.agent], { cwd, env, stdio: ["pipe", "pipe", "pipe"], windowsHide: true, shell: false });
    } catch (e) {
      throw this.fail(`${prog} did not start: ${(e as Error)?.message ?? String(e)}`);
    }
    this.child = child;
    this.buffered = "";
    this.stderr = "";
    child.on("error", (e: Error) => this.stop(`${prog}: ${e.message}`, child));
    child.on("exit", (code, signal) => this.stop(`${prog} exited (${signal ?? code})${this.stderr ? `: ${this.stderr.trim().split("\n").pop()}` : ""}`, child));
    child.stdin?.on("error", () => this.stop(`${prog} closed its input`, child));
    child.stdout?.setEncoding("utf8");
    child.stdout?.on("data", (chunk: string) => this.onData(chunk, child));
    child.stderr?.setEncoding("utf8");
    child.stderr?.on("data", (chunk: string) => {
      this.stderr = (this.stderr + chunk).slice(-MAX_STDERR);
    });
    // The host may exit with the co-process still running; it then reads
    // the end of its input and exits too.
    child.unref();
    for (const s of [child.stdin, child.stdout, child.stderr]) (s as unknown as { unref?: () => void } | null)?.unref?.();
    const reply = await this.send(child, "hello", { agent: o.agent, protocol: PROTOCOL }, o.startMs ?? 5000);
    if (reply.ok !== true || reply.protocol !== PROTOCOL) throw this.fail(`derm gate serve refused hello: ${String(reply.error ?? "no reason")}`, child);
    this.policy = reply.policy;
    this.lastProblem = undefined;
    return child;
  }

  private fail(reason: string, child?: ChildProcess): ServeUnavailable {
    this.stop(reason, child);
    return new ServeUnavailable(reason);
  }

  private send(child: ChildProcess, op: string, body: Record<string, unknown>, ms: number): Promise<Reply> {
    const id = this.nextId++;
    return new Promise<Reply>((resolve, reject) => {
      if (this.child !== child || child.stdin === null || child.stdin.destroyed) {
        reject(new ServeUnavailable(this.lastProblem ?? "derm gate serve is not running"));
        return;
      }
      const timer = setTimeout(() => this.stop(`derm gate serve did not answer ${op} within ${ms} ms`, child), ms);
      this.pending.push({ id, resolve, reject, timer });
      child.stdin.write(`${JSON.stringify({ ...body, id, op })}\n`);
    });
  }

  private onData(chunk: string, child: ChildProcess): void {
    if (this.child !== child) return;
    this.buffered += chunk;
    if (this.buffered.length > MAX_LINE * 2) {
      this.stop("derm gate serve wrote a line over the limit", child);
      return;
    }
    let nl: number;
    while ((nl = this.buffered.indexOf("\n")) >= 0) {
      const line = this.buffered.slice(0, nl);
      this.buffered = this.buffered.slice(nl + 1);
      if (line.trim() === "") continue;
      let reply: Reply;
      try {
        reply = JSON.parse(line) as Reply;
      } catch {
        this.stop("derm gate serve wrote a line that is not JSON", child);
        return;
      }
      const next = this.pending.shift();
      if (next === undefined || typeof reply !== "object" || reply === null || (reply.id !== next.id && reply.id !== null)) {
        if (next) this.pending.unshift(next);
        this.stop("derm gate serve answered out of order", child);
        return;
      }
      clearTimeout(next.timer);
      next.resolve(reply);
    }
  }

  /** Ends this co-process and rejects every waiting request with `reason`. */
  private stop(reason: string, child: ChildProcess | undefined = this.child): void {
    if (child === undefined || this.child !== child) return;
    this.child = undefined;
    this.lastProblem = reason;
    const waiting = this.pending;
    this.pending = [];
    for (const p of waiting) {
      clearTimeout(p.timer);
      p.reject(new ServeUnavailable(reason));
    }
    try {
      child.stdin?.end();
    } catch {
      // Already closed.
    }
    if (child.exitCode === null && child.signalCode === null) {
      try {
        child.kill();
      } catch {
        // Already gone.
      }
    }
  }
}

const REGISTRY = Symbol.for("derm.gateServe.v1");

/**
 * One co-process per agent per host process, shared by every extension of
 * the package that asks (Pi loads each extension file on its own; the
 * registry on `globalThis` keeps them to one co-process).
 */
export function sharedServe(options: ServeOptions): GateServe {
  const g = globalThis as unknown as { [REGISTRY]?: Map<string, GateServe> };
  const map = (g[REGISTRY] ??= new Map());
  const key = `${options.agent}\0${options.cwd()}`;
  let s = map.get(key);
  if (s === undefined || s.closed) {
    s = new GateServe(options);
    map.set(key, s);
  }
  return s;
}

/** The decide reply's fields (contract section 2.1). */
export type Answer = {
  action: "allow" | "ask" | "deny";
  normalizedTool: string;
  reason: string;
  updatedInput: unknown;
  redacted: number;
  askTimeoutSeconds: number;
};

/** The call a request names (contract section 2.1, `gate::core::GateCall`). */
export type Call = {
  tool: string;
  input: unknown;
  chat?: string;
  toolUseId?: string;
  fullAccess?: boolean;
  description?: string;
};

function answerOf(r: Reply): Answer {
  if (r.ok !== true) throw new ServeUnavailable(`derm gate serve refused the call: ${String(r.error ?? "no reason")}`);
  const action = r.action;
  if (action !== "allow" && action !== "ask" && action !== "deny") throw new ServeUnavailable("derm gate serve gave no action");
  return {
    action,
    normalizedTool: typeof r.normalizedTool === "string" ? r.normalizedTool : "",
    reason: typeof r.reason === "string" ? r.reason : "",
    updatedInput: r.updatedInput ?? undefined,
    redacted: typeof r.redacted === "number" ? r.redacted : 0,
    askTimeoutSeconds: typeof r.askTimeoutSeconds === "number" ? r.askTimeoutSeconds : 60,
  };
}

/** `decide`: the policy's answer (one decide path with `derm hook`, case 229). */
export async function decide(s: GateServe, call: Call, record = true): Promise<Answer> {
  return answerOf(await s.request("decide", { call, ...(record ? {} : { record: false }) }));
}

export type AskKind = { kind: "allow" | "deny" | "harness"; reason: string };

/** `approve`: an ask through the daemon's approver; anything unreadable is a deny. */
export async function approve(s: GateServe, call: Call, answer: Answer, canAsk: boolean, record = true): Promise<AskKind> {
  const r = await s.request("approve", { call, answer, canAsk, ...(record ? {} : { record: false }) }, (answer.askTimeoutSeconds + 6) * 1000);
  if (r.ok !== true) return { kind: "deny", reason: `derm gate serve refused the ask: ${String(r.error ?? "no reason")}` };
  const kind = r.kind === "allow" || r.kind === "harness" ? r.kind : "deny";
  return { kind, reason: typeof r.reason === "string" ? r.reason : "" };
}

/** `record`: the outcome a plugin settled on; never throws (records are best effort). */
export async function record(s: GateServe, call: Call, answer: Answer, decision: "allow" | "ask" | "deny", extra: { label?: string; via?: string; reason?: string; installs?: boolean; wait?: boolean } = {}): Promise<void> {
  try {
    await s.request("record", { call, answer, decision, ...extra });
  } catch {
    // The decision stands; its record is lost and the co-process restarts.
  }
}

/** `event`: a record only the plugin knows; never throws. `wait: false` queues it without waiting for the daemon. */
export async function event(s: GateServe, e: Record<string, unknown>, wait = true): Promise<void> {
  try {
    await s.request("event", { event: e, ...(wait ? {} : { wait: false }) });
  } catch {
    // Best effort.
  }
}

/** `redact`: the hook redactor over a value. Throws ServeUnavailable. */
export async function redact(s: GateServe, value: unknown): Promise<{ value: unknown; count: number }> {
  const r = await s.request("redact", { value });
  if (r.ok !== true) throw new ServeUnavailable(`derm gate serve refused redact: ${String(r.error ?? "no reason")}`);
  return { value: r.value, count: typeof r.count === "number" ? r.count : 0 };
}

/** Why calls are denied while the co-process is down, for a block reason. */
export function unavailable(e: unknown): string {
  const why = e instanceof Error ? e.message : String(e);
  return `the derm gate co-process is not running (${why}), so the call is refused`;
}
