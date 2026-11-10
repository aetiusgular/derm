// Whose files this gate trusts (wave 5 lane V, S2 part c; lane V's request
// V-3). Canonical copy: packages/derm-claude-plugin/src/core/.
//
// A gate trusts its policy, the daemon's socket and its chat token only when
// they are owned by the right user. Run as the person, that is the person's
// own uid, as before. Run as an agents' user (`derm run` starts the harness
// as a second local user, packaging/linux/agent-user/), it is the person
// that user works for, and never the agents' user itself: anything the agent
// owns, the agent could have written. Which uid is an agents' user, and for
// whom, comes from /etc/derm/agent-users.json, trusted only when root owns
// every part of its path and no one else can write it (the rule
// crates/derm-cli/src/run/user/anchor.rs applies, and sudoers(5) applies to
// /etc/sudoers.d). A file there that cannot be trusted or read makes the
// gate trust no one, so every call asks: a broken root file is never read as
// "no agents' user".

import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from "node:fs";
import path from "node:path";

export const ANCHOR = "/etc/derm/agent-users.json";
const MAX_BYTES = 64 * 1024;

export type Owners = {
  /** The uids whose files this gate trusts; empty trusts no one. */
  uids: number[];
  /** True when this process is an agents' user. */
  agent: boolean;
  problem?: string;
};

/** What a `/etc/derm/agent-users.json` says about `uid`. `text` undefined: no file. */
export function ownersFor(uid: number, text: string | undefined): Owners {
  if (text === undefined) return { uids: [uid], agent: false };
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { uids: [], agent: false, problem: `${ANCHOR} is not JSON` };
  }
  const p = parsed as { version?: unknown; agents?: unknown };
  if (p === null || typeof p !== "object" || p.version !== 1 || !Array.isArray(p.agents)) {
    return { uids: [], agent: false, problem: `${ANCHOR} is not version 1` };
  }
  const mine: number[] = [];
  for (const e of p.agents as unknown[]) {
    const a = e as { uid?: unknown; ownerUid?: unknown };
    if (a === null || typeof a !== "object" || !Number.isInteger(a.uid) || !Number.isInteger(a.ownerUid)) {
      return { uids: [], agent: false, problem: `${ANCHOR} has an entry without numeric uids` };
    }
    if (a.uid === uid) mine.push(a.ownerUid as number);
  }
  if (mine.length === 0) return { uids: [uid], agent: false };
  if (mine.length > 1) return { uids: [], agent: true, problem: `${ANCHOR} names uid ${uid} for more than one owner` };
  const owner = mine[0] as number;
  if (owner === uid || owner === 0) return { uids: [], agent: true, problem: `${ANCHOR} names an owner that separates nothing` };
  return { uids: [owner], agent: true };
}

/**
 * The file's text, `undefined` when it is not there, or the reason it cannot
 * be trusted. `from` and `trusted` are for tests: outside them every part of
 * the path from `/` must be root's.
 */
export function readAnchor(file: string = ANCHOR, from: string = "/", trusted: number = 0): string | undefined | { problem: string } {
  try {
    lstatSync(file);
  } catch (err) {
    if ((err as { code?: string }).code === "ENOENT" || (err as { code?: string }).code === "ENOTDIR") return undefined;
    return { problem: `${file} cannot be read` };
  }
  const rel = path.relative(from, file);
  if (rel.startsWith("..") || path.isAbsolute(rel)) return { problem: `${file} is not under ${from}` };
  const parts = [from];
  let at = from;
  for (const c of rel.split(path.sep).filter(Boolean)) {
    at = path.join(at, c);
    parts.push(at);
  }
  for (const p of parts) {
    let st;
    try {
      st = lstatSync(p);
    } catch {
      return { problem: `${p} cannot be read` };
    }
    if (st.isSymbolicLink()) return { problem: `${p} is a link` };
    if (st.uid !== trusted) return { problem: `${p} is not owned by uid ${trusted}` };
    if ((st.mode & 0o022) !== 0) return { problem: `${p} can be written by group or others` };
  }
  let fd: number | undefined;
  try {
    fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW);
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > MAX_BYTES) return { problem: `${file} is not a small regular file` };
    const buf = Buffer.alloc(st.size);
    let read = 0;
    while (read < st.size) {
      const n = readSync(fd, buf, read, st.size - read, read);
      if (n === 0) break;
      read += n;
    }
    return buf.subarray(0, read).toString("utf8");
  } catch {
    return { problem: `${file} cannot be read` };
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

let cached: Owners | undefined;

/** This process's trusted owners; read once (a hook lives for one call). */
export function trustedOwners(): Owners | undefined {
  if (typeof process.getuid !== "function") return undefined;
  if (cached) return cached;
  const uid = process.getuid();
  const text = readAnchor();
  cached = typeof text === "object" ? { uids: [], agent: false, problem: text.problem } : ownersFor(uid, text);
  return cached;
}

/** For tests only: what `trustedOwners` returns (undefined: read again). */
export function _setOwnersForTest(o: Owners | undefined): void {
  cached = o;
}

/** Whether a file owned by `uid` is trusted (true where uids are not kept). */
export function ownedByTrusted(uid: number): boolean {
  const o = trustedOwners();
  return o === undefined || o.uids.includes(uid);
}
