// Lockfiles: which packages a project already pins, read from the files the
// managers write (wave 5 lane X; contracts/policy.md section 6). The gate
// keeps an `allow` for an install whose every package is already pinned at
// the same version; the daemon diffs a lockfile before and after an install
// call (crates/derm-daemon/src/installs/, derm-core's `lockfile.rs`, which
// reads the same formats and is held equal to this file by
// contracts/fixtures/installs/lockfiles/).
//
// The parsers read only names, versions and whether an entry came from the
// registry; they are line readers, not full YAML or TOML parsers, written
// against lockfiles the managers wrote on 4 Nov 2026 (npm 12.2.2, pnpm
// 12.16.1, yarn 4.18.1 and 1.22.22, bun 1.4.4, uv 0.13.7, poetry 2.5.1,
// pdm 2.29.5, cargo 1.97.0; go.sum's three fields from Go 1.24.7's
// `readGoSum`). A line they cannot read is skipped: a missed entry can only
// make the gate ask.

import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";
import path from "node:path";
import type { Manager } from "./parse.ts";

export type LockEntry = { name: string; version: string; registry: boolean };
export type LockKind = "package-lock" | "pnpm-lock" | "yarn-lock" | "bun-lock" | "uv-lock" | "poetry-lock" | "pdm-lock" | "pylock" | "cargo-lock" | "go-sum";

/** The lockfiles each manager writes, in the order a project would have them. */
export const LOCKFILES: Record<Manager, { file: string; kind: LockKind }[]> = {
  npm: [
    { file: "package-lock.json", kind: "package-lock" },
    { file: "npm-shrinkwrap.json", kind: "package-lock" },
  ],
  pnpm: [{ file: "pnpm-lock.yaml", kind: "pnpm-lock" }],
  yarn: [{ file: "yarn.lock", kind: "yarn-lock" }],
  bun: [{ file: "bun.lock", kind: "bun-lock" }],
  pip: [{ file: "pylock.toml", kind: "pylock" }],
  uv: [{ file: "uv.lock", kind: "uv-lock" }],
  poetry: [{ file: "poetry.lock", kind: "poetry-lock" }],
  pdm: [{ file: "pdm.lock", kind: "pdm-lock" }],
  pipx: [],
  cargo: [{ file: "Cargo.lock", kind: "cargo-lock" }],
  go: [{ file: "go.sum", kind: "go-sum" }],
};

export const MAX_LOCKFILE_BYTES = 16 * 1024 * 1024;

/** The entries of one lockfile's text. */
export function parseLockfile(kind: LockKind, text: string): LockEntry[] {
  switch (kind) {
    case "package-lock":
      return packageLock(text);
    case "pnpm-lock":
      return pnpmLock(text);
    case "yarn-lock":
      return yarnLock(text);
    case "bun-lock":
      return bunLock(text);
    case "uv-lock":
    case "poetry-lock":
    case "pdm-lock":
    case "cargo-lock":
      return tomlPackages(text, "[[package]]", kind);
    case "pylock":
      return tomlPackages(text, "[[packages]]", kind);
    case "go-sum":
      return goSum(text);
  }
}

/** `name@version` with the `@` that splits them past a scope's own. */
function splitAt(spec: string): [string, string] | undefined {
  const at = spec.lastIndexOf("@");
  if (at <= 0) return undefined;
  return [spec.slice(0, at), spec.slice(at + 1)];
}

function packageLock(text: string): LockEntry[] {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    return [];
  }
  if (typeof doc !== "object" || doc === null) return [];
  const out: LockEntry[] = [];
  const packages = (doc as { packages?: unknown }).packages;
  if (typeof packages === "object" && packages !== null) {
    for (const [key, v] of Object.entries(packages as Record<string, unknown>)) {
      const i = key.lastIndexOf("node_modules/");
      if (i < 0 || typeof v !== "object" || v === null) continue;
      const e = v as { version?: unknown; link?: unknown; resolved?: unknown; name?: unknown };
      if (e.link === true || typeof e.version !== "string") continue;
      const name = typeof e.name === "string" ? e.name : key.slice(i + "node_modules/".length);
      out.push({ name, version: e.version, registry: registryResolved(e.resolved) });
    }
    return out;
  }
  // lockfileVersion 1: nested `dependencies`.
  const walk = (deps: unknown, depth: number) => {
    if (depth > 64 || typeof deps !== "object" || deps === null) return;
    for (const [name, v] of Object.entries(deps as Record<string, unknown>)) {
      if (typeof v !== "object" || v === null) continue;
      const e = v as { version?: unknown; resolved?: unknown; dependencies?: unknown };
      if (typeof e.version === "string" && !e.version.includes(":")) out.push({ name, version: e.version, registry: registryResolved(e.resolved) });
      walk(e.dependencies, depth + 1);
    }
  };
  walk((doc as { dependencies?: unknown }).dependencies, 0);
  return out;
}

/** An npm `resolved` URL from a registry tarball (`/-/name-1.0.0.tgz`), or none (the default registry's). */
function registryResolved(resolved: unknown): boolean {
  if (resolved === undefined) return true;
  return typeof resolved === "string" && /^https:\/\/[^/]+\/.*\/-\/[^/]+\.tgz$/.test(resolved);
}

function unquoteKey(k: string): string {
  const t = k.trim();
  if ((t.startsWith("'") && t.endsWith("'")) || (t.startsWith('"') && t.endsWith('"'))) return t.slice(1, -1);
  return t;
}

function pnpmLock(text: string): LockEntry[] {
  const out: LockEntry[] = [];
  let inPackages = false;
  for (const line of text.split(/\r?\n/)) {
    if (/^\S/.test(line)) {
      inPackages = line.trimEnd() === "packages:";
      continue;
    }
    if (!inPackages) continue;
    const m = /^ {2}(\S.*):\s*(\{\})?$/.exec(line);
    if (m === null) continue;
    let key = unquoteKey(m[1] as string);
    // Peer suffixes: `name@1.0.0(peer@2.0.0)`.
    const paren = key.indexOf("(");
    if (paren > 0) key = key.slice(0, paren);
    if (key.startsWith("/")) key = key.slice(1);
    let split = splitAt(key);
    if (split === undefined) {
      // Lockfile v5: `/name/1.0.0`.
      const slash = key.lastIndexOf("/");
      if (slash <= 0) continue;
      split = [key.slice(0, slash), key.slice(slash + 1)];
    }
    const [name, version] = split;
    const registry = !/^(link|file|workspace|git|github|https?):/.test(version) && !version.includes("/");
    out.push({ name, version, registry });
  }
  return out;
}

function yarnLock(text: string): LockEntry[] {
  const out: LockEntry[] = [];
  let header: string | undefined;
  let version: string | undefined;
  let resolution: string | undefined;
  const flush = () => {
    if (header !== undefined && version !== undefined) {
      if (resolution !== undefined) {
        // Berry: `name@npm:1.0.0`; any other protocol is not the registry.
        const r = /^(@?[^@]+)@([a-z]+):(.*)$/.exec(resolution);
        if (r !== null && r[2] !== "workspace") out.push({ name: r[1] as string, version, registry: r[2] === "npm" });
      } else {
        const first = unquoteKey((header.split(",")[0] as string).trim());
        const split = splitAt(first);
        if (split !== undefined) out.push({ name: split[0], version, registry: !/^(file|link|git|github|https?):/.test(split[1]) });
      }
    }
    header = undefined;
    version = undefined;
    resolution = undefined;
  };
  for (const line of text.split(/\r?\n/)) {
    if (line.startsWith("#") || line.trim() === "") continue;
    if (/^\S/.test(line)) {
      flush();
      if (line.startsWith("__metadata")) continue;
      header = line.replace(/:\s*$/, "");
      continue;
    }
    const v = /^ {2}version:? "?([^"\s]+)"?\s*$/.exec(line);
    if (v !== null) version = v[1];
    const r = /^ {2}resolution: "?([^"]+)"?\s*$/.exec(line);
    if (r !== null) resolution = r[1];
  }
  flush();
  return out;
}

function bunLock(text: string): LockEntry[] {
  // JSON with trailing commas (bun 1.2 and later write `bun.lock` so).
  let doc: unknown;
  try {
    doc = JSON.parse(text.replace(/,(\s*[}\]])/g, "$1"));
  } catch {
    return [];
  }
  const packages = (doc as { packages?: unknown })?.packages;
  if (typeof packages !== "object" || packages === null) return [];
  const out: LockEntry[] = [];
  for (const v of Object.values(packages as Record<string, unknown>)) {
    if (!Array.isArray(v) || typeof v[0] !== "string") continue;
    const split = splitAt(v[0]);
    if (split === undefined) continue;
    const [name, version] = split;
    if (/^(workspace|file|link|git|github|https?|root):/.test(version)) continue;
    out.push({ name, version, registry: true });
  }
  return out;
}

function tomlPackages(text: string, header: string, kind: LockKind): LockEntry[] {
  const out: LockEntry[] = [];
  let inBlock = false;
  let name: string | undefined;
  let version: string | undefined;
  let source: string | undefined;
  const flush = () => {
    if (inBlock && name !== undefined && version !== undefined) {
      const local = kind === "uv-lock" ? source !== undefined && /\b(editable|virtual|path|directory)\s*=/.test(source) : kind === "cargo-lock" ? source === undefined : false;
      const registry = kind === "cargo-lock" ? source?.startsWith('"registry+') === true : kind === "uv-lock" ? source === undefined || /\bregistry\s*=/.test(source) : true;
      if (!local) out.push({ name, version, registry });
    }
    name = undefined;
    version = undefined;
    source = undefined;
  };
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.startsWith("[")) {
      flush();
      inBlock = line === header;
      continue;
    }
    if (!inBlock) continue;
    const m = /^(name|version|source)\s*=\s*(.*)$/.exec(line);
    if (m === null) continue;
    const value = m[2] as string;
    const str = /^"([^"]*)"$/.exec(value);
    if (m[1] === "name" && str) name = str[1];
    if (m[1] === "version" && str) version = str[1];
    if (m[1] === "source") source = value;
  }
  flush();
  return out;
}

function goSum(text: string): LockEntry[] {
  const out: LockEntry[] = [];
  for (const line of text.split(/\r?\n/)) {
    const f = line.trim().split(/\s+/);
    if (f.length !== 3) continue;
    const [p, v] = f as [string, string, string];
    if (v.endsWith("/go.mod")) continue;
    out.push({ name: p, version: v, registry: true });
  }
  return out;
}

// --- Reading from disk ------------------------------------------------------

/** One lockfile's text, or undefined: not there, not a regular file, a link, or too large. */
export function readLockfileText(file: string): string | undefined {
  let fd: number | undefined;
  try {
    // O_NOFOLLOW: a lockfile planted as a link to somewhere else is not read.
    // O_NONBLOCK: a FIFO in its place does not hang the gate.
    fd = openSync(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > MAX_LOCKFILE_BYTES) return undefined;
    const buf = Buffer.alloc(st.size);
    let off = 0;
    while (off < st.size) {
      const n = readSync(fd, buf, off, st.size - off, off);
      if (n <= 0) break;
      off += n;
    }
    return buf.subarray(0, off).toString("utf8");
  } catch {
    return undefined;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

export type FoundLockfile = { file: string; kind: LockKind; entries: LockEntry[] };

/** The nearest lockfile of `manager` at or above `cwd`, up to 32 folders. */
export function findLockfile(manager: Manager, cwd: string): FoundLockfile | undefined {
  const names = LOCKFILES[manager];
  if (!names.length || !path.isAbsolute(cwd)) return undefined;
  let dir = path.resolve(cwd);
  for (let i = 0; i < 32; i++) {
    for (const { file, kind } of names) {
      const full = path.join(dir, file);
      const text = readLockfileText(full);
      if (text !== undefined) return { file: full, kind, entries: parseLockfile(kind, text) };
    }
    const up = path.dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  return undefined;
}
