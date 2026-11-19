// Step 7e of contracts/policy.md section 4: a shell command that changes the
// filesystem root, a system folder, a home folder, a top-level folder, a
// mounted volume, a disk device or a parent folder, or signals every process
// (E1-1, eval pass 1). The TypeScript form of
// crates/derm-core/src/destructive.rs, which holds the sources and the
// limits; the three matchers answer alike on contracts/fixtures/policy/cases.json.
// Canonical copy: packages/derm-claude-plugin/src/core/ (derm-pi carries its own).

import { headCommands } from "./command.ts";

/** Programs whose every operand is written, removed or changed. */
const CHANGE = ["rm", "rmdir", "unlink", "shred", "chmod", "chown", "chgrp", "truncate", "tee"];
/** Programs that write only their last operand (or `-t`'s folder). */
const COPY = ["cp", "ln", "install"];
/** Disk tools. */
const DISK = [
  "mkfs", "mkfs.bfs", "mkfs.btrfs", "mkfs.cramfs", "mkfs.exfat", "mkfs.ext2", "mkfs.ext3", "mkfs.ext4", "mkfs.f2fs", "mkfs.fat",
  "mkfs.minix", "mkfs.msdos", "mkfs.ntfs", "mkfs.vfat", "mkfs.xfs", "mke2fs", "mkswap", "wipefs", "blkdiscard", "fdisk", "sfdisk",
  "cfdisk", "sgdisk", "gdisk", "parted", "newfs", "newfs_apfs", "newfs_hfs", "diskutil",
];
const HEADS: ReadonlySet<string> = new Set(["kill", "dd", "mv", ...CHANGE, ...COPY, ...DISK]);
const SHELLS: ReadonlySet<string> = new Set(["sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "csh", "tcsh", "rbash", "yash", "eval"]);
const MAX_DEPTH = 4;

/** Folders protected at any depth. */
const TREES = ["etc", "bin", "sbin", "lib", "lib32", "lib64", "libx32", "boot", "sys", "proc", "system", "library", "applications"];
/** Under `/var`, protected at any depth; `/var/<x>` itself always is. */
const VAR_TREES = ["lib", "db", "root"];
/** `/dev` names that are a disk, a volume or memory: a prefix and what must follow it. */
const DISKS: ReadonlyArray<readonly [string, "letter" | "digit" | "any" | "end"]> = [
  ["sd", "letter"], ["hd", "letter"], ["vd", "letter"], ["xvd", "letter"], ["nvme", "digit"], ["mmcblk", "digit"], ["rdisk", "digit"],
  ["disk", "any"], ["mapper", "end"], ["dm-", "digit"], ["md", "digit"], ["loop", "digit"], ["sr", "digit"], ["mem", "end"],
  ["kmem", "end"], ["port", "end"],
];

type Class = { what: string; strong: boolean };

function isDisk(name: string): boolean {
  return DISKS.some(([prefix, follow]) => {
    if (!name.startsWith(prefix)) return false;
    const next = name.slice(prefix.length, prefix.length + 1);
    if (follow === "letter") return /^[a-z]$/.test(next);
    if (follow === "digit") return /^[0-9]$/.test(next);
    if (follow === "any") return true;
    return next === "";
  });
}

/** Reads `word` as a path, lexically. */
function classify(word: string): Class | undefined {
  const absolute = word.startsWith("/");
  const parts: string[] = [];
  let climbs = 0;
  for (const p of word.split("/")) {
    if (p === "" || p === ".") continue;
    if (p === "..") {
      if (parts.pop() === undefined && !absolute) climbs++;
    } else parts.push(p);
  }
  if (!absolute) return climbs > 0 && parts.length === 0 ? { what: "a parent folder", strong: false } : undefined;
  // macOS keeps `/etc`, `/var` and `/tmp` under `/private`.
  if (parts.length >= 2 && parts[0] === "private" && ["etc", "var", "tmp"].includes(parts[1]!)) parts.shift();
  const top = parts[0];
  const n = parts.length;
  if (top === undefined) return { what: "the filesystem root", strong: false };
  if (TREES.includes(top)) return { what: "a system folder", strong: true };
  if (top === "usr") return n >= 4 && parts[1] === "local" ? undefined : { what: "a system folder", strong: true };
  if (top === "var") {
    if (n === 1) return { what: "a system folder", strong: false };
    if (VAR_TREES.includes(parts[1]!)) return { what: "a system folder", strong: true };
    return n === 2 ? { what: "a system folder", strong: false } : undefined;
  }
  if (top === "dev") {
    if (n === 1) return { what: "a top-level folder", strong: false };
    return isDisk(parts[1]!) ? { what: "a disk device", strong: true } : undefined;
  }
  if (top === "root" && n === 1) return { what: "a home folder", strong: false };
  if ((top === "home" || top === "users") && n <= 2) return { what: "a home folder", strong: false };
  if ((top === "mnt" || top === "media" || top === "volumes") && n === 2) return { what: "a mounted volume", strong: false };
  if (n === 1) return { what: "a top-level folder", strong: false };
  return undefined;
}

function reason(what: string, program: string): string {
  return `command changes ${what}: \`${program}\``;
}

/** The words a command passes as operands: no flags, and everything after `--`. */
function operands(args: readonly string[]): string[] {
  const out: string[] = [];
  let all = false;
  for (const a of args) {
    if (!all && a === "--") all = true;
    else if (all || !a.startsWith("-") || a === "-") out.push(a);
  }
  return out;
}

/** `-t <folder>`, `--target-directory[=]<folder>`, and `-t` ending a cluster of short flags or with its folder attached (E1R-7). */
function targetDirectory(args: readonly string[]): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--") return undefined;
    if (a.startsWith("--target-directory=")) return a.slice("--target-directory=".length);
    if (a === "--target-directory") return args[i + 1];
    if (a.startsWith("-") && !a.startsWith("--")) {
      const at = a.indexOf("t");
      if (at !== -1) {
        const attached = a.slice(at + 1);
        return attached === "" ? args[i + 1] : attached;
      }
    }
  }
  return undefined;
}

function check(program: string, args: readonly string[]): string | undefined {
  const any = (words: readonly string[], strongOnly: boolean): string | undefined => {
    for (const w of words) {
      const c = classify(w);
      if (c !== undefined && (c.strong || !strongOnly)) return reason(c.what, program);
    }
    return undefined;
  };
  if (program === "kill") {
    // `-1` as a pid: after the first argument (a signal comes first), or after `--`.
    const dashes = args.indexOf("--");
    const every = args.some((a, i) => /^-0*1$/.test(a) && (i > 0 || (dashes !== -1 && dashes < i)));
    return every ? `command signals every process: \`${program}\`` : undefined;
  }
  if (["rm", "chmod", "chown", "chgrp"].includes(program) && args.includes("--no-preserve-root")) return reason("the filesystem root", program);
  if (program === "dd") return any(args.filter((a) => a.startsWith("of=")).map((a) => a.slice(3)), false);
  const copies = COPY.includes(program) || program === "mv";
  // Only these four have `-t`; for `chmod` it is a mode.
  const target = copies ? targetDirectory(args) : undefined;
  const ops = operands(args);
  // `-t`'s folder is the destination, not one more operand.
  if (target !== undefined) {
    const i = ops.indexOf(target);
    if (i !== -1) ops.splice(i, 1);
  }
  if (copies) {
    // A flag after the first operand may take a value, and the fold reads
    // `-T` as `-t`: then any operand in a system tree or on a disk counts.
    const first = args.findIndex((a) => !a.startsWith("-"));
    let lateFlag = false;
    if (first !== -1) {
      for (const a of args.slice(first)) {
        if (a === "--") break;
        if (a.startsWith("-") && a.length > 1) lateFlag = true;
      }
    }
    if (lateFlag || target !== undefined) {
      const r = any(ops, true);
      if (r !== undefined) return r;
    }
    // With `-t` every operand is a source; without, the last is the destination.
    let sources = ops;
    let dest: string | undefined;
    if (target !== undefined) dest = target;
    else if (ops.length >= 2) {
      sources = ops.slice(0, -1);
      dest = ops[ops.length - 1];
    }
    // A copy into a folder changes no folder itself: only a system tree or a disk as the destination counts.
    const d = dest === undefined ? undefined : any([dest], true);
    if (d !== undefined) return d;
    // `mv` removes its sources; a copy only reads them.
    return program === "mv" ? any(sources, false) : undefined;
  }
  return any(ops, false);
}

const BREAKS = new Set([" ", "\t", "\n", "\r", ";", "&", "|", "(", ")", "<", ">"]);
const STARTS = new Set([" ", "\t", "\n", "\r", ";", "&", "|", "(", ")"]);

/** The targets of output redirections in shell text, quotes read as the shell reads them; a descriptor (`>&2`, `>&-`) is no target. */
function writeTargets(text: string): string[] {
  const chars = Array.from(text);
  const out: string[] = [];
  let quote: string | undefined;
  let atWordStart = true;
  let i = 0;
  while (i < chars.length) {
    const ch = chars[i]!;
    if (quote !== undefined) {
      if (ch === quote) quote = undefined;
      i++;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      atWordStart = false;
    } else if (ch === "#" && atWordStart) {
      while (i < chars.length && chars[i] !== "\n") i++;
      continue;
    } else if (ch === ">") {
      i++;
      let descriptor = false;
      while (i < chars.length && (chars[i] === ">" || chars[i] === "|" || chars[i] === "&")) {
        descriptor = chars[i] === "&";
        i++;
      }
      while (i < chars.length && (chars[i] === " " || chars[i] === "\t")) i++;
      let word = "";
      let q: string | undefined;
      while (i < chars.length) {
        const c = chars[i]!;
        if (q !== undefined) {
          if (c === q) q = undefined;
          else word += c;
        } else if (c === "'" || c === '"') q = c;
        else if (BREAKS.has(c)) break;
        else word += c;
        i++;
      }
      const isDescriptor = descriptor && (word === "-" || /^[0-9]*$/.test(word));
      if (word !== "" && !isDescriptor) out.push(word);
      atWordStart = true;
      continue;
    } else atWordStart = STARTS.has(ch);
    i++;
  }
  return out;
}

function redirects(text: string, depth: number): string | undefined {
  for (const t of writeTargets(text)) {
    const c = classify(t);
    if (c !== undefined) return reason(c.what, ">");
  }
  if (depth >= MAX_DEPTH) return undefined;
  // A shell's `-c` string and `eval`'s words are shell text of their own.
  for (const cmd of headCommands(text, SHELLS)) {
    for (const arg of cmd.slice(1)) {
      if (!arg.includes(">")) continue;
      const r = redirects(arg, depth + 1);
      if (r !== undefined) return r;
    }
  }
  return undefined;
}

/** The reason to ask about folded shell text, if it holds such a command. */
export function destructive(folded: string): string | undefined {
  for (const cmd of headCommands(folded, HEADS)) {
    const r = check(cmd[0]!, cmd.slice(1));
    if (r !== undefined) return r;
  }
  return redirects(folded, 0);
}
