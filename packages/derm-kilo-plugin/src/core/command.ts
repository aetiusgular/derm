// Command rules (contracts/policy.md section 7; wave 5 lane W, decided at
// integration w5's phase 3 merge). A rule may name a CLI command by its first
// words (`"tool": "bash", "command": ["gh", "pr", "create"]`). This file holds
// the words' shape and the two ways a rule meets shell text:
//
// - a deny or an ask rule *narrows* (section 7, like step 3a): it meets any
//   simple command of the text, past `;`, `&&`, `||`, `|`, `&`, line breaks,
//   subshells and backticks, past the wrappers lane X lists (`sudo`, `env`,
//   `timeout`, `xargs` ...), inside `bash -c '...'`, `eval` and `env -S`,
//   and past global flags before a subcommand (`git -C repo push`). A rule
//   word that starts with `-` (lane W's addition, policy.md section 7) meets
//   that flag anywhere after the words before it, so `["git", "push",
//   "--force"]` meets `git push origin main --force`. Reading more commands
//   than the shell runs only narrows more: the side that fails safe.
// - an allow rule *widens* only a call whose whole text is one plain simple
//   command whose first words are the rule's, in order and exactly (no
//   wrapper, no path, no separator, no redirect). Steps 2, 6, 7a, 7b, 7c and
//   section 6 still run on it (the caller's).
//
// Canonical copy: packages/derm-claude-plugin/src/core/ (sync-core.mjs
// copies it into every package that carries the core). derm-pi carries the
// same file (packages/derm-pi/src/command.ts, held equal by a test), and
// derm-core the same logic in Rust (crates/derm-core/src/command.rs). All
// three are tested against contracts/fixtures/policy/.

import { commands } from "./installs/parse.ts";

/** At most this many words in a rule's `command`. */
export const MAX_COMMAND_WORDS = 8;

/** A command's name and its subcommands: lowercase, as the matcher folds. */
export const COMMAND_WORD = /^[a-z0-9][a-z0-9._:=+-]{0,63}$/;

/** A flag, after the first word only (lane W's addition): `-f`, `--force`, `--force-with-lease`. */
export const COMMAND_FLAG_WORD = /^--?[a-z0-9][a-z0-9._:=+-]{0,61}$/;

/** Why `value` is not a valid `command`, or undefined when it is. */
export function commandProblem(value: unknown): string | undefined {
  if (!Array.isArray(value)) return "command is not an array";
  if (value.length < 1 || value.length > MAX_COMMAND_WORDS) return `command has ${value.length} words (1 to ${MAX_COMMAND_WORDS})`;
  for (const [i, w] of value.entries()) {
    if (typeof w !== "string") return `command word ${i} is not a string`;
    if (COMMAND_WORD.test(w)) continue;
    if (i > 0 && COMMAND_FLAG_WORD.test(w)) continue;
    return `command word ${i} is not a plain lowercase word`;
  }
  return undefined;
}

// Lane X's wrapper list (installs/parse.ts): words that run the rest of the
// line as a command. Their own flags are not parsed; the command starts at
// the first later word that names a rule's head, a wrapper or a shell.
const WRAPPERS = new Set(["sudo", "doas", "env", "command", "exec", "builtin", "nohup", "time", "stdbuf", "chronic", "unbuffer", "nice", "ionice", "chrt", "taskset", "timeout", "xargs", "corepack", "busybox"]);
const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish"]);
const ASSIGNMENT = /^[a-z_][a-z0-9_]*=/;
const MAX_DEPTH = 4;

/** A word's program name: no folder, no `.exe` or `.cmd`. */
export function commandBase(word: string): string {
  const slash = word.lastIndexOf("/");
  let b = slash >= 0 ? word.slice(slash + 1) : word;
  for (const ext of [".exe", ".cmd"]) if (b.endsWith(ext)) b = b.slice(0, -ext.length);
  return b;
}

/**
 * The command string of a shell started with `-c` (or a cluster holding
 * `c`, as `-lc`): the first word that is not an option, as bash reads it.
 * Options may come before or after `-c`, `+x` style as well as `-x`;
 * `-o`, `+o`, `--rcfile` and `--init-file` take a value; `--` ends the
 * options (integration w5's close, review W5-S3: `bash -c -- '...'`,
 * `bash +x -c '...'` and `bash --rcfile f -c '...'` were not read).
 */
function shellCommandString(words: readonly string[]): string | undefined {
  let sawC = false;
  for (let i = 0; i < words.length; i++) {
    const w = words[i] as string;
    if (w === "--") return sawC ? words[i + 1] : undefined;
    if (!w.startsWith("-") && !w.startsWith("+")) return sawC ? w : undefined;
    if (w === "-o" || w === "+o" || w === "--rcfile" || w === "--init-file") {
      i++;
      continue;
    }
    if (/^-[a-z]*c[a-z]*$/.test(w)) sawC = true;
  }
  return undefined;
}

/**
 * Every simple command in folded shell text that starts with one of
 * `heads` (a rule's first word), its first word given as the bare program
 * name. Read from the text as written and with every backslash removed
 * (the shell reads `g\it` as `git`); backticks end a command, as `$(` does.
 */
export function headCommands(folded: string, heads: ReadonlySet<string>): string[][] {
  const out: string[][] = [];
  const texts = [folded, folded.replace(/\\/g, "")].map((t) => t.replace(/`/g, "\n"));
  for (const text of texts) walk(text, heads, 0, out);
  return out;
}

function walk(text: string, heads: ReadonlySet<string>, depth: number, out: string[][]): void {
  if (depth > MAX_DEPTH) return;
  for (const words of commands(text)) read(words, heads, depth, out);
}

function isHead(word: string, heads: ReadonlySet<string>): boolean {
  const b = commandBase(word);
  return heads.has(b) || WRAPPERS.has(b) || SHELLS.has(b) || b === "eval";
}

function read(input: string[], heads: ReadonlySet<string>, depth: number, out: string[][]): void {
  let words = input;
  for (let guard = 0; guard < 16; guard++) {
    while (words.length && ASSIGNMENT.test(words[0] as string)) words = words.slice(1);
    if (!words.length) return;
    const head = commandBase(words[0] as string);
    const rest = words.slice(1);
    if (heads.has(head)) {
      out.push([head, ...rest]);
      return;
    }
    if (head === "env") {
      const split = rest.findIndex((w) => w === "-s" || w === "--split-string" || w.startsWith("--split-string="));
      if (split >= 0) {
        const w = rest[split] as string;
        const s = w.startsWith("--split-string=") ? w.slice("--split-string=".length) : rest[split + 1];
        if (s !== undefined) walk(s, heads, depth + 1, out);
        return;
      }
    }
    if (head === "eval") {
      walk(rest.join(" "), heads, depth + 1, out);
      return;
    }
    if (SHELLS.has(head)) {
      const c = shellCommandString(rest);
      if (c !== undefined) walk(c, heads, depth + 1, out);
      return;
    }
    if (!WRAPPERS.has(head)) return;
    const next = rest.findIndex((w) => !ASSIGNMENT.test(w) && isHead(w, heads));
    if (next < 0) return;
    words = rest.slice(next);
  }
}

/**
 * Does a command's flag word meet a rule's flag word? `-f` also meets
 * `-fu`; a long flag also meets a prefix of it of two letters or more,
 * as `--forc` or `--fo=x` (git and other parsers take an unambiguous
 * prefix; integration w5's close, review W5-S4: `git reset --ha`).
 * Reading more only narrows more.
 */
function flagMeets(word: string, flag: string): boolean {
  if (word === flag || word.startsWith(`${flag}=`)) return true;
  if (flag.startsWith("--") && word.startsWith("--")) {
    const name = word.slice(2).split("=")[0] as string;
    if (name.length >= 2 && flag.slice(2).startsWith(name)) return true;
  }
  // A single-letter short flag inside a cluster of short flags (`-fu`).
  return /^-[a-z0-9]$/.test(flag) && /^-[a-z0-9]{2,}$/.test(word) && word.includes(flag.slice(1));
}

/**
 * Does a deny or ask rule's `command` meet one simple command (its words
 * from `headCommands`)? The first words must be equal; a later plain word
 * may follow flags and one value after a flag (`git -C repo push`); a flag
 * word meets that flag anywhere after the plain words before it.
 */
export function commandNarrows(rule: readonly string[], words: readonly string[]): boolean {
  if (words.length === 0 || words[0] !== rule[0]) return false;
  return meets(rule, 1, words, 1);
}

function meets(rule: readonly string[], j: number, words: readonly string[], i: number): boolean {
  if (j >= rule.length) return true;
  const want = rule[j] as string;
  if (want.startsWith("-")) {
    for (let k = i; k < words.length; k++) if (flagMeets(words[k] as string, want)) return meets(rule, j + 1, words, i);
    return false;
  }
  let valueAllowed = false;
  for (let k = i; k < words.length; k++) {
    const w = words[k] as string;
    if (w === want && meets(rule, j + 1, words, k + 1)) return true;
    if (w.startsWith("-")) {
      valueAllowed = !w.includes("=") && w !== "--";
      continue;
    }
    if (valueAllowed) {
      valueAllowed = false;
      continue;
    }
    return false;
  }
  return false;
}

/** Characters that make shell text more than one plain simple command. */
const NOT_PLAIN = /[;&|()<>`\n\r#]/;

/**
 * Does an allow rule's `command` cover the whole folded text? Only when the
 * text is one plain simple command whose first words are the rule's, in
 * order and exactly: no wrapper, no path, no assignment, no separator, no
 * subshell, no redirect, no comment. What else the text holds (`$`, globs,
 * a control file, an install) is the caller's steps 7a to 7c and section 6.
 */
export function commandAllows(rule: readonly string[], folded: string): boolean {
  if (NOT_PLAIN.test(folded)) return false;
  const words = folded.trim().split(/[ \t\v\f]+/);
  if (words.length < rule.length || !rule.every((w, i) => words[i] === w)) return false;
  // After the rule's own words only plain operands widen: no flag and no
  // `=`, since a flag can write (`git log --output=<file>` wrote through a
  // committed link into .git/config; integration w5's close, review W5-S1).
  return words.slice(rule.length).every((w) => !w.startsWith("-") && !w.includes("="));
}

/** The reason a command rule gives: `rule bash <words>` (policy.md section 7). */
export function commandReason(rule: readonly string[]): string {
  return `rule bash ${rule.join(" ")}`;
}
