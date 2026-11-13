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
const WRAPPERS = new Set(["sudo", "doas", "env", "command", "exec", "builtin", "nohup", "time", "stdbuf", "chronic", "unbuffer", "nice", "ionice", "chrt", "taskset", "timeout", "xargs", "corepack", "busybox", "parallel", "setsid", "flock", "unshare", "run0"]);
const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "csh", "tcsh", "rbash", "yash"]);
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
    // GNU parallel runs its command words and its `:::` arguments through a
    // shell (`parallel ::: 'git push --force'`; W6C-R3).
    if (head === "parallel") for (const w of rest) if (!w.startsWith("-")) walk(w, heads, depth + 1, out);
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

// --- A program read from input (policy.md section 4, step 7b; E0's R-E0-1) --
//
// A shell or interpreter whose program comes from its input (a pipe, a
// here-string, a process substitution or xargs; an interpreter's
// here-document too) runs text the line does not show. The same reading as
// derm-core's `stdin_program` (crates/derm-core/src/command.rs) and
// OpenMoat 0.19.0's `pipe-to-shell` and `<shell> @stdin`
// (policies/default-v1.yaml:258-270, src/shell/tests/stdin.rs). A shell's
// here-document is not counted: its lines are on the line, and the matcher
// reads them as commands.

interface Feed {
  piped: boolean;
  hereString: boolean;
  hereDoc: boolean;
  process: boolean;
}

const noFeed = (piped = false): Feed => ({ piped, hereString: false, hereDoc: false, process: false });

/** A command fed either way is fed. */
const orFeed = (a: Feed, b: Feed): Feed => ({
  piped: a.piped || b.piped,
  hereString: a.hereString || b.hereString,
  hereDoc: a.hereDoc || b.hereDoc,
  process: a.process || b.process,
});

// Words that open a compound command whose inner commands share the input it
// was given (`curl x | if true; then sh; fi`), the words that close one, and
// the reserved words a simple command may start with before its program
// (integration w6's re-review, W6C-R1).
const OPENERS = new Set(["if", "while", "until", "for", "case", "select"]);
const CLOSERS = new Set(["fi", "done", "esac"]);
const RESERVED = new Set(["if", "then", "else", "elif", "do", "while", "until", "!", "{", "coproc"]);

/** An open `(`: a subshell or group whose commands share a feed, or a process substitution with its command's words and feed so far. */
type Frame = { group: Feed } | { words: string[]; feed: Feed };

/**
 * Simple commands with what feeds each: `installs/parse.ts`'s `commands`,
 * keeping the pipe and redirect forms it drops. A subshell or compound
 * command right after a pipe passes the pipe's input to every command inside
 * it, and a process substitution feeds the command it sits in, before or
 * after its program word (W6C-R1). `base` feeds the whole text.
 */
function fedCommands(text: string, base: Feed): Array<[string[], Feed]> {
  const out: Array<[string[], Feed]> = [];
  let words: string[] = [];
  let word = "";
  let inWord = false;
  let quote: string | undefined;
  let skipNext = false;
  let feed: Feed = { ...base };
  const frames: Frame[] = [];
  const compounds: Feed[] = [];
  const shared = (): Feed => {
    let f = { ...base };
    for (const fr of frames) if ("group" in fr) f = orFeed(f, fr.group);
    for (const c of compounds) f = orFeed(f, c);
    return f;
  };
  const endWord = (): void => {
    if (inWord) {
      if (skipNext) skipNext = false;
      else words.push(word);
    }
    word = "";
    inWord = false;
  };
  const endCommand = (pipedNext: boolean): void => {
    endWord();
    if (words.length) {
      const first = words.find((w) => !["!", "{", "then", "else", "do"].includes(w)) ?? "";
      if (CLOSERS.has(words[0] as string)) compounds.pop();
      else if (OPENERS.has(first)) compounds.push(feed);
      out.push([words, feed]);
    }
    words = [];
    skipNext = false;
    feed = pipedNext ? orFeed(noFeed(true), shared()) : shared();
  };
  let i = 0;
  while (i < text.length) {
    const ch = text[i] as string;
    if (quote !== undefined) {
      if (ch === quote) quote = undefined;
      else word += ch;
      i++;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      inWord = true;
    } else if (ch === "#" && !inWord) {
      while (i < text.length && text[i] !== "\n") i++;
      endCommand(false);
      continue;
    } else if (ch === "|") {
      const or = text[i + 1] === "|";
      if (or || text[i + 1] === "&") i++;
      endCommand(!or);
    } else if (ch === "(") {
      // A subshell or group: right after a pipe it takes the pipe's input
      // (`curl x | (true; sh)`; W6C-S2, W6C-R1).
      if (!words.length && !inWord) frames.push({ group: feed });
      else {
        endCommand(false);
        frames.push({ group: noFeed() });
        feed = shared();
      }
    } else if (ch === ")") {
      endCommand(false);
      const fr = frames.pop();
      if (fr !== undefined && "words" in fr) {
        // The command a process substitution sat in goes on, fed by it.
        words = fr.words;
        feed = { ...fr.feed, process: true };
      } else feed = shared();
    } else if (ch === ";" || ch === "&" || ch === "\n" || ch === "\r") {
      endCommand(false);
    } else if (ch === "<" || ch === ">") {
      if (inWord && word !== "" && /^[0-9]+$/.test(word)) {
        word = "";
        inWord = false;
      }
      endWord();
      if (ch === "<" && text[i + 1] === "(") {
        // `<(` opens a command of its own; the command around it is held
        // until its `)`.
        frames.push({ words, feed });
        words = [];
        feed = shared();
        skipNext = false;
        i += 2;
        continue;
      }
      if (ch === "<") {
        let run = 0;
        while (text[i + run] === "<") run++;
        if (run === 2) feed.hereDoc = true;
        else if (run >= 3) feed.hereString = true;
      }
      while (i + 1 < text.length && "><&|-".includes(text[i + 1] as string)) i++;
      skipNext = true;
    } else if (ch === " " || ch === "\t" || ch === "\v" || ch === "\f") {
      endWord();
    } else {
      word += ch;
      inWord = true;
    }
    i++;
  }
  endWord();
  if (words.length) out.push([words, feed]);
  return out;
}

/** Interpreters that run a program from their input when the line gives none. */
function isInterpreter(base: string): boolean {
  // OpenMoat's `python*`: `python3.12`, `python3-dbg`, `pypy3` (W6C-S2).
  if (isPython(base)) return true;
  return ["node", "nodejs", "perl", "ruby", "php", "deno", "bun", "pwsh", "powershell"].includes(base);
}

const isPython = (base: string): boolean => base.startsWith("python") || base.startsWith("pypy");

/**
 * Paths a program reads its own standard input through, read lexically as the
 * kernel resolves them: `//`, `/./` and `..`, and under `/proc/self/root`
 * (W6C-S2, W6C-R2). A relative path whose last part is `stdin` or `fd/0`
 * counts too, since a `cd` may have put it under `/dev`.
 */
function isStdinPath(w: string): boolean {
  if (w === "-") return true;
  const abs = w.startsWith("/");
  const parts: string[] = [];
  for (const p of w.split("/")) {
    if (p === "" || p === ".") continue;
    if (p === "..") parts.pop();
    else parts.push(p);
  }
  if (!abs) return parts[parts.length - 1] === "stdin" || (parts[parts.length - 2] === "fd" && parts[parts.length - 1] === "0");
  let rest = parts;
  while (rest.length > 3 && rest[0] === "proc" && (rest[1] === "self" || rest[1] === "thread-self") && rest[2] === "root") rest = rest.slice(3);
  const j = rest.join("/");
  return j === "dev/stdin" || j === "dev/fd/0" || j === "proc/self/fd/0" || j === "proc/thread-self/fd/0";
}

/** What a PowerShell switch does with the words after it. */
type Pwsh = "flag" | "value" | "command" | "file";

/**
 * pwsh's switches in the order its parser tries them, each with the shortest
 * form it takes (PowerShell `v7.6.10`, `16ac95d`,
 * `CommandLineParameterParser.cs:914-1290`; `MatchSwitch` at `:798-806`).
 * `-version` and `-help` are read as flags, which only reads more as fed
 * (review W6C-R4, note BD).
 */
const PWSH: ReadonlyArray<readonly [string, string, Pwsh]> = [
  ["version", "v", "flag"],
  ["help", "h", "flag"],
  ["?", "?", "flag"],
  ["login", "l", "flag"],
  ["noexit", "noe", "flag"],
  ["noprofile", "nop", "flag"],
  ["nologo", "nol", "flag"],
  ["noninteractive", "noni", "flag"],
  ["socketservermode", "so", "flag"],
  ["v2socketservermode", "v2so", "flag"],
  ["servermode", "s", "flag"],
  ["namedpipeservermode", "nam", "flag"],
  ["sshservermode", "sshs", "flag"],
  ["noprofileloadtime", "noprofileloadtime", "flag"],
  ["interactive", "i", "flag"],
  ["configurationfile", "configurationfile", "value"],
  ["configurationname", "config", "value"],
  ["custompipename", "cus", "value"],
  ["commandwithargs", "commandwithargs", "command"],
  ["cwa", "cwa", "command"],
  ["command", "c", "command"],
  ["windowstyle", "w", "value"],
  ["file", "f", "file"],
  ["isswait", "isswait", "flag"],
  ["outputformat", "o", "value"],
  ["of", "o", "value"],
  ["inputformat", "inp", "value"],
  ["if", "if", "value"],
  ["executionpolicy", "ex", "value"],
  ["ep", "ep", "value"],
  ["encodedcommand", "e", "command"],
  ["ec", "e", "command"],
  ["encodedarguments", "encodeda", "value"],
  ["ea", "ea", "value"],
  ["settingsfile", "settings", "value"],
  ["sta", "sta", "flag"],
  ["mta", "mta", "flag"],
  ["workingdirectory", "wo", "value"],
  ["wd", "wd", "value"],
  ["removeworkingdirectorytrailingcharacter", "removeworkingdirectorytrailingcharacter", "flag"],
  ["token", "to", "value"],
  ["utctimestamp", "utc", "value"],
];

/** Windows PowerShell 5.1's switches (`about_PowerShell_exe`; prefix rules inferred, read so more reads as fed). */
const POWERSHELL: ReadonlyArray<readonly [string, string, Pwsh]> = [
  ["command", "c", "command"],
  ["encodedcommand", "e", "command"],
  ["ec", "ec", "command"],
  ["file", "f", "file"],
  ["psconsolefile", "p", "value"],
  ["version", "v", "value"],
  ["inputformat", "i", "value"],
  ["outputformat", "o", "value"],
  ["windowstyle", "w", "value"],
  ["encodedarguments", "e", "value"],
  ["ea", "ea", "value"],
  ["configurationname", "c", "value"],
  ["executionpolicy", "e", "value"],
  ["ep", "ep", "value"],
  ["nologo", "n", "flag"],
  ["noexit", "n", "flag"],
  ["sta", "s", "flag"],
  ["mta", "m", "flag"],
  ["noprofile", "n", "flag"],
  ["noninteractive", "n", "flag"],
];

/**
 * Does pwsh (or Windows PowerShell) read its program from its input? A switch
 * starts with a dash (`-`, U+2013, U+2014 or U+2015) or `/` on every system,
 * a doubled first character is dropped, and the first word that is no switch,
 * or a switch it does not know, is the script (`GetSwitchKey`, `:710-738`;
 * `IsDash`, `CharTraits.cs:255-261`). `-command -` and `-file -` read the
 * input, and so does a line with neither.
 */
function pwshReadsInput(program: string, args: readonly string[]): boolean {
  const table = program === "powershell" ? POWERSHELL : PWSH;
  const dash = (c: string): boolean => c === "-" || c === "\u2013" || c === "\u2014" || c === "\u2015";
  for (let i = 0; i < args.length; ) {
    const w = (args[i] as string).trim();
    const first = w[0];
    if (first === undefined || !(dash(first) || first === "/")) return isStdinPath(w);
    let key = w.slice(1);
    if (key.startsWith(first)) key = key.slice(1);
    const hit = table.find(([full, shortest]) => key.length >= shortest.length && full.startsWith(key));
    if (hit === undefined) return isStdinPath(w);
    const kind = hit[2];
    if (kind === "flag") i += 1;
    else if (kind === "value") i += 2;
    else {
      const value = args[i + 1];
      return value !== undefined && isStdinPath(value.trim());
    }
  }
  return true;
}

/** Does a shell's argument list hold `-c` among its flags (`-c`, `-ec`)? The values of `-o`, `+o`, `--rcfile` and `--init-file` are skipped (W6C-R3). */
function hasCFlag(args: readonly string[]): boolean {
  for (let i = 0; i < args.length; i++) {
    const w = args[i] as string;
    if (w === "--" || (!w.startsWith("-") && !w.startsWith("+"))) return false;
    if (w === "-o" || w === "+o" || w === "--rcfile" || w === "--init-file") {
      i++;
      continue;
    }
    if (w.startsWith("-") && !w.startsWith("--") && w.slice(1).includes("c")) return true;
  }
  return false;
}

/**
 * Does `program`, run with `args`, read its program from its input? A shell
 * does with `-s`, a stdin path, or no operand and no `-c`; `source` and `.`
 * with a stdin path or no operand; an interpreter with a stdin path, or no
 * operand and none of its program flags. Folded text is lowercase, so `-E`
 * reads as `-e` and `-X` as `-x`; where that joins a valued flag and one
 * that takes none, it is read as valued, which only reads more as fed.
 */
function readsItsInput(program: string, args: readonly string[]): boolean {
  if (program === "pwsh" || program === "powershell") return pwshReadsInput(program, args);
  const shell = SHELLS.has(program);
  const source = program === "source" || program === ".";
  let programLetters = "";
  let valuedLetters = "";
  let programLong: readonly string[] = [];
  let valuedLong: readonly string[] = [];
  if (shell) {
    programLetters = "c";
    valuedLetters = "o";
    valuedLong = ["--rcfile", "--init-file"];
  } else if (source) {
    // none
  } else if (isPython(program)) {
    programLetters = "cm";
    valuedLetters = "wx";
    valuedLong = ["--check-hash-based-pycs"];
  } else if (program === "node" || program === "nodejs" || program === "bun") {
    programLetters = "ep";
    valuedLetters = "rc";
    programLong = ["--eval", "--print"];
    valuedLong = ["--require", "--import", "--loader", "--experimental-loader", "--conditions", "--input-type", "--title"];
  } else if (program === "perl") {
    programLetters = "e";
  } else if (program === "ruby") {
    programLetters = "e";
    valuedLetters = "ric";
  } else if (program === "php") {
    programLetters = "rf";
    valuedLetters = "cdz";
  }
  const operands: string[] = [];
  for (let i = 0; i < args.length; ) {
    const w = args[i] as string;
    if (w === "--") {
      operands.push(...args.slice(i + 1));
      break;
    }
    const flag = (w.startsWith("-") && w.length > 1) || (shell && w.startsWith("+") && w.length > 1);
    if (!flag) {
      operands.push(w);
      i++;
      continue;
    }
    const name = w.split("=")[0] as string;
    if (programLong.includes(name)) return false;
    if (valuedLong.includes(name)) {
      i += w.includes("=") ? 1 : 2;
      continue;
    }
    if (w.startsWith("--")) {
      i++;
      continue;
    }
    const letters = w.slice(1);
    if (shell && w.startsWith("-") && letters.includes("s")) return true;
    if ([...letters].some((c) => programLetters.includes(c))) return false;
    // A short flag that takes a value consumes the next word unless it is attached.
    if (letters.length === 1 && valuedLetters.includes(letters)) {
      i += 2;
      continue;
    }
    i++;
  }
  const first = operands[0];
  if (first === undefined) return true;
  if (isStdinPath(first)) return true;
  // deno and bun name a subcommand first: `deno run -`, bare `deno run`.
  if ((program === "deno" || program === "bun") && first === "run") {
    const second = operands[1];
    return second === undefined || isStdinPath(second);
  }
  return false;
}

const isProgram = (b: string): boolean => SHELLS.has(b) || b === "source" || b === "." || isInterpreter(b);

/**
 * The program name of a shell or interpreter in folded shell text that
 * reads its program from its input, or undefined. Read as written and with
 * every backslash removed, inside `-c`, `eval` and `env -S` strings to the
 * same depth as the command rules.
 */
export function stdinProgram(folded: string): string | undefined {
  for (const text of [folded, folded.replace(/\\/g, "")]) {
    const p = stdinWalk(text.replace(/`/g, "\n"), 0, noFeed());
    if (p !== undefined) return p;
  }
  return undefined;
}

/** `base` feeds the whole text: a `-c`, `env -S` or `eval` string is read by commands that take the outer command's input (W6C-R1). */
function stdinWalk(text: string, depth: number, base: Feed): string | undefined {
  if (depth > MAX_DEPTH) return undefined;
  for (const [words, feed] of fedCommands(text, base)) {
    const p = stdinRead(words, feed, depth);
    if (p !== undefined) return p;
  }
  return undefined;
}

/** The words xargs fills from its input in a command it runs: `-I x`, `-ix`, `-i` (`{}`), `--replace[=x]`; `{}` always. */
function xargsTokens(args: readonly string[]): string[] {
  const out = ["{}"];
  for (let i = 0; i < args.length; i++) {
    const w = args[i] as string;
    if (!w.startsWith("-")) break;
    if (w === "-i" || w === "--replace") continue;
    if (w === "-I") {
      const v = args[i + 1];
      if (v !== undefined) out.push(v);
      i++;
    } else if (w.startsWith("--replace=")) out.push(w.slice("--replace=".length));
    else if (w.startsWith("-I") || w.startsWith("-i")) {
      if (w.length > 2) out.push(w.slice(2));
    }
  }
  return out.filter((t) => t !== "");
}

function stdinRead(input: string[], feed: Feed, depth: number): string | undefined {
  let words = input;
  // Behind xargs or parallel: the words it fills from its input.
  let xargs: string[] | undefined;
  for (let guard = 0; guard < 16; guard++) {
    while (words.length && (ASSIGNMENT.test(words[0] as string) || RESERVED.has(words[0] as string))) words = words.slice(1);
    if (!words.length) return undefined;
    const head = commandBase(words[0] as string);
    const rest = words.slice(1);
    if (head === "env") {
      const split = rest.findIndex((w) => w === "-s" || w === "--split-string" || w.startsWith("--split-string="));
      if (split >= 0) {
        const w = rest[split] as string;
        const s = w.startsWith("--split-string=") ? w.slice("--split-string=".length) : rest[split + 1];
        return s === undefined ? undefined : stdinWalk(s, depth + 1, feed);
      }
    }
    if (head === "eval") return stdinWalk(rest.join(" "), depth + 1, feed);
    if (isProgram(head)) {
      if (SHELLS.has(head)) {
        // Behind xargs or parallel a shell's `-c` takes its string from the
        // input when the line gives none, or when the string holds a word the
        // input fills (W6C-S2); a fixed string only gets the input as
        // arguments (W6C-R5).
        if (xargs !== undefined && hasCFlag(rest)) {
          const s = shellCommandString(rest);
          if (s === undefined || xargs.some((t) => s.includes(t))) return head;
        }
        const c = shellCommandString(rest);
        if (c !== undefined) return stdinWalk(c, depth + 1, feed);
      }
      const shellish = SHELLS.has(head) || head === "source" || head === ".";
      const fed = feed.piped || feed.hereString || feed.process || xargs !== undefined || (feed.hereDoc && !shellish);
      return fed && readsItsInput(head, rest) ? head : undefined;
    }
    if (head === "parallel") {
      // GNU parallel runs each input line as a command when its line names
      // none, and runs its command words and `:::` arguments through a shell
      // (GNU parallel 20231122, run; W6C-R3).
      const fed = feed.piped || feed.hereString || feed.process;
      const before = [];
      for (const w of rest) {
        if (w === ":::" || w === "::::") break;
        before.push(w);
      }
      const command = before.some((w) => !w.startsWith("-") && !/^[0-9]+$/.test(w));
      if (fed && !command && !rest.some((w) => w === ":::" || w === "::::")) return head;
      for (const w of rest) {
        if (w.startsWith("-")) continue;
        const p = stdinWalk(w, depth + 1, noFeed());
        if (p !== undefined) return p;
      }
    }
    if (!WRAPPERS.has(head)) return undefined;
    if (head === "xargs") xargs = xargsTokens(rest);
    else if (head === "parallel") xargs = ["{"];
    const next = rest.findIndex((w) => {
      const b = commandBase(w);
      return !ASSIGNMENT.test(w) && (WRAPPERS.has(b) || isProgram(b) || b === "eval");
    });
    if (next < 0) return undefined;
    words = rest.slice(next);
  }
  return undefined;
}
