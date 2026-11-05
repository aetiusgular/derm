// Reads package installs out of a shell call's text (contracts/policy.md
// section 6; wave 5 lane X). Pure: no file, no process, no network. The text
// is the matcher's folded input (lowercase, NFKD-folded, escapes decoded), so
// `$`, backticks, `\`, globs and braces never reach here: step 7b already
// asked on them. What is left is words, quotes and the operators that split
// one command from the next.
//
// The forms are read in each manager's own help at the version in use on
// 4 Nov 2026 (tk_lane_X.md, Research): npm 12.2.2, pnpm 12.16.1, yarn 4.18.1
// and 1.22.22, bun 1.4.4, pip 26.3, uv 0.13.7, poetry 2.5.1, pdm 2.29.5,
// pipx 1.18.13, cargo 1.97.0, go 1.24.7.
//
// Held equal to derm-core's `installs/parse.rs` and derm-pi's copy by
// contracts/fixtures/installs/cases.json and cases-x.json.

export type Manager = "npm" | "pnpm" | "yarn" | "bun" | "pip" | "uv" | "poetry" | "pdm" | "pipx" | "cargo" | "go";
export type Form = "add" | "run";
export type Ecosystem = "npm" | "PyPI" | "crates.io" | "Go";

export type Package = { name: string; version: string | null };

/** Something an install fetches that the check cannot name by registry. */
export type Unseen = "path" | "url" | "git" | "requirements" | "update" | "stdin" | "spec" | "registry";

export type Install = {
  manager: Manager;
  form: Form;
  packages: Package[];
  unseen: Unseen[];
};

export const ECOSYSTEM: Record<Manager, Ecosystem> = {
  npm: "npm",
  pnpm: "npm",
  yarn: "npm",
  bun: "npm",
  pip: "PyPI",
  uv: "PyPI",
  poetry: "PyPI",
  pdm: "PyPI",
  pipx: "PyPI",
  cargo: "crates.io",
  go: "Go",
};

const MAX_DEPTH = 4;

/** Every install in the text, in order. Empty when there is none. */
export function parseInstalls(text: string): Install[] {
  const out: Install[] = [];
  walk(text, 0, out);
  return out;
}

function walk(text: string, depth: number, out: Install[]): void {
  if (depth > MAX_DEPTH) return;
  for (const words of commands(text)) readCommand(words, depth, out);
}

// --- Words and commands -----------------------------------------------------

/**
 * Splits shell text into simple commands, each a list of words. Quotes join
 * into the word they sit in; `;`, `&`, `|`, `(`, `)` and a line break end a
 * command; `<` and `>` drop the word that follows (a redirect target); `#` at
 * a word's start ends the line.
 */
export function commands(text: string): string[][] {
  const out: string[][] = [];
  let words: string[] = [];
  let word = "";
  let inWord = false;
  let quote: "'" | '"' | undefined;
  let skipNext = false;
  const endWord = () => {
    if (inWord) {
      if (skipNext) skipNext = false;
      else words.push(word);
    }
    word = "";
    inWord = false;
  };
  const endCommand = () => {
    endWord();
    if (words.length) out.push(words);
    words = [];
    skipNext = false;
  };
  for (let i = 0; i < text.length; i++) {
    const ch = text[i] as string;
    if (quote !== undefined) {
      if (ch === quote) quote = undefined;
      else word += ch;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      inWord = true;
      continue;
    }
    if (ch === "#" && !inWord) {
      while (i < text.length && text[i] !== "\n") i++;
      endCommand();
      continue;
    }
    if (ch === ";" || ch === "&" || ch === "|" || ch === "(" || ch === ")" || ch === "\n" || ch === "\r") {
      endCommand();
      continue;
    }
    if (ch === "<" || ch === ">") {
      // A file descriptor's number before a redirect (`2>`) is not a word,
      // and `>&`, `>>`, `>|`, `<<`, `<>` are one operator; the word after is
      // the target (or the descriptor `>&1` names).
      if (inWord && quote === undefined && /^[0-9]+$/.test(word)) {
        word = "";
        inWord = false;
      }
      endWord();
      while (i + 1 < text.length && (text[i + 1] === ">" || text[i + 1] === "<" || text[i + 1] === "&" || text[i + 1] === "|")) i++;
      skipNext = true;
      continue;
    }
    if (ch === " " || ch === "\t" || ch === "\v" || ch === "\f") {
      endWord();
      continue;
    }
    word += ch;
    inWord = true;
  }
  endCommand();
  return out;
}

const ASSIGNMENT = /^[a-z_][a-z0-9_]*=/;

/** Stands for the words `xargs` reads from its input. No argv holds a NUL. */
export const STDIN_WORD = "\u0000stdin\u0000";

function base(word: string): string {
  const slash = word.lastIndexOf("/");
  let b = slash >= 0 ? word.slice(slash + 1) : word;
  for (const ext of [".exe", ".cmd"]) if (b.endsWith(ext)) b = b.slice(0, -ext.length);
  return b;
}

const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish"]);
const PYTHON = /^python(\d+(\.\d+)?)?$/;
const PIP = /^pip(\d+(\.\d+)?)?$/;

// Words that run the rest of the line as a command. Their own flags are not
// parsed: the command starts at the first word that names a manager, a
// wrapper or a shell, so a wrapper's flag value never hides it. A flag value
// that happens to name a manager (`sudo -u npm pip install x`) reads the
// install under the wrong manager: still an install, still asked.
const WRAPPERS = new Set(["sudo", "doas", "env", "command", "exec", "builtin", "nohup", "time", "stdbuf", "chronic", "unbuffer", "nice", "ionice", "chrt", "taskset", "timeout", "xargs", "corepack"]);
const MANAGER_HEADS = new Set(["npm", "npx", "pnpm", "pn", "pnpx", "pnx", "yarn", "yarnpkg", "bun", "bunx", "uv", "uvx", "poetry", "pdm", "pipx", "cargo", "go", "py", "eval"]);

function isHead(word: string): boolean {
  const b = base(word);
  return WRAPPERS.has(b) || MANAGER_HEADS.has(b) || SHELLS.has(b) || PIP.test(b) || PYTHON.test(b);
}

function readCommand(input: string[], depth: number, out: Install[]): void {
  let words = input;
  let fromStdin = false;
  for (let guard = 0; guard < 16; guard++) {
    while (words.length && ASSIGNMENT.test(words[0] as string)) words = words.slice(1);
    if (!words.length) return;
    const head = base(words[0] as string);
    const rest = words.slice(1);
    if (head === "env") {
      const split = rest.findIndex((w) => w === "-s" || w === "--split-string" || w.startsWith("--split-string="));
      if (split >= 0) {
        const w = rest[split] as string;
        const s = w.startsWith("--split-string=") ? w.slice("--split-string=".length) : rest[split + 1];
        if (s !== undefined) walk(s, depth + 1, out);
        return;
      }
    }
    if (head === "eval") {
      walk(rest.join(" "), depth + 1, out);
      return;
    }
    if (SHELLS.has(head)) {
      const c = shellCommandString(rest);
      if (c !== undefined) walk(c, depth + 1, out);
      return;
    }
    if (!WRAPPERS.has(head)) break;
    if (head === "xargs") fromStdin = true;
    const next = rest.findIndex((w) => !ASSIGNMENT.test(w) && isHead(w));
    if (next < 0) return;
    words = rest.slice(next);
    // xargs appends what it reads to the command: a package the gate never sees.
    if (head === "xargs") words = [...words, STDIN_WORD];
  }
  if (!words.length) return;
  const before = out.length;
  readManager(words, depth, out);
  if (fromStdin) for (const inst of out.slice(before)) if (!inst.unseen.includes("stdin")) inst.unseen.push("stdin");
}

function readManager(words: string[], depth: number, out: Install[]): void {
  const head = base(words[0] as string);
  const rest = words.slice(1);
  if (head === "npm") return npm(rest, out, depth);
  if (head === "npx") return npx(rest, "npm", out, depth);
  if (head === "pnpm" || head === "pn") return pnpm(rest, out, depth);
  if (head === "pnpx" || head === "pnx") return dlx(rest, "pnpm", out);
  if (head === "yarn" || head === "yarnpkg") return yarn(rest, out, depth);
  if (head === "bun") return bun(rest, out);
  if (head === "bunx") return bunx(rest, out);
  if (PIP.test(head)) return pip(rest, "pip", out);
  if (PYTHON.test(head) || head === "py") {
    const m = pythonModule(rest);
    if (m === undefined) return;
    if (PIP.test(m.module)) return pip(m.args, "pip", out);
    if (m.module === "uv") return uv(m.args, out);
    if (m.module === "pipx") return pipx(m.args, out);
    return;
  }
  if (head === "uv") return uv(rest, out);
  if (head === "uvx") return uvRun(rest, out);
  if (head === "poetry") return poetry(rest, out);
  if (head === "pdm") return pdm(rest, out);
  if (head === "pipx") return pipx(rest, out);
  if (head === "cargo") return cargo(rest, out);
  if (head === "go") return go(rest, out);
}

/** `-c <string>` (or a combined short flag holding `c`, as `-lc`). */
function shellCommandString(words: string[]): string | undefined {
  for (let i = 0; i < words.length; i++) {
    const w = words[i] as string;
    if (w === "--") return undefined;
    if (!w.startsWith("-")) return undefined;
    if (/^-[a-z]*c[a-z]*$/.test(w)) return words[i + 1];
    if (w === "-o" || w === "+o") i++;
  }
  return undefined;
}

/** `python -m <module> args`, past the interpreter's own flags. The text is
 * folded, so `-W <arg>` and `-X <opt>` arrive as `-w` and `-x`, and `-x`
 * (skip the first line) as `-x` too: a word after `-w` or `-x` is skipped as
 * a possible value, and the scan stops at `-c` or a script path. */
function pythonModule(words: string[]): { module: string; args: string[] } | undefined {
  for (let i = 0; i < words.length; i++) {
    const w = words[i] as string;
    if (w === "-m") {
      const m = words[i + 1];
      return m === undefined ? undefined : { module: m, args: words.slice(i + 2) };
    }
    if (w.startsWith("-m") && w.length > 2 && !w.startsWith("--")) return { module: w.slice(2), args: words.slice(i + 1) };
    if (w === "-c" || w === "--") return undefined;
    if (w.startsWith("-")) continue;
    const prev = words[i - 1];
    if (prev === "-w" || prev === "-x") continue;
    return undefined;
  }
  return undefined;
}

// --- Specs ------------------------------------------------------------------

const NPM_NAME = /^(@[a-z0-9~][a-z0-9._~-]*\/)?[a-z0-9~][a-z0-9._~-]*$/;
const PYPI_NAME = /^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$/;
const CRATE_NAME = /^[a-z0-9_-]{1,64}$/;
const GO_PATH = /^[a-z0-9-]+(\.[a-z0-9-]+)+(\/[a-z0-9._~+-]+)*$/;
const VERSION = /^[a-z0-9.^~<>=!*+_, -]{1,64}$/;

function looksLikeUrl(spec: string): boolean {
  return /^[a-z][a-z0-9+.-]*:\/\//.test(spec) || spec.startsWith("git@");
}

function looksLikePath(spec: string): boolean {
  return spec.startsWith(".") || spec.startsWith("/") || spec.startsWith("~") || spec.startsWith("file:") || /\.(tgz|tar\.gz|tar|zip|whl)$/.test(spec);
}

type Spec = { pkg: Package } | { unseen: Unseen };

function cleanVersion(v: string): string | null {
  if (v === "") return null;
  return VERSION.test(v) ? v : null;
}

/** An npm-style spec: `name`, `name@range`, `@scope/name@range`, `alias@npm:real@range`. */
export function npmSpec(spec: string): Spec {
  if (spec.startsWith("git+") || spec.startsWith("github:") || spec.startsWith("gitlab:") || spec.startsWith("bitbucket:") || spec.startsWith("gist:")) return { unseen: "git" };
  if (looksLikeUrl(spec)) return { unseen: "url" };
  if (looksLikePath(spec)) return { unseen: "path" };
  if (spec.startsWith("workspace:") || spec.startsWith("link:") || spec.startsWith("portal:") || spec.startsWith("patch:")) return { unseen: "path" };
  const at = spec.indexOf("@", 1);
  let name = at > 0 ? spec.slice(0, at) : spec;
  let range = at > 0 ? spec.slice(at + 1) : "";
  if (range.startsWith("npm:")) {
    const inner = npmSpec(range.slice(4));
    return inner;
  }
  if (range.startsWith("git") || range.startsWith("http") || range.startsWith("file:") || range.includes("/")) return { unseen: range.startsWith("file:") ? "path" : "git" };
  if (!NPM_NAME.test(name)) {
    // `user/repo` is a GitHub shorthand: a git source.
    if (/^[a-z0-9._-]+\/[a-z0-9._-]+(#.*)?$/.test(spec)) return { unseen: "git" };
    return { unseen: "spec" };
  }
  const version = range === "" ? null : cleanVersion(range);
  if (range !== "" && version === null) return { unseen: "spec" };
  name = name.slice(0, 214);
  return { pkg: { name, version } };
}

/** A PEP 508 requirement as a command names it: `name`, `name[extra]==1.0`, `name>=2`. */
export function pypiSpec(spec: string, poetryAt = false): Spec {
  if (spec.startsWith("git+") || spec.startsWith("hg+") || spec.startsWith("svn+") || spec.startsWith("bzr+")) return { unseen: "git" };
  if (looksLikeUrl(spec)) return { unseen: "url" };
  if (looksLikePath(spec)) return { unseen: "path" };
  const m = /^([a-z0-9][a-z0-9._-]*)(\[[a-z0-9._, -]*\])?\s*(.*)$/.exec(spec);
  if (m === null) return { unseen: "spec" };
  const name = (m[1] as string).replace(/[-_.]+/g, "-");
  if (!PYPI_NAME.test(name)) return { unseen: "spec" };
  let rest = (m[3] as string).trim();
  if (rest.startsWith("@")) {
    if (poetryAt) rest = rest.slice(1).trim();
    else return { unseen: "url" };
  }
  if (rest.startsWith(";")) rest = "";
  const semi = rest.indexOf(";");
  if (semi >= 0) rest = rest.slice(0, semi).trim();
  if (rest.startsWith("===")) rest = rest.slice(3);
  else if (rest.startsWith("==")) rest = rest.slice(2);
  const version = rest === "" ? null : cleanVersion(rest);
  if (rest !== "" && version === null) return { unseen: "spec" };
  return { pkg: { name, version } };
}

function crateSpec(spec: string): Spec {
  if (looksLikeUrl(spec)) return { unseen: "url" };
  if (looksLikePath(spec)) return { unseen: "path" };
  const at = spec.indexOf("@");
  const name = at >= 0 ? spec.slice(0, at) : spec;
  const range = at >= 0 ? spec.slice(at + 1) : "";
  if (!CRATE_NAME.test(name)) return { unseen: "spec" };
  const version = range === "" ? null : cleanVersion(range.replace(/^=/, ""));
  if (range !== "" && version === null) return { unseen: "spec" };
  return { pkg: { name, version } };
}

function goSpec(spec: string): Spec | undefined {
  // A local pattern (`.`, `./...`, `./cmd/x`) is the module's own code.
  if (spec === "." || spec.startsWith("./") || spec.startsWith("../") || spec.startsWith("/") || spec === "all" || spec === "...") return undefined;
  const at = spec.indexOf("@");
  const path = at >= 0 ? spec.slice(0, at) : spec;
  const range = at >= 0 ? spec.slice(at + 1) : "";
  if (range === "none") return undefined;
  if (!GO_PATH.test(path.replace(/\/\.\.\.$/, ""))) return { unseen: "spec" };
  const version = range === "" ? null : cleanVersion(range);
  if (range !== "" && version === null) return { unseen: "spec" };
  return { pkg: { name: path.replace(/\/\.\.\.$/, ""), version } };
}

// --- Argument walking --------------------------------------------------------

type Args = { positionals: string[]; values: Map<string, string[]>; flags: Set<string>; afterDashDash: string[] };

/**
 * Splits words into flags and positionals. `valued` names the flags that take
 * the next word as their value; any other flag takes none, so a word after an
 * unknown flag is read as a package: the side that fails safe (it can only
 * add a name to the card, never hide one). `--flag=value` is always a value.
 */
function args(words: string[], valued: readonly string[], stopAtFirstPositional = false): Args {
  const a: Args = { positionals: [], values: new Map(), flags: new Set(), afterDashDash: [] };
  for (let i = 0; i < words.length; i++) {
    const w = words[i] as string;
    if (w === "--") {
      a.afterDashDash = words.slice(i + 1);
      break;
    }
    if (w.startsWith("-") && w !== "-") {
      const eq = w.indexOf("=");
      if (eq > 0) {
        push(a.values, w.slice(0, eq), w.slice(eq + 1));
        continue;
      }
      if (valued.includes(w) && i + 1 < words.length) {
        push(a.values, w, words[i + 1] as string);
        i++;
        continue;
      }
      a.flags.add(w);
      continue;
    }
    a.positionals.push(w);
    if (stopAtFirstPositional) {
      a.afterDashDash = words.slice(i + 1);
      break;
    }
  }
  return a;
}

function push(m: Map<string, string[]>, k: string, v: string): void {
  const list = m.get(k);
  if (list === undefined) m.set(k, [v]);
  else list.push(v);
}

function valuesOf(a: Args, ...names: string[]): string[] {
  return names.flatMap((n) => a.values.get(n) ?? []);
}

function has(a: Args, ...names: string[]): boolean {
  return names.some((n) => a.flags.has(n) || a.values.has(n));
}

function build(manager: Manager, form: Form, specs: string[], read: (s: string) => Spec | undefined, extra: Unseen[] = []): Install {
  const inst: Install = { manager, form, packages: [], unseen: [...extra] };
  for (const s of specs) {
    if (s === STDIN_WORD) {
      if (!inst.unseen.includes("stdin")) inst.unseen.push("stdin");
      continue;
    }
    const r = read(s);
    if (r === undefined) continue;
    if ("pkg" in r) inst.packages.push(r.pkg);
    else if (!inst.unseen.includes(r.unseen)) inst.unseen.push(r.unseen);
  }
  return inst;
}

function registryFlags(a: Args, names: string[]): Unseen[] {
  return has(a, ...names) ? ["registry"] : [];
}

/** The first word that names one of `known`, past flags and their values. A word
 * that is not a known subcommand may be an unknown flag's value, so the scan
 * goes on to the next word (the side that fails safe). */
function subcommand(words: string[], known: ReadonlySet<string>, valued: readonly string[]): { name: string; rest: string[] } | undefined {
  for (let i = 0; i < words.length; i++) {
    const w = words[i] as string;
    if (w === "--") return undefined;
    if (w.startsWith("-")) {
      if (!w.includes("=") && valued.includes(w)) i++;
      continue;
    }
    if (known.has(w)) return { name: w, rest: [...words.slice(0, i), ...words.slice(i + 1)] };
  }
  return undefined;
}

// --- npm ---------------------------------------------------------------------

const NPM_INSTALL = new Set(["install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall", "add", "install-test", "it"]);
const NPM_UPDATE = new Set(["update", "up", "upgrade", "udpate"]);
const NPM_EXEC = new Set(["exec", "x"]);
const NPM_KNOWN = new Set([...NPM_INSTALL, ...NPM_UPDATE, ...NPM_EXEC, "ci", "clean-install", "install-clean", "isntall-clean", "install-ci-test", "cit", "clean-install-test", "sit", "run", "run-script", "rum", "urn", "test", "t", "tst", "start", "stop", "restart", "ls", "list", "la", "ll", "view", "info", "show", "v", "outdated", "audit", "uninstall", "remove", "rm", "r", "un", "unlink", "prune", "dedupe", "ddp", "find-dupes", "rebuild", "rb", "init", "create", "innit", "pack", "publish", "config", "c", "get", "set", "cache", "help", "explain", "why", "query", "pkg", "version", "doctor", "root", "prefix", "bin", "link", "ln", "approve-scripts", "deny-scripts", "install-scripts", "sbom", "search", "fund", "login", "logout", "whoami", "token", "owner", "access", "team", "org", "profile", "star", "stars", "unstar", "repo", "docs", "home", "bugs", "issues", "edit", "explore", "diff", "dist-tag", "deprecate", "undeprecate", "unpublish", "ping", "completion", "hook", "shrinkwrap", "stage", "trust", "patch"]);
// Lowercase, as the folded text is. `-p` is not here: `npm install -P` (save-prod)
// folds to `-p`; only `npx` and `npm exec` read `-p` as `--package`.
const NPM_VALUED = ["-w", "--workspace", "--prefix", "-c", "--call", "--registry", "--userconfig", "--globalconfig", "--cache", "--omit", "--include", "--install-strategy", "--cpu", "--os", "--libc", "--before", "--min-release-age", "--min-release-age-exclude", "--allow-scripts", "--allow-directory", "--allow-file", "--allow-git", "--allow-remote", "--tag", "--loglevel", "--package"];
const NPM_REGISTRY = ["--registry"];

function npm(words: string[], out: Install[], depth: number): void {
  const sub = subcommand(words, NPM_KNOWN, NPM_VALUED);
  if (sub === undefined) return;
  if (NPM_EXEC.has(sub.name)) return npx(sub.rest, "npm", out, depth);
  const a = args(sub.rest, NPM_VALUED);
  if (NPM_INSTALL.has(sub.name)) {
    // A bare install reinstalls what package.json and the lockfile name.
    if (a.positionals.length === 0) return;
    out.push(build("npm", "add", a.positionals, npmSpec, registryFlags(a, NPM_REGISTRY)));
    return;
  }
  if (NPM_UPDATE.has(sub.name)) {
    const inst = build("npm", "add", a.positionals, npmSpec, ["update", ...registryFlags(a, NPM_REGISTRY)]);
    out.push(inst);
  }
}

/** `npx` and `npm exec`: `--package`/`-p` names the packages, else the first word. */
function npx(words: string[], manager: Manager, out: Install[], depth: number): void {
  const a = args(words, ["-p", "--package", "-c", "--call", "-w", "--workspace", "--registry", "--prefix", "--cache", "--userconfig", "--loglevel"], true);
  const call = valuesOf(a, "-c", "--call");
  for (const c of call) walk(c, depth + 1, out);
  const pkgs = valuesOf(a, "-p", "--package");
  const first = a.positionals[0] ?? a.afterDashDash.find((w) => !w.startsWith("-"));
  const specs = pkgs.length ? pkgs : first !== undefined && call.length === 0 ? [first] : [];
  if (!specs.length) return;
  out.push(build(manager, "run", specs, npmSpec, registryFlags(a, NPM_REGISTRY)));
}

// --- pnpm --------------------------------------------------------------------

const PNPM_ADD = new Set(["add", "install", "i"]);
const PNPM_UPDATE = new Set(["update", "up", "upgrade"]);
const PNPM_KNOWN = new Set([...PNPM_ADD, ...PNPM_UPDATE, "dlx", "exec", "run", "test", "t", "start", "ls", "list", "ll", "why", "outdated", "audit", "remove", "rm", "uninstall", "un", "prune", "rebuild", "rb", "store", "init", "create", "pack", "publish", "config", "c", "link", "ln", "unlink", "import", "fetch", "patch", "patch-commit", "dedupe", "setup", "env", "root", "bin", "licenses", "approve-builds", "ignored-builds", "deploy", "doctor", "server", "self-update", "cat-file", "cat-index", "find-hash", "recursive", "sbom", "view", "info"]);
// `-C` and `-F` arrive folded as `-c` and `-f`.
const PNPM_VALUED = ["-c", "--dir", "-f", "--filter", "--filter-prod", "--workspace-dir", "--store-dir", "--state-dir", "--virtual-store-dir", "--global-dir", "--registry", "--loglevel", "--reporter", "--cpu", "--os", "--libc", "--allow-build", "--lockfile-dir", "--save-prefix", "--save-catalog-name", "--env-file", "--npmrc-auth-file", "--workspace-packages", "--https-proxy", "--http-proxy", "--no-proxy", "--package", "--changed-files-ignore-pattern", "--test-pattern"];

function pnpm(words: string[], out: Install[], depth: number): void {
  void depth;
  const sub = subcommand(words, PNPM_KNOWN, PNPM_VALUED);
  if (sub === undefined) return;
  if (sub.name === "dlx") return dlx(sub.rest, "pnpm", out);
  const a = args(sub.rest, PNPM_VALUED);
  if (PNPM_ADD.has(sub.name)) {
    if (a.positionals.length === 0) return;
    out.push(build("pnpm", "add", a.positionals, npmSpec, registryFlags(a, ["--registry"])));
    return;
  }
  if (PNPM_UPDATE.has(sub.name)) out.push(build("pnpm", "add", a.positionals, npmSpec, ["update", ...registryFlags(a, ["--registry"])]));
}

/** `pnpm dlx`, `pnpx`, `pnx`, `yarn dlx`: `--package`/`-p` names the packages, else the command's first word. */
function dlx(words: string[], manager: Manager, out: Install[]): void {
  // `-c` is shell mode here, a switch; `-p` is `--package` (yarn).
  const a = args(words, ["--package", "-p", "--allow-build", "--cpu", "--os", "--libc", "--registry", "--dir"], true);
  const pkgs = valuesOf(a, "--package", "-p");
  let first = a.positionals[0];
  if (has(a, "-c", "--shell-mode") && first !== undefined) {
    // Shell mode: the command is a shell string; its first word names the
    // package when no `--package` does.
    first = commands(first)[0]?.[0];
  }
  const specs = pkgs.length ? pkgs : first !== undefined ? [first] : [];
  if (!specs.length) return;
  out.push(build(manager, "run", specs, npmSpec, registryFlags(a, ["--registry"])));
}

// --- yarn --------------------------------------------------------------------

const YARN_KNOWN = new Set(["add", "dlx", "global", "up", "upgrade", "install", "run", "test", "remove", "info", "why", "list", "workspace", "workspaces", "exec", "node", "npm", "set", "config", "cache", "init", "pack", "plugin", "constraints", "dedupe", "explain", "patch", "rebuild", "unlink", "link", "bin", "outdated", "audit", "autoclean", "check", "create", "generate-lock-entry", "import", "licenses", "login", "logout", "owner", "policies", "publish", "tag", "team", "version", "versions"]);
// `-p` is not here: `yarn add -P` (peer) folds to `-p`; `yarn dlx` reads it.
const YARN_VALUED = ["--cwd", "--mode", "--package", "--use-yarnrc", "--modules-folder", "--cache-folder", "--registry", "--network-timeout", "--network-concurrency", "--mutex", "--global-folder", "--link-folder"];

function yarn(words: string[], out: Install[], depth: number): void {
  const sub = subcommand(words, YARN_KNOWN, YARN_VALUED);
  if (sub === undefined) return;
  if (sub.name === "dlx") return dlx(sub.rest, "yarn", out);
  if (sub.name === "workspace") {
    // `yarn workspace <name> add <pkg>`: the workspace's name, then a command.
    const a = args(sub.rest, YARN_VALUED, true);
    return yarn(a.afterDashDash, out, depth);
  }
  if (sub.name === "global") return yarn(sub.rest, out, depth);
  const a = args(sub.rest, YARN_VALUED);
  if (sub.name === "add") {
    if (a.positionals.length === 0) return;
    out.push(build("yarn", "add", a.positionals, npmSpec, registryFlags(a, ["--registry"])));
    return;
  }
  if (sub.name === "up" || sub.name === "upgrade") out.push(build("yarn", "add", a.positionals, npmSpec, ["update"]));
}

// --- bun ---------------------------------------------------------------------

const BUN_KNOWN = new Set(["add", "a", "install", "i", "x", "update", "run", "test", "remove", "rm", "pm", "link", "unlink", "outdated", "audit", "info", "why", "publish", "patch", "init", "create", "c", "build", "upgrade", "repl", "exec"]);
// `-F` arrives as `-f`. `-p` is `--production` for add and install, `--package` for bunx.
const BUN_VALUED = ["-c", "--config", "--cwd", "--registry", "--backend", "--cache-dir", "--ca", "--cafile", "--env-file", "--concurrent-scripts", "--network-concurrency", "--omit", "--linker", "--minimum-release-age", "--minimum-release-age-excludes", "--cpu", "--os", "--libc", "-f", "--filter", "--catalog"];

function bun(words: string[], out: Install[]): void {
  const sub = subcommand(words, BUN_KNOWN, BUN_VALUED);
  if (sub === undefined) return;
  if (sub.name === "x") return bunx(sub.rest, out);
  const a = args(sub.rest, BUN_VALUED);
  if (sub.name === "add" || sub.name === "a" || sub.name === "install" || sub.name === "i") {
    if (a.positionals.length === 0) return;
    out.push(build("bun", "add", a.positionals, npmSpec, registryFlags(a, ["--registry"])));
    return;
  }
  if (sub.name === "update") out.push(build("bun", "add", a.positionals, npmSpec, ["update"]));
}

function bunx(words: string[], out: Install[]): void {
  const a = args(words, [...BUN_VALUED, "-p", "--package"], true);
  const pkgs = valuesOf(a, "-p", "--package");
  const first = a.positionals[0];
  const specs = pkgs.length ? pkgs : first !== undefined ? [first] : [];
  if (!specs.length) return;
  out.push(build("bun", "run", specs, npmSpec, registryFlags(a, ["--registry"])));
}

// --- pip ---------------------------------------------------------------------

// `-C` folds to `-c` (both take a value). `-I` (ignore-installed) folds to `-i`,
// read as `--index-url`: that asks (a registry other than the default).
const PIP_VALUED = ["-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-t", "--target", "--config-settings", "-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--platform", "--python-version", "--implementation", "--abi", "--root", "--prefix", "--src", "--upgrade-strategy", "--build-constraint", "--no-binary", "--only-binary", "--progress-bar", "--root-user-action", "--report", "--log", "--proxy", "--retries", "--timeout", "--exists-action", "--trusted-host", "--cert", "--client-cert", "--cache-dir", "--use-feature", "--use-deprecated", "--keyring-provider", "--python", "--resume-retries", "--uploaded-prior-to", "--requirements-from-script", "--refresh-package", "--all-releases", "--only-final", "--group"];
const PIP_REGISTRY = ["-i", "--index-url", "--extra-index-url", "-f", "--find-links"];

function pip(words: string[], manager: Manager, out: Install[]): void {
  const sub = subcommand(words, new Set(["install", "download", "wheel", "uninstall", "list", "show", "freeze", "check", "config", "cache", "index", "inspect", "hash", "help", "debug", "completion", "lock"]), PIP_VALUED);
  if (sub === undefined || sub.name !== "install") return;
  const a = args(sub.rest, PIP_VALUED);
  const extra: Unseen[] = [...registryFlags(a, PIP_REGISTRY)];
  if (has(a, "-r", "--requirement", "--requirements-from-script", "--group")) extra.push("requirements");
  if (has(a, "-e", "--editable")) extra.push("path");
  const specs = joinAtUrls(a.positionals);
  if (specs.length === 0 && extra.length === 0) return;
  out.push(build(manager, "add", specs, (s) => pypiSpec(s), extra));
}

/** `name @ url` arrives as three words: keep it one spec so it reads as a URL. */
function joinAtUrls(words: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < words.length; i++) {
    const w = words[i] as string;
    if (words[i + 1] === "@" && words[i + 2] !== undefined) {
      out.push(`${w} @ ${words[i + 2]}`);
      i += 2;
    } else out.push(w);
  }
  return out;
}

// --- uv ----------------------------------------------------------------------

const UV_GLOBAL_VALUED = ["--directory", "--project", "--cache-dir", "--config-file", "--color", "--python", "-p", "--allow-insecure-host"];
// `-P` (upgrade-package) folds into `-p` (python) and `-C` into `-c`: both take a value.
const UV_VALUED = [...UV_GLOBAL_VALUED, "--bounds", "--branch", "--rev", "--tag", "--config-setting", "--config-settings-package", "--constraints", "-c", "--default-index", "--exclude-newer", "--exclude-newer-package", "--extra", "--extra-index-url", "--find-links", "-f", "--fork-strategy", "--group", "--index", "--index-strategy", "--index-url", "-i", "--keyring-provider", "--link-mode", "--marker", "-m", "--no-binary-package", "--no-build-isolation-package", "--no-build-package", "--no-install-package", "--no-sources-package", "--optional", "--package", "--prerelease", "--prerelease-package", "--refresh-package", "--reinstall-package", "--requirements", "-r", "--resolution", "--script", "--upgrade-group", "--upgrade-package", "--build-constraints", "-b", "--editable", "-e", "--excludes", "--no-binary", "--only-binary", "--output-format", "--overrides", "--prefix", "--python-platform", "--python-version", "--target", "-t", "--torch-backend", "--env-file", "--from", "--with", "-w", "--with-editable", "--with-requirements", "--with-executables-from", "--no-editable-package"];
const UV_REGISTRY = ["--index", "--index-url", "-i", "--default-index", "--extra-index-url", "--find-links", "-f"];
const UV_KNOWN = new Set(["add", "pip", "tool", "run", "sync", "lock", "remove", "init", "tree", "export", "venv", "build", "publish", "python", "cache", "self", "version", "help", "format", "auth"]);

function uv(words: string[], out: Install[]): void {
  const sub = subcommand(words, UV_KNOWN, UV_VALUED);
  if (sub === undefined) return;
  if (sub.name === "pip") {
    const inner = subcommand(sub.rest, new Set(["install", "sync", "compile", "uninstall", "list", "show", "freeze", "check", "tree"]), UV_VALUED);
    if (inner === undefined || inner.name !== "install") return;
    const a = args(inner.rest, UV_VALUED);
    const extra: Unseen[] = [...registryFlags(a, UV_REGISTRY)];
    if (has(a, "-r", "--requirements")) extra.push("requirements");
    if (has(a, "-e", "--editable")) extra.push("path");
    const specs = joinAtUrls(a.positionals);
    if (specs.length === 0 && extra.length === 0) return;
    out.push(build("uv", "add", specs, (s) => pypiSpec(s), extra));
    return;
  }
  if (sub.name === "tool") {
    const inner = subcommand(sub.rest, new Set(["run", "install", "upgrade", "list", "uninstall", "update-shell", "dir"]), UV_VALUED);
    if (inner === undefined) return;
    if (inner.name === "run") return uvRun(inner.rest, out);
    if (inner.name === "install") {
      const a = args(inner.rest, UV_VALUED);
      const specs = [...joinAtUrls(a.positionals), ...valuesOf(a, "--with", "-w", "--with-executables-from")];
      const extra: Unseen[] = [...registryFlags(a, UV_REGISTRY)];
      if (has(a, "--with-requirements")) extra.push("requirements");
      if (has(a, "--with-editable")) extra.push("path");
      out.push(build("uv", "add", specs, (s) => pypiSpec(s), extra));
    }
    if (inner.name === "upgrade") out.push(build("uv", "add", [], (s) => pypiSpec(s), ["update"]));
    return;
  }
  const a = args(sub.rest, UV_VALUED);
  if (sub.name === "add") {
    const extra: Unseen[] = [...registryFlags(a, UV_REGISTRY)];
    if (has(a, "-r", "--requirements")) extra.push("requirements");
    if (has(a, "--editable", "-e")) extra.push("path");
    const specs = joinAtUrls(a.positionals);
    if (specs.length === 0 && extra.length === 0) return;
    out.push(build("uv", "add", specs, (s) => pypiSpec(s), extra));
    return;
  }
  if ((sub.name === "sync" || sub.name === "lock" || sub.name === "run") && has(a, "-u", "--upgrade", "--upgrade-package")) {
    out.push(build("uv", "add", [], (s) => pypiSpec(s), ["update"]));
  }
  if (sub.name === "run") {
    // `uv run --with <pkg>` installs into a throwaway environment.
    const withs = valuesOf(a, "--with", "-w");
    const extra: Unseen[] = has(a, "--with-requirements") ? ["requirements"] : [];
    if (withs.length || extra.length) out.push(build("uv", "run", withs, (s) => pypiSpec(s), [...extra, ...registryFlags(a, UV_REGISTRY)]));
  }
}

/** `uvx` and `uv tool run`: `--from` names the package, else the command (`ruff@0.5`). */
function uvRun(words: string[], out: Install[]): void {
  const a = args(words, UV_VALUED, true);
  const from = valuesOf(a, "--from");
  const first = a.positionals[0];
  const specs = from.length ? from : first !== undefined ? [first.includes("@") && !first.includes(" @ ") ? first.replace("@", "==") : first] : [];
  const withs = valuesOf(a, "--with", "-w");
  const extra: Unseen[] = [...registryFlags(a, UV_REGISTRY)];
  if (has(a, "--with-requirements")) extra.push("requirements");
  if (has(a, "--with-editable")) extra.push("path");
  if (!specs.length && !withs.length) return;
  out.push(build("uv", "run", [...specs, ...withs], (s) => pypiSpec(s), extra));
}

// --- poetry, pdm, pipx -------------------------------------------------------

// Folded: `-G` is `-g`, `-P` is `-p`, `-C` is `-c`. `-E` (extras) folds into `-e`
// (editable, a switch): read as a switch, so an extra may show as a name.
const POETRY_VALUED = ["-g", "--group", "--extras", "--optional", "--python", "--platform", "--markers", "--source", "-p", "--project", "-c", "--directory"];

function poetry(words: string[], out: Install[]): void {
  const sub = subcommand(words, new Set(["add", "update", "install", "lock", "sync", "remove", "show", "run", "build", "publish", "init", "new", "check", "config", "env", "cache", "export", "list", "search", "self", "source", "version", "debug", "about", "help", "python"]), POETRY_VALUED);
  if (sub === undefined) return;
  const a = args(sub.rest, POETRY_VALUED);
  const extra = registryFlags(a, ["--source"]);
  if (sub.name === "add") {
    if (a.positionals.length === 0) return;
    out.push(build("poetry", "add", a.positionals, (s) => pypiSpec(s, true), extra));
  }
  if (sub.name === "update") out.push(build("poetry", "add", a.positionals, (s) => pypiSpec(s, true), ["update", ...extra]));
  if (sub.name === "self") {
    const inner = subcommand(sub.rest, new Set(["add", "update", "install"]), POETRY_VALUED);
    if (inner?.name === "add") {
      const b = args(inner.rest, POETRY_VALUED);
      out.push(build("poetry", "add", b.positionals, (s) => pypiSpec(s, true)));
    }
  }
}

// Folded: `-L` is `-l`, `-C` is `-c`. `-G` (group) folds into `-g` (global, a
// switch): read as a switch, so a group name may show as a package name.
const PDM_VALUED = ["-p", "--project", "-l", "--lockfile", "--override", "--venv", "-k", "--skip", "--group", "-e", "--editable", "-c", "--config-setting"];

function pdm(words: string[], out: Install[]): void {
  const sub = subcommand(words, new Set(["add", "update", "install", "sync", "lock", "remove", "list", "run", "build", "publish", "init", "info", "show", "search", "config", "venv", "cache", "export", "import", "fix", "outdated", "self", "use", "python", "py"]), PDM_VALUED);
  if (sub === undefined) return;
  const a = args(sub.rest, PDM_VALUED);
  const extra: Unseen[] = has(a, "-e", "--editable") ? ["path"] : [];
  if (sub.name === "add") {
    if (a.positionals.length === 0 && extra.length === 0) return;
    out.push(build("pdm", "add", a.positionals, (s) => pypiSpec(s), extra));
  }
  if (sub.name === "update") out.push(build("pdm", "add", a.positionals, (s) => pypiSpec(s), ["update"]));
}

const PIPX_VALUED = ["--spec", "--python", "--pip-args", "--suffix", "-i", "--index-url", "--preinstall", "--include-resources-from", "--cooldown", "--app", "--python-args", "--with"];

function pipx(words: string[], out: Install[]): void {
  const sub = subcommand(words, new Set(["install", "install-all", "inject", "upgrade", "upgrade-all", "upgrade-shared", "uninstall", "uninstall-all", "reinstall", "reinstall-all", "list", "interpreter", "run", "runpip", "ensurepath", "environment", "completions", "pin", "unpin"]), PIPX_VALUED);
  if (sub === undefined) return;
  const extra = (a: Args): Unseen[] => [...registryFlags(a, ["-i", "--index-url"]), ...(has(a, "--pip-args") ? (["spec"] as Unseen[]) : [])];
  if (sub.name === "install") {
    const a = args(sub.rest, PIPX_VALUED);
    const specs = [...a.positionals, ...valuesOf(a, "--preinstall")];
    out.push(build("pipx", "add", specs, (s) => pypiSpec(s), extra(a)));
  }
  if (sub.name === "inject") {
    // `pipx inject <venv> <pkg>...`: the first word names the venv.
    const a = args(sub.rest, PIPX_VALUED);
    out.push(build("pipx", "add", a.positionals.slice(1), (s) => pypiSpec(s), extra(a)));
  }
  if (sub.name === "run") {
    const a = args(sub.rest, PIPX_VALUED, true);
    const spec = valuesOf(a, "--spec");
    const specs = spec.length ? spec : a.positionals.slice(0, 1);
    out.push(build("pipx", "run", [...specs, ...valuesOf(a, "--with")], (s) => pypiSpec(s), extra(a)));
  }
  if (sub.name === "upgrade" || sub.name === "upgrade-all") out.push(build("pipx", "add", [], (s) => pypiSpec(s), ["update"]));
}

// --- cargo, go ---------------------------------------------------------------

const CARGO_VALUED = ["--git", "--branch", "--tag", "--rev", "--path", "--base", "--registry", "--index", "--rename", "--features", "-f", "--target", "--manifest-path", "-p", "--package", "--version", "--vers", "--root", "--jobs", "-j", "--target-dir", "--profile", "--bin", "--example", "--color", "--config", "-z", "--message-format", "--lockfile-path", "--precise"];

function cargo(words: string[], out: Install[]): void {
  const sub = subcommand(words, new Set(["add", "install", "update", "build", "b", "check", "c", "run", "r", "test", "t", "remove", "rm", "uninstall", "fetch", "generate-lockfile", "tree", "metadata", "new", "init", "clean", "doc", "fmt", "clippy", "publish", "search", "vendor", "fix", "bench", "help", "login", "logout", "owner", "package", "pkgid", "yank", "info", "locate-project", "report", "rustc", "rustdoc", "verify-project", "version"]), CARGO_VALUED);
  if (sub === undefined) return;
  const a = args(sub.rest, CARGO_VALUED);
  const extra: Unseen[] = [];
  if (has(a, "--git")) extra.push("git");
  if (has(a, "--path")) extra.push("path");
  if (has(a, "--registry", "--index")) extra.push("registry");
  if (sub.name === "add") {
    if (a.positionals.length === 0 && extra.length === 0) return;
    out.push(build("cargo", "add", a.positionals, crateSpec, extra));
  }
  if (sub.name === "install") {
    const version = valuesOf(a, "--version", "--vers")[0];
    const specs = a.positionals.map((p) => (version !== undefined && !p.includes("@") ? `${p}@${version}` : p));
    if (specs.length === 0 && extra.length === 0) return;
    out.push(build("cargo", "add", specs, crateSpec, extra));
  }
  if (sub.name === "update") {
    const named = valuesOf(a, "-p", "--package");
    const precise = valuesOf(a, "--precise")[0];
    const specs = named.map((n) => (precise !== undefined ? `${n}@${precise}` : n));
    out.push(build("cargo", "add", [...specs, ...a.positionals], crateSpec, precise !== undefined && named.length ? [] : ["update"]));
  }
}

function go(words: string[], out: Install[]): void {
  const sub = subcommand(words, new Set(["get", "install", "run", "build", "mod", "test", "vet", "fmt", "generate", "list", "env", "version", "work", "tool", "clean", "doc", "fix", "help", "bug", "telemetry"]), ["-c", "-o", "-tags", "-ldflags", "-gcflags", "-asmflags", "-mod", "-modfile", "-p", "-exec", "-overlay", "-pgo", "-pkgdir", "-toolexec", "-buildmode", "-compiler", "-gccgoflags", "-installsuffix", "-covermode", "-coverpkg"]);
  if (sub === undefined) return;
  const a = args(sub.rest, ["-c", "-o", "-tags", "-ldflags", "-gcflags", "-asmflags", "-mod", "-modfile", "-p", "-exec", "-overlay", "-pgo", "-pkgdir", "-toolexec", "-buildmode", "-compiler", "-gccgoflags", "-installsuffix"]);
  if (sub.name === "get") {
    const extra: Unseen[] = has(a, "-u") ? ["update"] : [];
    const inst = build("go", "add", a.positionals, (s) => goSpec(s), extra);
    if (inst.packages.length || inst.unseen.length) out.push(inst);
    return;
  }
  if (sub.name === "install" || sub.name === "run") {
    // Only `pkg@version` leaves the module: without one, the module's go.mod
    // and go.sum decide what builds (go help install).
    const versioned = (sub.name === "run" ? a.positionals.slice(0, 1) : a.positionals).filter((p) => p.includes("@"));
    if (!versioned.length) return;
    const inst = build("go", sub.name === "run" ? "run" : "add", versioned, (s) => goSpec(s));
    if (inst.packages.length || inst.unseen.length) out.push(inst);
  }
}
