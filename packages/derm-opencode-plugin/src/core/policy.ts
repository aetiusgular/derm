// The policy file and the matcher, lane F's TypeScript reader of
// contracts/policy.md (sections 1 to 4). Tested against
// contracts/fixtures/policy/. Canonical copy: packages/derm-claude-plugin/src/core/.

import { createHash } from "node:crypto";
import { ownedByTrusted } from "./owner.ts";
import { closeSync, fstatSync, openSync, readSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { decodeEscapes, fold } from "./fold.ts";
// Wave 5 lane X's seam (the wave 5 base): package installs, section 6.
import { installDecision, parseInstalls } from "./installs/index.ts";
// Wave 5 lane W: command rules, section 7.
import { commandAllows, commandNarrows, commandProblem, commandReason, headCommands, stdinProgram } from "./command.ts";

export type Action = "allow" | "ask" | "deny";

export type Rule = {
  tool: string;
  harness?: string;
  chat?: string;
  action: Action;
  descriptionSha256?: string;
  /** Section 7: a CLI command's first words; `tool` is then `bash`. */
  command?: string[];
};

export type PolicyFile = {
  version: 1;
  askTimeoutSeconds: number;
  servers: string[];
  rules: Rule[];
};

export type LoadedPolicy = {
  policy: PolicyFile;
  /** Set when the file was missing or bad; the reason of a `no rule` answer names it. */
  problem?: string;
};

export type Call = {
  tool: string;
  harness: string;
  chat?: string;
  description?: string;
  inputText: string;
};

export type Decision = {
  action: Action;
  normalizedTool: string;
  reason: string;
};

export const DEFAULT_ASK_TIMEOUT_SECONDS = 60;
const MAX_POLICY_BYTES = 1024 * 1024;

export function emptyPolicy(): PolicyFile {
  return { version: 1, askTimeoutSeconds: DEFAULT_ASK_TIMEOUT_SECONDS, servers: [], rules: [] };
}

/** `$DERM_POLICY` if set, else `~/.derm/policy.json` (contract, section 1). */
export function policyPath(env: NodeJS.ProcessEnv = process.env): string {
  const fromEnv = env.DERM_POLICY;
  if (fromEnv && fromEnv.trim() !== "") return fromEnv;
  return path.join(homedir(), ".derm", "policy.json");
}

/** The real path of `p`, following links on every part that exists; a missing tail is appended as written. */
function realish(p: string): string {
  const abs = path.resolve(p);
  let head = abs;
  const tail: string[] = [];
  for (;;) {
    try {
      return path.join(realpathSync(head), ...tail.reverse());
    } catch {
      const parent = path.dirname(head);
      if (parent === head) return abs;
      tail.push(path.basename(head));
      head = parent;
    }
  }
}

/** True when `file` is `folder` or lies under it, after links are followed. */
export function insideFolder(file: string, folder: string): boolean {
  const rel = path.relative(realish(folder), realish(file));
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

/**
 * Loads the policy for a hook. A `DERM_POLICY` that points inside the session
 * folder is refused: a project's settings file (Claude Code's
 * `.claude/settings.json` `env`) or a cloned repository can set it there, and
 * the file would then be the project's, not yours. The default
 * `~/.derm/policy.json` is never refused this way (a session may start in HOME).
 */
export function loadPolicyFrom(env: NodeJS.ProcessEnv = process.env, cwd: string = process.cwd()): LoadedPolicy {
  const fromEnv = env.DERM_POLICY?.trim();
  if (fromEnv && path.isAbsolute(fromEnv) && insideFolder(fromEnv, cwd)) {
    return { policy: emptyPolicy(), problem: "DERM_POLICY is inside the session folder, which a project can set; not used" };
  }
  return loadPolicy(policyPath(env));
}

const TOOL_PATTERN = /^(\*|[a-z0-9_]+\/(\*|[a-z0-9_]+)|[a-z0-9_]+)$/;
const HARNESS_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/;
const SERVER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;
const SHA_PATTERN = /^[0-9a-f]{64}$/;

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Validates parsed JSON against contracts/policy.schema.json by hand (the hook
 * has no dependencies). Returns the policy or the first problem found.
 */
export function parsePolicy(value: unknown): PolicyFile | string {
  if (!isPlainObject(value)) return "not an object";
  for (const key of Object.keys(value)) {
    if (!["version", "askTimeoutSeconds", "servers", "rules"].includes(key)) return `unknown field ${key}`;
  }
  if (value.version !== 1) return "version is not 1";
  let askTimeoutSeconds = DEFAULT_ASK_TIMEOUT_SECONDS;
  if (value.askTimeoutSeconds !== undefined) {
    const t = value.askTimeoutSeconds;
    if (typeof t !== "number" || !Number.isInteger(t) || t < 1 || t > 3600) return "askTimeoutSeconds out of range";
    askTimeoutSeconds = t;
  }
  const servers: string[] = [];
  if (value.servers !== undefined) {
    if (!Array.isArray(value.servers)) return "servers is not an array";
    for (const s of value.servers) {
      if (typeof s !== "string" || !SERVER_PATTERN.test(s)) return "bad server name";
      if (servers.includes(s)) return "duplicate server name";
      servers.push(s);
    }
  }
  const rules: Rule[] = [];
  if (value.rules !== undefined) {
    if (!Array.isArray(value.rules)) return "rules is not an array";
    if (value.rules.length > 1000) return "more than 1000 rules";
    for (const [i, r] of value.rules.entries()) {
      if (!isPlainObject(r)) return `rule ${i} is not an object`;
      for (const key of Object.keys(r)) {
        if (!["tool", "harness", "chat", "action", "descriptionSha256", "command"].includes(key)) return `rule ${i}: unknown field ${key}`;
      }
      if (typeof r.tool !== "string" || !TOOL_PATTERN.test(r.tool)) return `rule ${i}: bad tool`;
      if (r.action !== "allow" && r.action !== "ask" && r.action !== "deny") return `rule ${i}: bad action`;
      const rule: Rule = { tool: r.tool, action: r.action };
      if (r.harness !== undefined) {
        if (typeof r.harness !== "string" || !HARNESS_PATTERN.test(r.harness)) return `rule ${i}: bad harness`;
        rule.harness = r.harness;
      }
      if (r.chat !== undefined) {
        if (typeof r.chat !== "string" || r.chat.length < 1 || r.chat.length > 200) return `rule ${i}: bad chat`;
        rule.chat = r.chat;
      }
      if (r.descriptionSha256 !== undefined) {
        if (typeof r.descriptionSha256 !== "string" || !SHA_PATTERN.test(r.descriptionSha256)) return `rule ${i}: bad descriptionSha256`;
        rule.descriptionSha256 = r.descriptionSha256;
      }
      if (r.command !== undefined) {
        // Section 7: a command rule names a shell command, so its tool is
        // `bash`, and a description pin means nothing on it.
        const problem = commandProblem(r.command);
        if (problem !== undefined) return `rule ${i}: ${problem}`;
        if (r.tool !== "bash") return `rule ${i}: a command rule's tool must be bash`;
        if (r.descriptionSha256 !== undefined) return `rule ${i}: a command rule has no descriptionSha256`;
        rule.command = [...(r.command as string[])];
      }
      rules.push(rule);
    }
  }
  return { version: 1, askTimeoutSeconds, servers, rules };
}

/** Why the hook reads no policy on Windows (WW5-3). */
export const WINDOWS_POLICY_PROBLEM =
  "on Windows the hook cannot read who may write the policy file, so it uses none and every call asks";

/**
 * Reads the policy file. Called on the first tool call, never at load (case
 * 46). Missing, unreadable, too large, not JSON, or failing the schema: the
 * empty policy, with the problem named (contract, section 1). Nothing fails open.
 */
export function loadPolicy(file: string = policyPath(), platform: NodeJS.Platform = process.platform): LoadedPolicy {
  // A relative path would resolve inside the project, which an agent can write.
  if (!path.isAbsolute(file)) return { policy: emptyPolicy(), problem: "policy path is not absolute" };
  let fd: number | undefined;
  try {
    fd = openSync(file, "r");
    const st = fstatSync(fd);
    if (!st.isFile()) return { policy: emptyPolicy(), problem: "policy file is not a regular file" };
    // On Windows Node gives a file's mode from its read-only attribute alone
    // (libuv v1.52.1 `src/win/fs.c:1956-1960`, Node 24's) and has no
    // `process.getuid`, so neither check below can read who may write the
    // file: an ordinary file read as "writable by others", and one Everyone
    // may write passed once marked read-only (WW5-3, Windows test w5). Until
    // the hook can read the file's access list it uses no policy there, and
    // every call asks.
    if (platform === "win32") return { policy: emptyPolicy(), problem: WINDOWS_POLICY_PROBLEM };
    if (!ownedByTrusted(st.uid)) return { policy: emptyPolicy(), problem: "policy file owned by another user" };
    if ((st.mode & 0o022) !== 0) return { policy: emptyPolicy(), problem: "policy file writable by group or others" };
    // A folder others can write (such as /tmp) lets them swap the file.
    const dir = statSync(path.dirname(file));
    if ((dir.mode & 0o022) !== 0) return { policy: emptyPolicy(), problem: "policy folder writable by group or others" };
    if (st.size > MAX_POLICY_BYTES) return { policy: emptyPolicy(), problem: "policy file too large" };
    const buf = Buffer.alloc(st.size);
    let read = 0;
    while (read < st.size) {
      const n = readSync(fd, buf, read, st.size - read, read);
      if (n === 0) break;
      read += n;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(buf.subarray(0, read).toString("utf8"));
    } catch {
      return { policy: emptyPolicy(), problem: "policy file is not JSON" };
    }
    const result = parsePolicy(parsed);
    if (typeof result === "string") return { policy: emptyPolicy(), problem: `policy file invalid: ${result}` };
    return { policy: result };
  } catch (error) {
    const code = (error as NodeJS.ErrnoException)?.code;
    return { policy: emptyPolicy(), problem: code === "ENOENT" ? "no policy file" : "policy file unreadable" };
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

// ---------------------------------------------------------------- names

/**
 * Step 7 (integration w2, security finding S5): a Claude Code plugin's
 * server, `plugin_<plugin>_<server>` (Claude Code 2.1.311 names its tools
 * `mcp__plugin_<plugin>_<server>__<tool>`, read in its binary), keeps its
 * whole name, so a rule for `exa/*` does not allow a plugin's server that is
 * also called `exa`. Every bare server it could be (each suffix after a `_`,
 * since plugin and server names both hold `_` after step 1) is a narrowing
 * name: a deny or an ask there still reaches the plugin's copy.
 */
function pluginBareServers(server: string): string[] {
  if (!server.startsWith("plugin_")) return [];
  const rest = server.slice("plugin_".length);
  const out: string[] = [];
  for (let i = rest.indexOf("_"); i >= 0; i = rest.indexOf("_", i + 1)) {
    const bare = rest.slice(i + 1);
    if (bare !== "" && !bare.startsWith("_")) out.push(bare);
  }
  return out;
}

function join(server: string, tool: string): string {
  return server === "" ? tool : `${server}/${tool}`;
}

/** Splits at the first run of two or more `_`, the whole run consumed (Droid's `s___t`; note AQ section 6). */
function splitAtRun(s: string): [string, string] | undefined {
  const d = s.indexOf("__");
  if (d < 0) return undefined;
  let e = d;
  while (e < s.length && s[e] === "_") e++;
  return [s.slice(0, d), s.slice(e)];
}

/** The longest `servers` entry `rest` starts with, followed by `sep`. */
function knownServerPrefix(rest: string, servers: readonly string[], sep: string): string | undefined {
  let best: string | undefined;
  for (const s0 of servers) {
    const s = lowerName(s0);
    if (s !== "" && rest.startsWith(s + sep) && rest.length > s.length + sep.length && (best === undefined || s.length > best.length)) best = s;
  }
  return best;
}

function splitDoubleThenSingle(rest: string, servers: readonly string[] = []): [string, string] {
  // A server the policy names, with `_` or `__` in it, wins over the first
  // run (Claude Code allows a server named `<a>__<b>`; integration w2, S5).
  const known = knownServerPrefix(rest, servers, "__");
  if (known !== undefined) {
    let e = known.length;
    while (e < rest.length && rest[e] === "_") e++;
    return [known, rest.slice(e)];
  }
  const run = splitAtRun(rest);
  if (run) return run;
  const s = rest.indexOf("_");
  if (s >= 0) return [rest.slice(0, s), rest.slice(s + 1)];
  return ["", rest];
}

/** Step 1: trim, ASCII-lowercase, every character outside `[a-z0-9_/]` to `_`. Also applied to each `servers` entry. */
export function lowerName(raw: string): string {
  let lowered = "";
  for (const ch of raw.trim()) {
    const c = ch.length === 1 && ch <= "\x7f" ? ch.toLowerCase() : ch;
    lowered += /^[a-z0-9_/]$/.test(c) ? c : "_";
  }
  return lowered;
}

/**
 * contracts/policy.md section 2, the same steps as derm-core's
 * normalize_tool_name. `harness` is the agent's id: later waves apply the
 * agent's declared name form from its preset row before the generic steps
 * (note AQ section 6). No wave 1 agent declares one, so it is unused here.
 */
export function normalizeToolName(raw: string, servers: readonly string[], harness?: string): string {
  void harness;
  const lowered = lowerName(raw);
  const slash = lowered.indexOf("/");
  if (slash >= 0) return lowered;
  if (lowered.startsWith("mcp__")) return join(...splitDoubleThenSingle(lowered.slice(5), servers));
  if (lowered.startsWith("mcp_")) return join(...splitDoubleThenSingle(lowered.slice(4), servers));
  const run = splitAtRun(lowered);
  if (run) return join(run[0], run[1]);
  let best: string | undefined;
  for (const s0 of servers) {
    const s = lowerName(s0);
    if (lowered.length > s.length + 1 && lowered.startsWith(s) && lowered[s.length] === "_" && (best === undefined || s.length > best.length)) {
      best = s;
    }
  }
  if (best !== undefined) return join(best, lowered.slice(best.length + 1));
  return lowered;
}

/**
 * Separators an agent writes between server and tool other than the plain
 * `__` (after `mcp__`) or `_` (after `mcp_`, or with no prefix): its
 * declared name form (note AQ section 6). Only agents with a built gate are
 * listed; a wave 4 lane adds its agent's form through integration with the
 * tests that show the form cannot fold another server in (integration w2's
 * re-review, W2-R1: Droid's `___`, Copilot's `-` and Vibe's `.` let
 * `exa-evil` pass as `exa`). oh-my-pi's `_` after `mcp__` is its only form,
 * and as ambiguous as OpenCode's `<server>_<tool>` (contracts/policy.md).
 */
export const RAW_SEPARATORS: Readonly<Record<string, readonly string[]>> = {
  "oh-my-pi": ["_"],
};

/**
 * Integration w2 review, W2-S2: whether the raw name spells the chosen split
 * plainly. A server part with capitals or non-ASCII letters, or a separator
 * the fold made (`exa-__t`, `exa.__t`, `exa-evil_t`) or one longer than the
 * form's (`mcp__exa___t`), could be another server's name folded into a
 * listed one, so an allow there asks.
 */
export function splitInDoubt(raw: string, lowered: string, prefix: number, server: string, tool: string, harness?: string): boolean {
  const cps = Array.from(raw.trim());
  if (cps.length !== lowered.length) return true;
  const start = prefix > 0 ? prefix : 0;
  const sepStart = start + server.length;
  const sepEnd = lowered.length - tool.length;
  if (sepEnd <= sepStart) return true;
  const rawServer = cps.slice(start, sepStart).join("");
  if (/[A-Z]|[^\x00-\x7f]/.test(rawServer)) return true;
  const rawSep = cps.slice(sepStart, sepEnd).join("");
  if ((RAW_SEPARATORS[harness ?? ""] ?? []).includes(rawSep)) return false;
  if (rawSep !== lowered.slice(sepStart, sepEnd)) return true;
  if (prefix === 5) return rawSep !== "__";
  if (prefix === 4) return rawSep !== "_";
  return rawSep.length > 2;
}

/**
 * Other names the same call could have (integration w2, security finding
 * S5): a plugin server's bare forms (step 7), and, for an `mcp__` name whose
 * tool part still holds a run of `__` that `servers` does not settle, every
 * other split at a run. A rule on one of these may narrow the answer (a deny,
 * an ask) and never widen it. `ambiguous` is true when the split itself
 * could be wrong, which turns an allow into an ask.
 */
export function narrowingNames(raw: string, servers: readonly string[], harness?: string): { names: string[]; ambiguous: boolean } {
  const primary = normalizeToolName(raw, servers, harness);
  const slash = primary.indexOf("/");
  // A shell under another name is also `bash` (integration w4; case 82):
  // Gemini's run_shell_command, Codex's exec_command, Claude Code's Monitor.
  if (slash < 0) return { names: primary !== "bash" && isShellTool(primary) ? ["bash"] : [], ambiguous: false };
  const names = new Set<string>();
  let ambiguous = false;
  const lowered = lowerName(raw);
  const prefix = lowered.startsWith("mcp__") ? 5 : lowered.startsWith("mcp_") ? 4 : -1;
  const primaryServer = primary.slice(0, slash);
  const splits: Array<[string, string]> = [[primaryServer, primary.slice(slash + 1)]];
  if (prefix > 0) {
    // Every split at a run of `__`. A server the policy lists picks the
    // primary split; it does not prove that no longer server exists, so a
    // split past the primary's still makes the name ambiguous.
    const rest = lowered.slice(prefix);
    for (let d = rest.indexOf("__"); d >= 0; ) {
      let e = d;
      while (e < rest.length && rest[e] === "_") e++;
      const split: [string, string] = [rest.slice(0, d), rest.slice(e)];
      if (split[0] !== "" && split[1] !== "" && join(...split) !== primary) {
        splits.push(split);
        if (split[0].length > primaryServer.length) ambiguous = true;
      }
      d = rest.indexOf("__", e);
    }
  }
  if (splitInDoubt(raw, lowered, prefix, primaryServer, primary.slice(slash + 1), harness)) ambiguous = true;
  for (const [server, tool] of splits) {
    const whole = join(server, tool);
    if (whole !== primary) names.add(whole);
    for (const bare of pluginBareServers(server)) names.add(join(bare, tool));
  }
  return { names: [...names], ambiguous };
}

// ---------------------------------------------------------------- reject list

export const ENDPOINT_KEYS = [
  "anthropic_base_url",
  "chatgpt_base_url",
  "dangerouslydisablesandbox",
  "approval_policy",
  "--dangerously-",
  "settings.local.json",
] as const;

export const GIT_CONFIG_KEYS = [
  "core.fsmonitor",
  "core.hookspath",
  "core.sshcommand",
  "core.pager",
  "core.editor",
  "core.askpass",
  "core.gitproxy",
  "core.attributesfile",
  "sequence.editor",
  "pager.",
  "alias.",
  "gpg.program",
  "gpg.ssh.program",
  "credential.helper",
  "include.path",
  "includeif.",
  "filter.",
  ".driver",
  ".textconv",
  "diff.external",
  "uploadpack",
  "receivepack",
  ".insteadof",
  ".pushinsteadof",
  "protocol.",
  "ext::",
  "fd::",
  "git_allow_protocol",
  "git_ssh",
  "git_proxy_command",
  "git_askpass",
  "git_external_diff",
  "git_config_parameters",
  "git_config_count",
] as const;

export const GIT_CONTEXT_PATHS = [".git/", ".gitmodules", ".gitattributes", ".gitconfig", "git_config"] as const;

// `powershell` is not in the contract's list; lane A added it (Pi 1.4.0 has the tool). A request for integration.
// "monitor" (Claude Code's and OpenClaude's Monitor runs a command; lane L's
// request 5), "shell_command" (Amp, Command Code) and "run_commands" (Cline)
// added by integration w4 (lane P's request 6). Each one's other name is
// `bash` (narrowingNames): a `bash` deny or ask narrows it, a `bash` allow
// does not widen it.
export const SHELL_TOOLS = ["bash", "shell", "exec_command", "local_shell", "run_shell_command", "user_bash", "terminal", "powershell", "monitor", "shell_command", "run_commands"] as const;

/**
 * Files that control derm or a harness's hooks. An `allow` whose folded input
 * names one becomes `ask`, so an allowed tool cannot quietly rewrite the
 * policy or switch the gate off (for example `disableAllHooks` in Claude
 * Code's settings, or the plugin entry in Codex's config). Lane A's list
 * plus each harness's own files. Narrowing only; not in the contract.
 */
export const CONTROL_PATHS = [
  ".derm/",
  "derm/daemon.",
  // The old name's folders: derm never reads them, and while a tk install
  // or a tk-daemon is left on the machine its policy and token stay guarded
  // (rename review R1). Narrowing only.
  ".tk/",
  "tk/daemon.",
  "derm/otlp.endpoint",
  "derm_policy",
  "derm_chat_token",
  ".pi/agent/",
  ".claude/settings",
  ".claude.json",
  ".claude/plugins",
  "disableallhooks",
  "managed-settings",
  ".codex/config.toml",
  ".codex/hooks.json",
  ".codex/plugins",
  "requirements.toml",
  "opencode.json",
  ".config/opencode/",
  ".cache/opencode/",
  // Git's own config and hooks name programs git runs later (rules cases 27,
  // 31; integration w1 security finding S4). The reject list catches dotted
  // keys such as core.fsmonitor; these catch the INI form and hook scripts.
  ".git/config",
  ".git/hooks/",
  ".gitconfig",
  ".config/git/",
  ".gitmodules",
  // A harness's whole project or home folder: settings, hooks, plugins,
  // commands and skills it loads (integration w1, finding S7).
  ".claude/",
  ".codex/",
  ".pi/",
  // Wave 2's agents (lane I's request 2, folded in by integration w2): each
  // one's config and plugin folders and the variables that move them or switch
  // its hooks off. Sources per agent in each adapter's src/control.ts and in
  // plans/parallel/tk_lane_I.md.
  ".gemini/",
  "gemini-cli/",
  "geminicli/",
  "gemini_cli_system",
  ".config/kilo/",
  ".kilo/",
  ".kilocode/",
  "kilo.json",
  "kilo_config",
  "kilo_pure",
  ".hermes/",
  "hermes_home",
  "hermes_safe_mode",
  "hermes_yolo_mode",
  "hermes_enable_project_plugins",
  "hermes_accept_hooks",
  ".openclaw/",
  "openclaw.json",
  "openclaw_config_path",
  "openclaw_state_dir",
  "openclaw_home",
  ".omp/",
  "pi_coding_agent_dir",
  "pi_config_dir",
  "derm_pi_freeze_input",
  // Wave 4's agents (lanes L, N and P's requests, folded in by integration
  // w4): each one's config, hook and plugin folders and the variables that
  // move them or switch the gate off. Sources per agent in each package's
  // src/control.ts and in plans/parallel/tk_lane_L.md, tk_lane_N.md and
  // tk_lane_P.md. Kimi Code's folder is `.kimi-code/` in lane L's run of
  // 2.4.1 and `.kimi/` in lane Q's reading of 1.52.0; both are listed.
  ".openclaude/",
  ".openclaude.json",
  "openclaude_config_dir",
  ".qwen/",
  "qwen_home",
  "qwen_code_system_settings",
  ".factory/",
  "factory_home_override",
  ".commandcode/",
  ".kimi-code/",
  "kimi_code_home",
  ".kimi/",
  "kimi_share_dir",
  ".augment/",
  ".copilot/",
  "copilot_home",
  ".grok/",
  "grok_claude_hooks_enabled",
  "grok_cursor_hooks_enabled",
  "grok_home",
  ".cursor/",
  "cursor/hooks.json",
  ".agents/hooks.json",
  ".agents/plugins/",
  ".config/goose/",
  "goose_path_root",
  "goose_mode",
  "goose_disable_keyring",
  ".vibe/",
  "vibe_home",
  ".config/crush/",
  ".local/share/crush/",
  "crushrc",
  "crush.json",
  "crush_global_config",
  "crush_global_data",
  ".kiro/",
  "kiro_home",
  ".config/amp/",
  ".amp/",
  "amp/plugins",
  "xdg_config_home",
  "ampcode/",
  "dangerouslyallowall",
  ".cline/",
  "documents/cline/",
  ".clinerules",
  "cline_dir",
  "cline_data_dir",
  "cline_tool_approval",
  "cline_plugin_",
  "cline-approvals/",
  "derm-approval/",
  // The sbx kit's folder: its marker, `/opt/derm-kit/sbx-vm`, turns the
  // hook's VM route on, so an allowed call on a host must not write it
  // (integration w5's re-reviews, W5R-7(a) and W5R2-3). The marker's own
  // name too, for `cd /opt/derm-kit && touch sbx-vm`.
  "derm-kit/",
  "sbx-vm",
  // Wave 5b's close (W5B-S1): derm's own program, now the gate for every
  // agent, wherever the plugins' launcher and shims find it, and the
  // variable the in-process plugins read it from.
  "/bin/derm",
  "cellar/derm/",
  "derm_bin",
] as const;

// A folder entry's bare name, for `mv ~/.derm old` and `cd ~/.derm && cp x
// policy.json` (rename review F1; lane L's C-1 and L-S4, lane P's P-S4):
// only for a folder that starts with `.` or holds a `/`, so `gemini-cli` in
// `npm install @google/gemini-cli` is not one, and only where the name stands
// alone: no name character runs into it on the left (`math.pi`) or on the
// right (`.qwenrc`, `.factory-notes`). Anything else after it counts (end,
// space, quote, `;`, `.bak`), which only ever narrows. derm-pi and derm-core
// match the same way; the policy fixtures hold the three equal.
const NAME_CHAR = /[a-z0-9_-]/;
const LEFT_NAME_CHAR = /[a-z0-9_.-]/;

// Each text, and beside it each one that holds a `\` with every `\` read as
// `/` (Windows test w6, WW6-1): a file tool on Windows names a path the way
// Windows writes it (`C:\Users\u\.git\hooks\pre-commit`), and Windows takes
// `\` and `/` alike as separators, so an entry with an inner `/` is also looked
// for there. Only ever adds an ask; run before withCollapsedSlashes. derm-core's
// `with_native_separators`.
export function withNativeSeparators(texts: string[]): string[] {
  const out = [...texts];
  for (const t of texts) if (t.includes("\\")) out.push(t.replace(/\\/g, "/"));
  return out;
}

// Each text, and beside it, where it differs, the text with each part's
// trailing dots and spaces read away (Windows test w6 retest, WW6R-1):
// Windows' path normalization drops a single trailing dot from a part before
// a separator and every trailing dot and space from the last part, so a Win32
// caller writing `.git.\hooks\pre-commit` lands in `.git\hooks` (Jeremy
// Kuhne, "Path Normalization"). A run of dots and spaces is read away where it
// ends a part that holds something else, before `/`, a quote, a separator of
// words or the end of the text; more than Windows does, which only adds an
// ask. `.`, `..` and a part of dots alone are left. Run after
// withNativeSeparators. derm-core's `with_win32_trimmed`.
export function withWin32Trimmed(texts: string[]): string[] {
  const out = [...texts];
  for (const t of texts) {
    const trimmed = win32Trim(t);
    if (trimmed !== t) out.push(trimmed);
  }
  return out;
}

const WIN32_PART_END = new Set(["/", '"', "'", "`", "\n", "\t", "\r", ";", "|", "&", ")", ",", "}", "]"]);
const WIN32_NOT_A_NAME = new Set(["/", '"', "'", "`", "(", "=", ":"]);

function win32Trim(t: string): string {
  const chars = Array.from(t);
  let out = "";
  let i = 0;
  while (i < chars.length) {
    const c = chars[i];
    if (c === "." || c === " ") {
      const start = i;
      while (i < chars.length && (chars[i] === "." || chars[i] === " ")) i++;
      const before = start > 0 ? chars[start - 1] : undefined;
      const named = before !== undefined && !WIN32_NOT_A_NAME.has(before) && !/[ \t\n\f\r]/.test(before);
      const next = chars[i];
      if (named && (next === undefined || WIN32_PART_END.has(next))) continue;
      out += chars.slice(start, i).join("");
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

// The path the shell opens is the same with `//` or `/./` in it, so a
// control path is also looked for in the text with those collapsed to `/`
// (review W4-S5). Only ever adds an ask.
export function withCollapsedSlashes(texts: string[]): string[] {
  const out = [...texts];
  for (const t of texts) {
    const c = t.replace(/\/(?:\.?\/)+/g, "/");
    if (c !== t) out.push(c);
    const d = withoutDotDot(c);
    if (d !== c) out.push(d);
  }
  return out;
}

/**
 * `a/b/../c` read as `a/c`, lexically: each `..` part drops the part before
 * it unless that is empty, `.` or `..` (re-review W4-R4). One pass over the
 * parts, so linear; the text is the whole input, so a part may hold spaces,
 * and a wrong drop only adds a text to look in.
 */
export function withoutDotDot(text: string): string {
  if (!text.includes("..")) return text;
  const out: string[] = [];
  for (const part of text.split("/")) {
    const last = out[out.length - 1];
    if (part === ".." && last !== undefined && last !== "" && last !== "." && last !== "..") out.pop();
    else out.push(part);
  }
  return out.join("/");
}

/** Whether folded `text` names the control path `entry` (contract section 4, step 7a). */
export function namesControlPath(text: string, entry: string): boolean {
  if (text.includes(entry)) return true;
  if (!entry.endsWith("/")) return false;
  const base = entry.slice(0, -1);
  if (!(base.startsWith(".") || base.includes("/"))) return false;
  for (let i = text.indexOf(base); i >= 0; i = text.indexOf(base, i + 1)) {
    const prev = i === 0 ? undefined : text[i - 1];
    const next = text[i + base.length];
    if ((prev === undefined || !LEFT_NAME_CHAR.test(prev)) && (next === undefined || !NAME_CHAR.test(next))) return true;
  }
  return false;
}

/**
 * Secret material (contracts/policy.md section 4, step 7a; integration w6's
 * close, E0's R-E0-2): keys, cloud, registry and database credentials,
 * password stores, shell history and `.env` files, for every tool. From
 * OpenMoat 0.19.0's `secrets-paths` (policies/default-v1.yaml:17-75) and its
 * key-file names (:1336-1338). Matched by `namesEntry`; derm-core's
 * `SECRET_PATHS` and derm-pi's are the same list.
 */
export const SECRET_PATHS = [
  ".ssh/", ".aws/", ".gnupg/", ".config/gh/", ".netrc", ".authinfo", ".docker/config.json",
  ".config/containers/auth.json", ".config/doctl/", ".kube/", ".config/gcloud/", ".azure/",
  ".git-credentials", ".pypirc", ".cargo/credentials", ".gem/credentials", ".pgpass", ".my.cnf",
  ".mylogin.cnf", ".vault-token", ".terraform.d/credentials", ".config/op/", ".password-store/",
  ".local/share/keyrings/", "library/keychains/", ".zsh_history", ".bash_history", ".env", ".envrc",
  "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
  // Windows test w6, WW6-9: gcloud's, gh's and PSReadLine's places on Windows (derm-core's list says where from).
  "appdata/roaming/gcloud/", "appdata/roaming/github cli/", "powershell/psreadline/",
] as const;

/**
 * Files something runs later, outside the call (step 7a; R-E0-2's start-up
 * half and R-E0-3): CI and commit hooks, editor run configurations, package
 * manager configuration that runs code, agent skill, hook and MCP files, and
 * every shell's start-up files with curl's and wget's. From OpenMoat 0.19.0's
 * `runs-later` (:1152-1230) and `shell-rc` (:645-658). A leading `*` matches
 * a suffix. Matched by `namesEntry`; derm-core's and derm-pi's list.
 */
export const RUNS_LATER_PATHS = [
  ".github/workflows/", ".github/agents/", ".github/hooks/", ".github/mcp.json", ".gitlab-ci.yml", ".circleci/",
  "azure-pipelines.yml", "jenkinsfile", ".buildkite/", ".husky/", ".pre-commit-config.yaml", "lefthook.yml",
  ".lefthook.yml", ".githooks/", ".git-hooks/", "githooks/", "git-hooks/", ".vscode/", "*.code-workspace",
  ".idea/", "*.run.xml", ".npmrc", ".yarnrc", ".cargo/config", "bunfig.toml", ".mcp.json", ".agents/",
  ".opencode/", ".continue/", ".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile",
  ".zshrc", ".zshenv", ".zprofile", ".zlogin", ".zlogout", ".config/fish/", ".login", ".cshrc", ".tcshrc",
  ".kshrc", ".mkshrc", ".curlrc", "_curlrc", ".config/curlrc", ".wgetrc", ".config/wget/",
  // Windows test w6, WW6-9: PowerShell's profiles and modules, and the Startup folder (derm-core's list says where from).
  "documents/powershell/", "documents/windowspowershell/", ".config/powershell/", "start menu/programs/startup/",
] as const;

/**
 * Cloud instance metadata and link-local addresses (step 7a; R-E0-5), from
 * OpenMoat 0.19.0's `cloud-metadata` (:659-664). Matched by `namesEntry`, so
 * `10.169.254.1` is not `169.254.`.
 */
export const METADATA_ADDRESSES = ["169.254.", "fe80:", "fd00:ec2:", "100.100.100.200", "168.63.129.16", "192.0.0.192", "fd20:ce::254", "fd00:c1::a9fe:a9fe", "fd00:42::42", "fd00:a9fe:a9fe::1", "fd00:100::100:200", "2852039166", "0xa9fea9fe", "0251.0376.0251.0376", "metadata.google.internal", "metadata.goog"] as const;

// `.env` followed by one of these is a committed template with no values
// (OpenMoat 0.19.0's `.env.example` exception and its siblings, :61-67).
const ENV_TEMPLATES = [".example", ".sample", ".template", ".dist"] as const;

/**
 * Whether folded `text` names `entry` of the lists above as a whole name: no
 * name character runs into it on the left (`.` counts there), and, when it
 * ends in a name character, none on the right. A folder entry also matches
 * its bare name; a leading `*` drops the left check; `.env` followed by a
 * template's suffix is not the file. derm-core's `names_entry`.
 */
export function namesEntry(text: string, entry: string): boolean {
  const suffix = entry.startsWith("*");
  const e = suffix ? entry.slice(1) : entry;
  const base = e.endsWith("/") ? e.slice(0, -1) : e;
  if (base === "") return false;
  const endsInName = NAME_CHAR.test(base[base.length - 1] as string);
  for (let i = text.indexOf(base); i >= 0; i = text.indexOf(base, i + 1)) {
    const prev = i === 0 ? undefined : text[i - 1];
    const after = text.slice(i + base.length);
    const next = after[0];
    const leftOk = suffix || prev === undefined || !LEFT_NAME_CHAR.test(prev);
    // `.env-production` and `.env_local` are `.env` files too (W6C-S3).
    const rightOk = !endsInName || next === undefined || !NAME_CHAR.test(next) || (base === ".env" && (next === "-" || next === "_"));
    // A template only when the whole name ends in its suffix: `.env.example`, not `.env.example.local`.
    let tail = "";
    for (const c of after) {
      if (!NAME_CHAR.test(c) && c !== ".") break;
      tail += c;
    }
    const template = base === ".env" && ENV_TEMPLATES.some((t) => tail.endsWith(t));
    if (leftOk && rightOk && !template) return true;
  }
  return false;
}

/** Step 7a's other lists and the reason each gives (integration w6's close). */
export const MORE_STEP_7A_LISTS: ReadonlyArray<[readonly string[], string]> = [
  [SECRET_PATHS, "a secret path"],
  [RUNS_LATER_PATHS, "a file that runs later"],
  [METADATA_ADDRESSES, "a cloud metadata address"],
];

/** The first entry of step 7a's other lists that `texts` name, with its reason. */
export function moreStep7a(texts: readonly string[]): string | undefined {
  for (const [list, what] of MORE_STEP_7A_LISTS) {
    const entry = list.find((e) => texts.some((t) => namesEntry(t, e)));
    if (entry !== undefined) return `input names ${what} (${entry})`;
  }
  return undefined;
}

/**
 * Shell text the matcher cannot read: expansions, history, braces, tilde,
 * zsh glob qualifiers, a backslash, and (integration w1, finding S1) the glob
 * characters `*`, `?` and `[`, which name files the matcher never sees.
 */
export const UNREADABLE_SHELL_TOKENS = ["$", "`", "!", "{", "}", "~", "(e:", "(+", "(-", "\\", "*", "?", "["] as const;

/**
 * The reason names the first token found (in the list's order), and calls a
 * glob one, so a user can tell why `ls *.md` asks (Mac test w1, finding M9).
 * Starts with the contract's reason, which the fixtures match as a prefix.
 * derm-pi and derm-core write the same text.
 */
export function unreadableReason(token: string): string {
  const glob = token === "*" || token === "?" || token === "[";
  return `shell text the matcher cannot read: \`${token}\`${glob ? " (a glob)" : ""}`;
}

/** Tools that run PowerShell (lane Z's request 3; note AU section 10). */
export const POWERSHELL_TOOLS = ["powershell"] as const;

const PLAIN_POWERSHELL_CHAR = /^[a-z0-9 ._/:=+-]$/;

/**
 * The first character of folded `text` that a plain PowerShell word list
 * does not hold, or undefined. PowerShell quotes, escapes and stops parsing
 * its own way (the backtick, `--%`, `;`, `|`, `&`, `@`, parentheses, and
 * its typographic quotes and dashes; about_Parsing, PowerShell 7.6), which
 * the bash and zsh reader of case 30 does not read, so an allow by command
 * text holds only for letters, digits, spaces and `._/:=+-`.
 */
export function powershellUnplain(folded: string): string | undefined {
  for (const ch of folded) if (!PLAIN_POWERSHELL_CHAR.test(ch)) return ch;
  return undefined;
}

/** The reason for an ask on PowerShell text; derm-pi and derm-core write the same. */
export function powershellReason(ch: string): string {
  const cp = ch.codePointAt(0) ?? 0;
  const shown = cp >= 0x21 && cp <= 0x7e ? ch : `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;
  return `PowerShell text the matcher reads only as plain words: \`${shown}\``;
}

/**
 * The text with every quote removed. The shell joins `ANTHROPIC_"BASE_URL"`
 * and `g''it` into one word, so the reject list and the control files are
 * also read this way (integration w1, finding S1). Only adds matches.
 */
export function unquote(text: string): string {
  return text.replace(/["']/g, "");
}

const GIT_WORD = /(?<![a-z0-9_])git(?![a-z0-9_])/g;

/** contracts/policy.md section 3.2: is folded text a git context? */
export function isGitContext(folded: string): boolean {
  if (GIT_CONTEXT_PATHS.some((p) => folded.includes(p))) return true;
  // A line that ends in `\` continues on the next, as the shell reads it
  // (derm-core's `git_context`; integration w1, finding S10).
  for (const line of folded.replace(/\\\r?\n/g, " ").split(/\r\n|\n|\r/)) {
    GIT_WORD.lastIndex = 0;
    const m = GIT_WORD.exec(line);
    if (!m) continue;
    const after = line.slice(m.index + 3);
    if (after.includes("-c") || after.includes("config") || after.includes("--config-env")) return true;
  }
  return false;
}

/** The first reject-list key the text holds, or undefined. */
export function rejectKey(inputText: string): string | undefined {
  const folded = fold(decodeEscapes(inputText));
  for (const text of [folded, unquote(folded)]) {
    for (const k of ENDPOINT_KEYS) if (text.includes(k)) return k;
    if (isGitContext(text)) for (const k of GIT_CONFIG_KEYS) if (text.includes(k)) return k;
  }
  return undefined;
}

// ---------------------------------------------------------------- matching

function rankOf(rule: Rule): [number, number, number] {
  const tool = rule.tool === "*" ? 0 : rule.tool.endsWith("/*") ? 1 : 2;
  return [rule.chat !== undefined ? 1 : 0, rule.harness !== undefined ? 1 : 0, tool];
}

function compareRank(a: [number, number, number], b: [number, number, number]): number {
  for (let i = 0; i < 3; i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

const SEVERITY: Record<Action, number> = { allow: 0, ask: 1, deny: 2 };

function toolMatches(pattern: string, normalized: string): boolean {
  if (pattern === "*") return true;
  if (pattern === normalized) return true;
  if (pattern.endsWith("/*")) {
    const slash = normalized.indexOf("/");
    return slash >= 0 && normalized.slice(0, slash) === pattern.slice(0, -2);
  }
  return false;
}

export function isShellTool(normalized: string): boolean {
  return (SHELL_TOOLS as readonly string[]).includes(normalized);
}

export function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/** contracts/policy.md section 4, steps 1 to 7, and section 7. Step 8 (the wait) is the caller's. */
export function evaluate(loaded: LoadedPolicy, call: Call): Decision {
  const { policy } = loaded;
  const normalizedTool = normalizeToolName(call.tool, policy.servers, call.harness);
  const key = rejectKey(call.inputText);
  if (key !== undefined) return { action: "deny", normalizedTool, reason: `reject list: ${key}` };

  const applies = (r: Rule) => (r.harness === undefined || r.harness === call.harness) && (r.chat === undefined || r.chat === call.chat);
  // A command rule (section 7) is never a rule for the whole tool: it takes
  // no part in steps 3 to 5 and 3a, only in the section 7 steps below.
  const toolRules = policy.rules.filter((r) => r.command === undefined);
  const matches = toolRules.filter((r) => toolMatches(r.tool, normalizedTool) && applies(r));
  // Section 4 step 3a (S5): rules on the call's other names narrow it. A
  // deny there is a deny; an ask turns an allow into an ask; an allow there
  // counts for nothing. `*` rules already matched the call itself.
  const other = narrowingNames(call.tool, policy.servers, call.harness);
  const narrowing = toolRules.filter((r) => r.tool !== "*" && applies(r) && other.names.some((n) => toolMatches(r.tool, n)));
  const narrowDeny = narrowing.find((r) => r.action === "deny");
  if (narrowDeny !== undefined) return { action: "deny", normalizedTool, reason: `rule ${narrowDeny.tool} (also names ${normalizedTool})` };
  const narrowAsk = narrowing.find((r) => r.action === "ask");
  // Section 7: command rules meet shell tools only. A deny is a deny at
  // once; an ask turns an allow into an ask; an allow may widen an ask below.
  const commandRules = isShellTool(normalizedTool) ? policy.rules.filter((r) => r.command !== undefined && applies(r)) : [];
  const folded = commandRules.length > 0 ? fold(decodeEscapes(call.inputText)) : "";
  const met = (() => {
    if (commandRules.length === 0) return { deny: undefined, ask: undefined, allow: [] as Rule[] };
    const narrowers = commandRules.filter((r) => r.action !== "allow");
    const cmds = narrowers.length > 0 ? headCommands(folded, new Set(narrowers.map((r) => (r.command as string[])[0] as string))) : [];
    const hit = (r: Rule) => cmds.some((c) => commandNarrows(r.command as string[], c));
    const allow = commandRules
      .filter((r) => r.action === "allow" && commandAllows(r.command as string[], folded))
      .sort((a, b) => (b.command as string[]).length - (a.command as string[]).length);
    return { deny: narrowers.find((r) => r.action === "deny" && hit(r)), ask: narrowers.find((r) => r.action === "ask" && hit(r)), allow };
  })();
  if (met.deny !== undefined) return { action: "deny", normalizedTool, reason: commandReason(met.deny.command as string[]) };

  // Section 7: an allow command rule widens an ask that step 5 left with no
  // rule, or a `bash` ask of no higher rank, when nothing narrows it and the
  // text passes every step an allow passes (else the ask stands).
  const widen = (asked: Decision, top: Rule | undefined): Decision => {
    if (met.ask !== undefined) return asked;
    const rule = met.allow.find((r) => top === undefined || compareRank(rankOf(r), rankOf(top)) >= 0);
    if (rule === undefined) return asked;
    if (parseInstalls(folded).length > 0) return asked; // never an install of section 6
    // A `bash` ask that narrows a shell under another name is the ask this
    // rule widens, when it is of no higher rank; any other narrowing ask stands.
    const ask = narrowAsk !== undefined && !(narrowAsk.tool === "bash" && compareRank(rankOf(rule), rankOf(narrowAsk)) >= 0) ? narrowAsk : undefined;
    const d = allowSteps(normalizedTool, call, commandReason(rule.command as string[]), ask, false);
    return d.action === "allow" ? d : asked;
  };

  if (matches.length === 0) {
    return widen({ action: "ask", normalizedTool, reason: loaded.problem ? `no rule (${loaded.problem})` : "no rule" }, undefined);
  }
  let top = matches[0] as Rule;
  for (const r of matches.slice(1)) {
    const c = compareRank(rankOf(r), rankOf(top));
    if (c > 0 || (c === 0 && SEVERITY[r.action] > SEVERITY[top.action])) top = r;
  }
  const reason = `rule ${top.tool}${top.harness ? ` harness=${top.harness}` : ""}${top.chat ? " chat" : ""}`;
  if (top.action === "ask" && top.tool === "bash") return widen({ action: "ask", normalizedTool, reason }, top);
  if (top.action !== "allow") return { action: top.action, normalizedTool, reason };
  if (met.ask !== undefined) return { action: "ask", normalizedTool, reason: commandReason(met.ask.command as string[]) };
  if (other.ambiguous) {
    if (narrowAsk !== undefined) return { action: "ask", normalizedTool, reason: `rule ${narrowAsk.tool} (also names ${normalizedTool})` };
    return { action: "ask", normalizedTool, reason: "ambiguous server name: list the server in the policy's servers" };
  }
  // Every tied allow must hold its pin: one changed description is enough
  // to ask (case 57; derm-core's rule, integration w1 finding S10).
  if (narrowAsk === undefined) {
    const pins = matches
      .filter((r) => compareRank(rankOf(r), rankOf(top)) === 0 && r.descriptionSha256 !== undefined)
      .map((r) => (r.descriptionSha256 as string).toLowerCase());
    if (pins.length > 0) {
      const current = call.description === undefined ? undefined : sha256Hex(call.description);
      if (current === undefined || pins.some((p) => p !== current)) {
        return { action: "ask", normalizedTool, reason: "description changed" };
      }
    }
  }
  return allowSteps(normalizedTool, call, reason, narrowAsk, false);
}

/**
 * The steps an allow passes before it stands: a narrowing ask (step 3a), an
 * ambiguous split, then step 7 (control files, shell text the matcher cannot
 * read, an install of section 6, PowerShell's plain words).
 */
function allowSteps(normalizedTool: string, call: Call, reason: string, narrowAsk: Rule | undefined, ambiguous: boolean): Decision {
  if (narrowAsk !== undefined) return { action: "ask", normalizedTool, reason: `rule ${narrowAsk.tool} (also names ${normalizedTool})` };
  if (ambiguous) return { action: "ask", normalizedTool, reason: "ambiguous server name: list the server in the policy's servers" };
  const folded = fold(decodeEscapes(call.inputText));
  const unquoted = unquote(folded);
  const texts = withCollapsedSlashes(withWin32Trimmed(withNativeSeparators([folded, unquoted])));
  const control = CONTROL_PATHS.find((p) => texts.some((t) => namesControlPath(t, p)));
  if (control !== undefined) return { action: "ask", normalizedTool, reason: `input names a control file (${control})` };
  // On the folded text, so `＄HOME` asks: stricter than the raw input, the
  // side that fails safe (integration w1; derm-core and derm-pi do the same).
  const token = isShellTool(normalizedTool) ? UNREADABLE_SHELL_TOKENS.find((t) => folded.includes(t)) : undefined;
  if (token !== undefined) return { action: "ask", normalizedTool, reason: unreadableReason(token) };
  // Package installs (contracts/policy.md section 6; lane X's seam). An
  // install's ask or deny names its packages, so it comes first.
  const install = isShellTool(normalizedTool) ? installDecision(normalizedTool, folded) : undefined;
  if (install !== undefined) return { action: install.action, normalizedTool, reason: install.reason };
  // PowerShell (lane Z's request 3, step 7c): plain words only, or ask,
  // after an install the lockfile vouches for (installDecision keeps the allow by answering nothing).
  const unplain = (POWERSHELL_TOOLS as readonly string[]).includes(normalizedTool) ? powershellUnplain(folded) : undefined;
  if (unplain !== undefined) return { action: "ask", normalizedTool, reason: powershellReason(unplain) };
  // Step 7d (integration w6's close, E0's R-E0-1, 2, 3 and 5), last, so an
  // earlier step's reason stands where both apply: step 7a's other lists for
  // every tool, then a shell or interpreter that reads its program from its input.
  const more = moreStep7a(texts);
  if (more !== undefined) return { action: "ask", normalizedTool, reason: more };
  const fed = isShellTool(normalizedTool) ? stdinProgram(folded) : undefined;
  if (fed !== undefined) return { action: "ask", normalizedTool, reason: `program read from input: \`${fed}\`` };
  return { action: "allow", normalizedTool, reason };
}
