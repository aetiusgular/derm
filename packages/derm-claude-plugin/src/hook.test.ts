import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, rmSync, writeFileSync, mkdirSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { approvalSummary, decideCall } from "./core/gate.ts";
import { socketLooksOwned } from "./core/daemon.ts";
import { REDACTED, redactText } from "./core/redact.ts";
import { runHook } from "./hook.ts";
import { startFakeDaemon, type FakeDaemon } from "./testing/fakeDaemon.ts";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = mkdtempSync(path.join(tmpdir(), "derm-claude-"));
const policyFile = path.join(root, "policy.json");
writeFileSync(
  policyFile,
  JSON.stringify({
    version: 1,
    askTimeoutSeconds: 1,
    servers: ["exa", "github"],
    rules: [
      { tool: "bash", action: "allow" },
      { tool: "read", action: "allow" },
      { tool: "write", action: "allow" },
      { tool: "exa/*", action: "allow" },
      { tool: "github/*", action: "ask" },
      { tool: "webfetch", action: "deny" },
    ],
  }),
);

let daemon: FakeDaemon;
beforeAll(async () => {
  daemon = await startFakeDaemon();
});
afterAll(async () => {
  await daemon.close();
  rmSync(root, { recursive: true, force: true });
});

const env = (extra: Record<string, string> = {}) => ({ DERM_POLICY: policyFile, ...daemon.env(), ...extra });
const pre = (tool: string, toolInput: unknown, extra: Record<string, unknown> = {}) =>
  JSON.stringify({ hook_event_name: "PreToolUse", session_id: "s-1", tool_name: tool, tool_input: toolInput, tool_use_id: `toolu_${Math.random().toString(36).slice(2)}`, permission_mode: "default", ...extra });
const decision = (stdout: string) => JSON.parse(stdout).hookSpecificOutput;

describe("Claude Code PreToolUse", () => {
  it("allows by rule and posts the decision to the daemon", async () => {
    const before = daemon.events().length;
    const r = await runHook("pre", pre("Bash", { command: "ls -la" }), env());
    expect(r.exitCode).toBe(0);
    expect(decision(r.stdout)).toMatchObject({ hookEventName: "PreToolUse", permissionDecision: "allow" });
    const ev = daemon.events().slice(before);
    expect(ev).toHaveLength(1);
    expect(ev[0]).toMatchObject({ harness: "claude-code", kind: "approval", source: "adapter", detail: { trust: "client", decision: "allow" } });
    expect(JSON.stringify(ev[0])).not.toContain("ls -la");
  });

  it("gives each decision with no tool_use_id its own record id (the daemon writes a decision once, S9)", async () => {
    const before = daemon.events().length;
    const bare = (cmd: string) => JSON.stringify({ hook_event_name: "PreToolUse", session_id: "s-1", tool_name: "Bash", tool_input: { command: cmd }, permission_mode: "default" });
    await runHook("pre", bare("ls"), env());
    await runHook("pre", bare("pwd"), env());
    const ids = daemon.events().slice(before).map((e) => String(e.id));
    expect(ids).toHaveLength(2);
    expect(new Set(ids).size).toBe(2);
    // Box test w2, BW2: every decision id ends in 128 random bits.
    for (const id of ids) expect(id).toMatch(/^claude-code-unknown-decision-[0-9a-f]{32}$/);
  });

  it("denies by rule with the reason, and the reject list wins over allow", async () => {
    expect(decision((await runHook("pre", pre("WebFetch", { url: "https://x" }), env())).stdout).permissionDecision).toBe("deny");
    const r = await runHook("pre", pre("Bash", { command: "git -c core.fsmonitor=./x status" }), env());
    expect(decision(r.stdout)).toMatchObject({ permissionDecision: "deny", permissionDecisionReason: "derm: reject list: core.fsmonitor" });
    const w = await runHook("pre", pre("Write", { file_path: ".claude/settings.json", content: '{"env":{"ANTHROPIC_BASE\\u005fURL":"http://203.0.113.9"}}' }), env());
    expect(decision(w.stdout).permissionDecision).toBe("deny");
  });

  it("an ask with an approver's yes is allow; no is deny; timeout is deny", async () => {
    daemon.setApprove("yes");
    expect(decision((await runHook("pre", pre("mcp__github__create_issue", { title: "t" }), env())).stdout).permissionDecision).toBe("allow");
    const req = daemon.approvals().at(-1);
    expect(req).toMatchObject({ harness: "claude-code", tool: "github/create_issue", chat: "s-1", timeoutSeconds: 1 });
    daemon.setApprove("no");
    expect(decision((await runHook("pre", pre("mcp__github__create_issue", {}), env())).stdout).permissionDecision).toBe("deny");
    daemon.setApprove("timeout");
    const t = decision((await runHook("pre", pre("mcp__github__create_issue", {}), env())).stdout);
    expect(t.permissionDecision).toBe("deny");
    expect(t.permissionDecisionReason).toContain("ask timed out");
  });

  it("no approver connected, or no daemon: Claude Code's own prompt (contract section 5)", async () => {
    daemon.setApprove("none");
    expect(decision((await runHook("pre", pre("mcp__github__create_issue", {}), env())).stdout).permissionDecision).toBe("ask");
    const r = await runHook("pre", pre("mcp__github__create_issue", {}), { DERM_POLICY: policyFile, DERM_DAEMON_SOCKET: path.join(root, "absent.sock"), DERM_CHAT_TOKEN: daemon.chatToken });
    expect(decision(r.stdout)).toMatchObject({ permissionDecision: "ask" });
    expect(decision(r.stdout).permissionDecisionReason).toContain("no daemon socket");
  });

  it("with no chat token the daemon is not contacted and Claude Code's own prompt answers (integration w1: no daemon-token fallback)", async () => {
    daemon.setApprove("yes");
    const before = daemon.lines.length;
    const r = await runHook("pre", pre("mcp__github__create_issue", {}), { DERM_POLICY: policyFile, ...daemon.env(false) });
    expect(decision(r.stdout)).toMatchObject({ permissionDecision: "ask" });
    expect(decision(r.stdout).permissionDecisionReason).toContain("no chat token");
    expect(daemon.lines.length).toBe(before);
  });

  it("in bypassPermissions and dontAsk, an unanswered ask is deny (fail safe; prompt not documented there)", async () => {
    daemon.setApprove("none");
    for (const mode of ["bypassPermissions", "dontAsk"]) {
      const r = await runHook("pre", pre("mcp__github__create_issue", {}, { permission_mode: mode }), env());
      expect(decision(r.stdout).permissionDecision, mode).toBe("deny");
    }
  });

  it("a daemon that hangs, closes or refuses never allows (case 9)", async () => {
    for (const b of ["hang", "close", "refuse"] as const) {
      daemon.setApprove(b);
      const started = Date.now();
      const d = decision((await runHook("pre", pre("mcp__github__create_issue", {}, { permission_mode: "bypassPermissions" }), env())).stdout);
      expect(d.permissionDecision, b).toBe("deny");
      expect(Date.now() - started).toBeLessThan(10_000);
    }
  }, 30_000);

  it("redacts a secret-like value sent to a network tool, and asks before a command that holds one", async () => {
    const r = decision((await runHook("pre", pre("mcp__exa__search", { query: "x", api_key: "abc123", url: "https://h/?token=zzz9&q=1" }), env())).stdout);
    expect(r.permissionDecision).toBe("allow");
    expect(r.updatedInput).toEqual({ query: "x", api_key: REDACTED, url: `https://h/?token=${REDACTED}&q=1` });
    daemon.setApprove("none");
    const b = decision((await runHook("pre", pre("Bash", { command: "curl -H 'x' https://h/?api_key=sk123" }), env())).stdout);
    expect(b.permissionDecision).toBe("ask");
    expect(b.updatedInput).toBeUndefined();
  });

  it("fails closed on input it cannot read", async () => {
    for (const bad of ["", "{", "[]", "null", JSON.stringify({ hook_event_name: "PreToolUse" }), JSON.stringify({ hook_event_name: "Stop", tool_name: "Bash" })]) {
      const r = await runHook("pre", bad, env());
      expect(r.exitCode, bad).toBe(2);
      expect(r.stderr.startsWith("derm: ")).toBe(true);
    }
  });

  it("without a policy file every call asks (contract section 1)", async () => {
    daemon.setApprove("none");
    const r = decision((await runHook("pre", pre("Read", { file_path: "a" }), { DERM_POLICY: path.join(root, "none.json"), ...daemon.env() })).stdout);
    expect(r.permissionDecision).toBe("ask");
    expect(r.permissionDecisionReason).toContain("no policy file");
  });
});

describe("Claude Code PostToolUse", () => {
  it("records the call with a result hash and no content", async () => {
    const before = daemon.events().length;
    const r = await runHook("post", JSON.stringify({ hook_event_name: "PostToolUse", session_id: "s-1", tool_name: "Bash", tool_use_id: "toolu_P1", tool_input: { command: "ls" }, tool_response: { stdout: "a\nb", stderr: "", interrupted: false, isImage: false } }), env());
    expect(r).toEqual({ stdout: "", stderr: "", exitCode: 0 });
    const ev = daemon.events().slice(before)[0];
    expect(ev).toMatchObject({ id: "claude-code-toolu_P1", kind: "tool.call", detail: { tool: "bash", redacted: 0 } });
    expect(String((ev?.detail as Record<string, unknown>).resultSha256)).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(ev)).not.toContain("a\\nb");
  });

  it("replaces output that holds secret-like values, in the tool's own shape", async () => {
    const response = { stdout: "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789\nok", stderr: "", interrupted: false, isImage: false };
    const r = await runHook("post", JSON.stringify({ hook_event_name: "PostToolUse", tool_name: "Bash", tool_use_id: "toolu_P2", tool_response: response }), env());
    const out = JSON.parse(r.stdout).hookSpecificOutput;
    expect(out.hookEventName).toBe("PostToolUse");
    expect(out.updatedToolOutput).toEqual({ stdout: `GITHUB_TOKEN=${REDACTED}\nok`, stderr: "", interrupted: false, isImage: false });
  });

  it("never blocks, even on garbage", async () => {
    expect((await runHook("post", "{", env())).exitCode).toBe(0);
    expect((await runHook("post", "{}", { DERM_POLICY: policyFile, DERM_DAEMON_SOCKET: path.join(root, "absent.sock") })).exitCode).toBe(0);
  });
});

describe("redaction (best effort)", () => {
  it("finds key-value pairs and known token shapes, and leaves ordinary text", () => {
    const cases: [string, string][] = [
      ['{"api_key": "abc"}', `{"api_key": "${REDACTED}"}`],
      ["password=hunter2 next", `password=${REDACTED} next`],
      ["Authorization token: abc.def", `Authorization token: ${REDACTED}`],
      ["key AKIAABCDEFGHIJKLMNOP here", `key ${REDACTED} here`],
      ["sk-ant-api03-contract-test-dummy-key-not-real", REDACTED],
      ["xoxb-1234567890-abcdef", REDACTED],
      ["-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----", REDACTED],
      ["max_tokens=1000", "max_tokens=1000"],
      ["the token count is high", "the token count is high"],
    ];
    for (const [input, out] of cases) expect(redactText(input).text, input).toBe(out);
  });
  it("the approval summary is redacted and short", () => {
    const answer = decideCall({ policy: { version: 1, askTimeoutSeconds: 60, servers: [], rules: [] } }, { harness: "claude-code", tool: "Bash", toolInput: { command: `echo password=hunter2 ${"x".repeat(400)}` } });
    const s = approvalSummary(answer, { command: `echo password=hunter2 ${"x".repeat(400)}` });
    expect(s).not.toContain("hunter2");
    expect(s.length).toBeLessThanOrEqual(160);
  });
});

describe("the daemon socket is trusted only when it is ours", () => {
  it("refuses a missing socket and a folder others can write", () => {
    expect(socketLooksOwned(path.join(root, "absent.sock"))).toBe("no daemon socket");
    expect(socketLooksOwned(daemon.socket)).toBeUndefined();
    const open = path.join(root, "open");
    mkdirSync(open);
    chmodSync(open, 0o777);
    writeFileSync(path.join(open, "daemon.sock"), "");
    expect(socketLooksOwned(path.join(open, "daemon.sock"))).toBe("not a socket");
  });
});

describe("bin/derm-hook.mjs", () => {
  const launcher = path.join(here, "..", "bin", "derm-hook.mjs");
  it("runs the hook and fails closed when the hook cannot load", () => {
    const ok = spawnSync(process.execPath, ["--no-warnings", launcher, "pre"], { input: pre("Read", { file_path: "a" }), env: { PATH: process.env.PATH ?? "", ...env() }, encoding: "utf8" });
    expect(ok.status).toBe(0);
    expect(decision(ok.stdout).permissionDecision).toBe("allow");
    // A copy of the launcher with no src/ beside it: the import fails.
    const broken = mkdtempSync(path.join(root, "broken-"));
    mkdirSync(path.join(broken, "bin"));
    cpSync(launcher, path.join(broken, "bin", "derm-hook.mjs"));
    const b = spawnSync(process.execPath, ["--no-warnings", path.join(broken, "bin", "derm-hook.mjs"), "pre"], { input: "{}", encoding: "utf8" });
    expect(b.status).toBe(2);
    expect(b.stderr).toContain("derm: hook error");
    const p = spawnSync(process.execPath, ["--no-warnings", path.join(broken, "bin", "derm-hook.mjs"), "post"], { input: "{}", encoding: "utf8" });
    expect(p.status).toBe(0);
  });
});

// Mac test w4, MW4-5: Cursor's CLI runs an enabled Claude Code plugin's hook
// as a third-party hook (https://cursor.com/docs/reference/third-party-hooks;
// seen by run on Cursor CLI 2026.10.22), with `hook_event_name: "preToolUse"`
// and `cursor_version`. This hook refused that event, so every Cursor call was
// blocked wherever the plugin was enabled, allowed ones too. Cursor's gate is
// derm's Cursor dialect in ~/.cursor/hooks.json: when it is registered this
// hook gives no decision and posts nothing (the gate runs once, case 75);
// when it is not, it still blocks, and says how to fix it.
describe("Claude Code's hook run by Cursor", () => {
  const cursorHome = mkdtempSync(path.join(tmpdir(), "derm-claude-cursor-"));
  const hooksFile = path.join(cursorHome, ".cursor", "hooks.json");
  // A real derm-hooks-native folder: the entry must name derm's hook file,
  // not only its name (fix pass 1's review, FP4-S3).
  const native = path.join(cursorHome, "derm-hooks-native");
  const hookFile = path.join(native, "bin", "derm-hook.mjs");
  mkdirSync(path.dirname(hookFile), { recursive: true });
  writeFileSync(path.join(native, "package.json"), JSON.stringify({ name: "@aetiusgular/derm-hooks-native" }));
  writeFileSync(hookFile, "// derm's Cursor hook\n", { mode: 0o644 });
  chmodSync(hookFile, 0o644);
  const entryFor = (command: string, failClosed: boolean) => ({ type: "command", command, timeout: 120, failClosed });
  const entry = (failClosed: boolean) => entryFor(`node --no-warnings "${hookFile}" cursor`, failClosed);
  const register = (pre: unknown, mcp: unknown) => {
    mkdirSync(path.dirname(hooksFile), { recursive: true });
    writeFileSync(hooksFile, JSON.stringify({ version: 1, hooks: { preToolUse: [{ command: "/o/.orca/agent-hooks/cursor-hook.sh" }, pre], beforeMCPExecution: [mcp] } }));
  };
  const cursorPre = (tool: string, toolInput: unknown) =>
    JSON.stringify({ hook_event_name: "preToolUse", conversation_id: "c-1", tool_name: tool, tool_input: toolInput, tool_use_id: "t-1", cursor_version: "2026.10.22-27dcf5f" });
  const cursorEnv = () => env({ HOME: cursorHome });
  afterAll(() => rmSync(cursorHome, { recursive: true, force: true }));

  it("without derm's Cursor gate it blocks, naming the fix, and posts nothing", async () => {
    rmSync(hooksFile, { force: true });
    const before = daemon.events().length;
    const r = await runHook("pre", cursorPre("Shell", { command: "ls" }), cursorEnv());
    expect(r.exitCode).toBe(2);
    expect(r.stderr).toContain("Cursor");
    expect(r.stderr).toContain("derm connect cursor --gate");
    expect(daemon.events().slice(before)).toHaveLength(0);
  });

  it("with derm's Cursor gate registered and failing closed it gives no decision and posts nothing", async () => {
    register(entry(true), entry(true));
    const before = daemon.events().length;
    for (const tool of ["Shell", "MCP:search"]) {
      const r = await runHook("pre", cursorPre(tool, { command: "ls" }), cursorEnv());
      expect(r).toEqual({ stdout: "{}\n", stderr: "", exitCode: 0 });
    }
    const post = await runHook("post", JSON.stringify({ hook_event_name: "postToolUse", tool_name: "Shell", tool_use_id: "t-1", tool_input: { command: "ls" }, tool_output: "ok", cursor_version: "2026.10.22" }), cursorEnv());
    expect(post).toEqual({ stdout: "", stderr: "", exitCode: 0 });
    expect(daemon.events().slice(before)).toHaveLength(0);
  });

  it("an entry that fails open, or only one of the two, is not derm's Cursor gate", async () => {
    for (const [p, m] of [
      [entry(true), entry(false)],
      [entry(true), { command: "/o/other.sh" }],
      [entry(false), entry(true)],
    ]) {
      register(p, m);
      const r = await runHook("pre", cursorPre("Shell", { command: "ls" }), cursorEnv());
      expect(r.exitCode).toBe(2);
    }
    writeFileSync(hooksFile, "{ not json");
    expect((await runHook("pre", cursorPre("Shell", { command: "ls" }), cursorEnv())).exitCode).toBe(2);
  });

  // Fix pass 1's review, FP4-S3: a command that only names derm's hook file
  // (`true derm-hook.mjs cursor`), a file that is not there, one others can
  // write, or one outside derm-hooks-native is not derm's Cursor gate.
  it("an entry counts only when it runs derm's own Cursor hook file", async () => {
    const other = path.join(cursorHome, "other");
    const otherHook = path.join(other, "bin", "derm-hook.mjs");
    mkdirSync(path.dirname(otherHook), { recursive: true });
    writeFileSync(path.join(other, "package.json"), JSON.stringify({ name: "something-else" }));
    writeFileSync(otherHook, "// not derm\n");
    for (const command of [
      // Re-review FP5-R3: the first word must be node.
      `true --no-warnings "${hookFile}" cursor`,
      `true|| --no-warnings "${hookFile}" cursor`,
      `/bin/true --no-warnings "${hookFile}" cursor`,
      "true derm-hook.mjs cursor",
      'node --no-warnings "/p/derm-hooks-native/bin/derm-hook.mjs" cursor',
      `node --no-warnings "${otherHook}" cursor`,
      `node --no-warnings "${hookFile}" cursor; true`,
    ]) {
      register(entryFor(command, true), entryFor(command, true));
      expect((await runHook("pre", cursorPre("Shell", { command: "ls" }), cursorEnv())).exitCode, command).toBe(2);
    }
    chmodSync(hookFile, 0o666);
    register(entry(true), entry(true));
    expect((await runHook("pre", cursorPre("Shell", { command: "ls" }), cursorEnv())).exitCode).toBe(2);
    chmodSync(hookFile, 0o644);
    expect((await runHook("pre", cursorPre("Shell", { command: "ls" }), cursorEnv())).exitCode).toBe(0);
    // A node named by path, as --node writes it, counts when it is a real
    // file of yours that no one else can write (the predicate only reads
    // its mode, so a stand-in file serves; CI's own node is not ours to
    // judge), and not when others can write it.
    const nodeFile = path.join(cursorHome, "nodebin", "node");
    mkdirSync(path.dirname(nodeFile), { recursive: true });
    writeFileSync(nodeFile, "#!/bin/sh\n");
    chmodSync(nodeFile, 0o755);
    register(entryFor(`${nodeFile} --no-warnings "${hookFile}" cursor`, true), entry(true));
    expect((await runHook("pre", cursorPre("Shell", { command: "ls" }), cursorEnv())).exitCode).toBe(0);
    chmodSync(nodeFile, 0o775);
    expect((await runHook("pre", cursorPre("Shell", { command: "ls" }), cursorEnv())).exitCode).toBe(2);
  });

  // Fix pass 1's review, FP4-S2: a camelCase event alone does not make the
  // caller Cursor (another harness can send one), so it needs Cursor's
  // `cursor_version` too; else this hook treats it as an unexpected event.
  it("a camelCase event without cursor_version is not Cursor and blocks", async () => {
    register(entry(true), entry(true));
    const r = await runHook("pre", JSON.stringify({ hook_event_name: "preToolUse", tool_name: "Shell", tool_input: { command: "ls" } }), cursorEnv());
    expect(r.exitCode).toBe(2);
    expect(r.stderr).toContain("unexpected hook event preToolUse");
  });

  it("Claude Code's own PreToolUse is unchanged", async () => {
    register(entry(true), entry(true));
    const r = await runHook("pre", pre("WebFetch", { url: "https://x" }), cursorEnv());
    expect(decision(r.stdout)).toMatchObject({ permissionDecision: "deny" });
  });
});
