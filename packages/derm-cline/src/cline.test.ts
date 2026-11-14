import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startFakeDaemon, type FakeDaemon } from "../../derm-claude-plugin/src/testing/fakeDaemon.ts";
import { REDACTED } from "./core/redact.ts";
import { CLINE_SHELL_TOOLS, Unreadable, answerRequest, beforeTool, defaultDeps, gateCallOf, shellCommandsOf, type BeforeToolContext, type Deps } from "./cline.ts";
import { CLINE_CONTROL_PATHS, clineControlPath } from "./control.ts";
import { overBudget } from "./budget.ts";
import plugin from "./plugin.ts";
import { GateServe } from "./serve/client.ts";

const here = path.dirname(fileURLToPath(import.meta.url));
// Wave 5b (lane 5bC): the decision is `derm gate serve`'s, so the cases
// that decide run against a derm build (DERM_BIN, else target/debug or
// target/release), and the hook is async.
const ROOT = path.resolve(here, "../../..");
const DERM = process.env.DERM_TEST_NO_BUILD ? undefined : [process.env.DERM_BIN, path.join(ROOT, "target/debug/derm"), path.join(ROOT, "target/release/derm"), path.join(ROOT, "target/debug/derm.exe"), path.join(ROOT, "target/release/derm.exe")].find((p) => p !== undefined && existsSync(p));
const root = mkdtempSync(path.join(tmpdir(), "derm-cline-"));
const work = path.join(root, "work");
mkdirSync(work);
const policyFile = path.join(root, "policy.json");
writeFileSync(
  policyFile,
  JSON.stringify({
    version: 1,
    askTimeoutSeconds: 1,
    servers: ["exa", "github"],
    rules: [
      { tool: "bash", action: "allow" },
      { tool: "read_files", action: "allow" },
      { tool: "editor", action: "allow" },
      { tool: "exa/*", action: "allow" },
      { tool: "github/*", action: "ask" },
      { tool: "fetch_web_content", action: "deny" },
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

// One co-process per environment, with derm by its absolute path (case 227).
function depsWith(env: Record<string, string>): Deps {
  const s = new GateServe({ agent: "cline", env, cwd: () => work, trusted: () => true, startMs: 1200, requestMs: 1200, locate: () => ({ path: DERM as string }) });
  return { ...defaultDeps(env, () => work), serve: () => s };
}
const deps = (extra: Record<string, string> = {}): Deps => depsWith({ DERM_POLICY: policyFile, ...daemon.env(), ...extra });
let n = 0;
const ctx = (toolName: string, input: unknown): BeforeToolContext => ({ snapshot: { conversationId: "conv_1" }, toolCall: { toolCallId: `call_${++n}`, toolName, input }, input });
/** A case that decides: it needs a derm build (`derm gate serve`). */
const itDerm = it.runIf(DERM !== undefined);
const settle = () => new Promise((r) => setTimeout(r, 50));

describe("the dialect's fixtures (contracts/fixtures/hook-dialects/cline)", () => {
  const fixture = (name: string) => JSON.parse(readFileSync(path.join(here, "../../../contracts/fixtures/hook-dialects/cline", name), "utf8"));
  itDerm("answers the approval request fixture in the answer fixture's shape", async () => {
    expect(await answerRequest(fixture("approval-request.json"), deps())).toEqual(fixture("approval-answer.allow.json"));
    const denied = await answerRequest({ ...fixture("approval-request.json"), toolName: "fetch_web_content", input: { url: "https://x" } }, deps());
    expect(Object.keys(denied).sort()).toEqual(Object.keys(fixture("approval-answer.deny.json")).sort());
    expect(denied).toEqual({ approved: false, reason: "derm: rule fetch_web_content deny" });
  });
  it("reads the shell call in the file-hook fixture's tool_call the same way", async () => {
    const f = fixture("stdin.pre-tool.json");
    expect(gateCallOf(f.tool_call.name, f.tool_call.input, { toolCallId: f.tool_call.id, conversationId: f.taskId }, {})).toMatchObject({ tool: "bash", toolInput: { command: "ls -la" }, chat: "conv_1" });
  });
});

describe("beforeTool (the SDK plugin)", () => {
  itDerm("returns nothing on an allow rule, so Cline's own policy decides (case 72), and records it", async () => {
    const before = daemon.events().length;
    expect(await beforeTool(ctx("run_commands", { commands: ["ls"] }), deps())).toBeUndefined();
    await settle();
    expect(daemon.events().slice(before)[0]).toMatchObject({ harness: "cline", kind: "approval", detail: { decision: "allow", tool: "bash", via: "plugin" } });
  });
  itDerm("skips a denied call with the reason, never stop (case 79)", async () => {
    expect(await beforeTool(ctx("fetch_web_content", { url: "https://x" }), deps())).toEqual({ skip: true, reason: "derm: rule fetch_web_content deny" });
    expect(await beforeTool(ctx("run_commands", { commands: ["git -c core.fsmonitor=./x status"] }), deps())).toEqual({ skip: true, reason: "derm: reject list: core.fsmonitor" });
    const out = await beforeTool(ctx("run_commands", { commands: ["ls"] }), deps());
    expect(out).toBeUndefined();
  });
  itDerm("turns an ask into Cline's own approval, whatever --auto-approve says (cases 71, 83)", async () => {
    expect(await beforeTool(ctx("github__create_issue", { title: "x" }), deps())).toEqual({ policy: { autoApprove: false } });
    // No rule: ask, never Cline's auto-approve (case 72).
    expect(await beforeTool(ctx("spawn_agent", { task: "x" }), deps())).toEqual({ policy: { autoApprove: false } });
  });
  itDerm("never waits on the daemon: an unreachable or hanging daemon does not hold the answer (Cline gives a hook 3 s)", async () => {
    daemon.setApprove("hang");
    const started = Date.now();
    expect(await beforeTool(ctx("github__create_issue", {}), deps())).toEqual({ policy: { autoApprove: false } });
    // With no daemon the decision is kept in the light tier's log under the
    // home (box test w6, BW6-3: a plugin that keeps its own records gets it
    // too), so this environment names one; with none the light tier fails
    // closed, as Claude Code's hook does.
    const home = { HOME: root, USERPROFILE: root };
    expect(await beforeTool(ctx("run_commands", { commands: ["ls"] }), depsWith({ DERM_POLICY: policyFile, DERM_DAEMON_SOCKET: path.join(root, "absent.sock"), ...home }))).toBeUndefined();
    expect(Date.now() - started).toBeLessThan(500);
    daemon.setApprove("yes");
  });
  itDerm("rewrites a secret-like value in an MCP call's input", async () => {
    expect(await beforeTool(ctx("exa__search", { query: "q", api_key: "abc" }), deps())).toEqual({ input: { query: "q", api_key: REDACTED } });
  });
  itDerm("asks instead of rewriting a shell command or an editor write", async () => {
    expect(await beforeTool(ctx("run_commands", { commands: ["curl -H 'Authorization: Bearer sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789' h"] }), deps())).toEqual({ policy: { autoApprove: false } });
    expect(await beforeTool(ctx("editor", { path: "a.env", new_text: "API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789" }), deps())).toEqual({ policy: { autoApprove: false } });
  });
  itDerm("judges the input Cline will run (an earlier hook's rewrite), not the model's", async () => {
    const c: BeforeToolContext = { snapshot: {}, toolCall: { toolCallId: "c1", toolName: "run_commands", input: { commands: ["ls"] } }, input: { commands: ["export ANTHROPIC_BASE_URL=http://x"] } };
    expect(await beforeTool(c, deps())).toEqual({ skip: true, reason: "derm: reject list: anthropic_base_url" });
  });
  itDerm("fails closed inside the hook: bad input and a broken policy load skip the call", async () => {
    expect(await beforeTool({} as BeforeToolContext, deps())).toEqual({ skip: true, reason: "derm: tool call has no tool name" });
    expect(await beforeTool(undefined as never, deps())).toMatchObject({ skip: true });
    const broken = { ...deps(), serve: () => { throw new Error("boom"); } };
    expect(await beforeTool(ctx("run_commands", { commands: ["ls"] }), broken)).toEqual({ skip: true, reason: "derm: hook error: boom" });
  });
  itDerm("a policy inside the session folder is not used (a project can set it)", async () => {
    const inside = path.join(work, "policy.json");
    writeFileSync(inside, readFileSync(policyFile));
    expect(await beforeTool(ctx("run_commands", { commands: ["ls"] }), depsWith({ DERM_POLICY: inside }))).toEqual({ policy: { autoApprove: false } });
  });
});

describe("shell as bash (cases 30, 82)", () => {
  it("reads every shape Cline's normalizer takes, one command per line", async () => {
    expect(shellCommandsOf({ commands: ["a", "b"] })).toBe("a\nb");
    expect(shellCommandsOf({ commands: "a" })).toBe("a");
    expect(shellCommandsOf({ commands: { command: "git", args: ["status"] } })).toBe("git status");
    expect(shellCommandsOf({ command: "c" })).toBe("c");
    expect(shellCommandsOf({ command: "git", args: ["-c", "x=y"] })).toBe("git -c x=y");
    expect(shellCommandsOf({ cmd: "d" })).toBe("d");
    expect(shellCommandsOf(["e", { command: "f" }])).toBe("e\nf");
    expect(shellCommandsOf("g")).toBe("g");
    expect(gateCallOf("run_commands", { commands: ["ls"], cwd: "/srv" }, {}, {})).toMatchObject({ tool: "bash", toolInput: { command: "ls", cwd: "/srv" } });
  });
  itDerm("refuses input it cannot read the way Cline will (review P-S1)", async () => {
    for (const bad of [
      { commands: ["true", { command: "sh", args: ["-c", "echo ANTHROPIC_BASE_URL=x > hidden.txt"] }], command: "true" },
      { commands: { command: "sh", args: ["-c", "evil"] }, cmd: "ls" },
      { command: "ls", cmd: "rm -r ~" },
      { commands: [1] },
      { commands: [{ command: "sh", args: [1] }] },
      { commands: [{ command: "sh", argv: ["x"] }] },
      { commands: [] },
      {},
      42,
    ]) {
      expect(() => shellCommandsOf(bad), JSON.stringify(bad)).toThrow(Unreadable);
      expect(await beforeTool(ctx("run_commands", bad), deps()), JSON.stringify(bad)).toMatchObject({ skip: true });
    }
  });
  itDerm("checks an argv entry as one command line, so the git checks see it (review P-S3)", async () => {
    expect(await beforeTool(ctx("run_commands", { command: "git", args: ["-c", "core.fsmonitor=x", "init", "g"] }), deps())).toEqual({ skip: true, reason: "derm: reject list: core.fsmonitor" });
    expect(await beforeTool(ctx("run_commands", { commands: [{ command: "git", args: ["-c", "core.hooksPath=/tmp/h", "status"] }] }), deps())).toMatchObject({ skip: true });
  });
  itDerm("case 30's tokens ask under an allow rule, through Cline's shell name", async () => {
    for (const tool of CLINE_SHELL_TOOLS) {
      for (const cmd of ["echo $HOME", "ls `id`", "cat ~/.ssh/id_rsa", "rm -rf *", "echo {a,b}", "!!", "ls\\ -la", "print *(e:'x':)"]) {
        expect(await beforeTool(ctx(tool, { commands: [cmd] }), deps()), `${tool}: ${cmd}`).toEqual({ policy: { autoApprove: false } });
      }
    }
  });
  itDerm("a second command on its own line is checked too", async () => {
    expect(await beforeTool(ctx("run_commands", { commands: ["ls", "export CHATGPT_BASE_URL=http://x"] }), deps())).toMatchObject({ skip: true });
  });
  itDerm("commands derm cannot read are refused", async () => {
    expect(await beforeTool(ctx("run_commands", { commands: [{ argv: ["ls"] }] }), deps())).toEqual({ skip: true, reason: "derm: run_commands holds an entry derm cannot read" });
  });
});

describe("answerRequest (the approval file)", () => {
  itDerm("an allow rule approves; a deny rule and the reject list do not", async () => {
    expect(await answerRequest({ toolName: "run_commands", input: { commands: ["ls"] }, toolCallId: "t1" }, deps())).toEqual({ approved: true });
    expect(await answerRequest({ toolName: "run_commands", input: { commands: ["export ANTHROPIC_BASE_URL=x"] } }, deps())).toEqual({ approved: false, reason: "derm: reject list: anthropic_base_url" });
  });
  itDerm("an ask is the approver's yes, else a deny (Cline's prompt is not reachable from the file)", async () => {
    daemon.setApprove("yes");
    expect(await answerRequest({ toolName: "github__create_issue", input: {}, toolCallId: "t2", conversationId: "conv_9" }, deps())).toEqual({ approved: true });
    // The chat never comes from the file, which the agent can write (review P-S5).
    expect(daemon.approvals().at(-1)).toMatchObject({ harness: "cline", tool: "github/create_issue", chat: "" });
    for (const b of ["no", "none", "timeout", "close"] as const) {
      daemon.setApprove(b);
      expect((await answerRequest({ toolName: "github__create_issue", input: {} }, deps())).approved, b).toBe(false);
    }
    daemon.setApprove("yes");
    expect(await answerRequest({ toolName: "github__create_issue", input: {} }, depsWith({ DERM_POLICY: policyFile, DERM_DAEMON_SOCKET: path.join(root, "absent.sock") }))).toMatchObject({ approved: false, reason: expect.stringContaining("not reachable") });
  });
  itDerm("a secret-like value it cannot redact here asks", async () => {
    daemon.setApprove("none");
    expect((await answerRequest({ toolName: "exa__search", input: { api_key: "abc" } }, deps())).approved).toBe(false);
    daemon.setApprove("yes");
  });
  itDerm("records the answer, as the approval file's", async () => {
    const before = daemon.events().length;
    await answerRequest({ toolName: "read_files", input: { paths: ["a"] }, toolCallId: "t3" }, deps());
    expect(daemon.events().slice(before)[0]).toMatchObject({ harness: "cline", kind: "approval", detail: { decision: "allow", via: "approval-file", toolUseId: "t3" } });
  });
  itDerm("a request with no tool name, or a broken policy load, is a deny", async () => {
    expect(await answerRequest({} as never, deps())).toMatchObject({ approved: false });
    expect(await answerRequest(null as never, deps())).toMatchObject({ approved: false });
    expect(await answerRequest({ toolName: "run_commands", input: { commands: ["ls"] } }, { ...deps(), serve: () => { throw new Error("boom"); } })).toEqual({ approved: false, reason: "derm: responder error: boom" });
  });
});

describe("redaction rules and cost (review P-S2, P-S6)", () => {
  itDerm("rewrites only for MCP tools and fetch_web_content; apply_patch and editor ask even when a server name would split them", async () => {
    const allowFile = path.join(root, "allow-all.json");
    writeFileSync(allowFile, JSON.stringify({ version: 1, askTimeoutSeconds: 1, servers: ["apply"], rules: [{ tool: "*", action: "allow" }] }));
    const allowAll = depsWith({ DERM_POLICY: allowFile, ...daemon.env() });
    expect(await beforeTool(ctx("fetch_web_content", { url: "https://h/?token=zz9" }), allowAll)).toEqual({ input: { url: `https://h/?token=${REDACTED}` } });
    expect(await beforeTool(ctx("apply_patch", { patch: "+API_KEY=abc" }), allowAll)).toEqual({ policy: { autoApprove: false } });
    expect(await beforeTool(ctx("editor", { path: "a", new_text: "password=hunter22" }), allowAll)).toEqual({ policy: { autoApprove: false } });
  });
  itDerm("refuses input that would make the core's redaction slow, in well under Cline's 3 s", async () => {
    const heavy = "token.".repeat(4000);
    let t = Date.now();
    expect(await beforeTool(ctx("run_commands", { commands: [`echo ${heavy}`] }), deps())).toMatchObject({ skip: true, reason: expect.stringContaining("cannot check in time") });
    expect(Date.now() - t).toBeLessThan(500);
    t = Date.now();
    expect(await answerRequest({ toolName: "editor", input: { new_text: heavy } }, deps())).toMatchObject({ approved: false });
    expect(Date.now() - t).toBeLessThan(500);
    // Many medium runs add up too.
    const many = Array.from({ length: 40 }, () => "token.".repeat(170)).join(" ");
    t = Date.now();
    expect(await beforeTool(ctx("editor", { new_text: many }), deps())).toMatchObject({ skip: true });
    expect(Date.now() - t).toBeLessThan(500);
    // Ordinary large input passes the guard.
    expect(overBudget({ text: "a".repeat(200_000), b: "token ".repeat(5000) })).toBeUndefined();
  });
});

describe("Cline's control files", () => {
  it("lists the markers in folded form", async () => {
    for (const p of CLINE_CONTROL_PATHS) expect(p).toBe(p.toLowerCase());
  });
  it.each([
    ["~/.cline/plugins/evil.ts", ".cline/"],
    ["<ws>/.cline/hooks/PreToolUse", ".cline/"],
    ["/home/u/Documents/Cline/Plugins/x.js", "documents/cline/"],
    [".clinerules/hooks/PreToolUse.sh", ".clinerules"],
    ["/home/u/.agents/plugins/p/plugin.json", ".agents/plugins"],
    ["export CLINE_DIR=/tmp/x", "cline_dir"],
    ["CLINE_DATA_DIR=/tmp/d cline", "cline_data_dir"],
    ["unset CLINE_TOOL_APPROVAL_MODE", "cline_tool_approval"],
    ["CLINE_PLUGIN_MODE=sandbox", "cline_plugin_"],
    ["/run/user/1000/derm/cline-approvals/s.decision.r.json", "cline-approvals/"],
    ["cd /run/user/1000/cline-approvals && cp /w/d.json s.decision.r.json", "cline-approvals/"],
    ["cd /home/u/.cline && cp x plugins/zz/index.ts", ".cline/"],
    ["cd /home/u/Documents/Cline && cp x Plugins/zz.ts", "documents/cline/"],
    ["mkdir -p .cline && cd .cline && cp x plugins/y.ts", ".cline/"],
  ])("%s names %s", async (text, marker) => {
    expect(clineControlPath(text)).toBe(marker);
  });
  itDerm("an allowed write into Cline's plugin folder asks", async () => {
    expect(await beforeTool(ctx("editor", { path: "/home/u/.cline/plugins/x.ts", new_text: "export default {}" }), deps())).toEqual({ policy: { autoApprove: false } });
    expect(await beforeTool(ctx("run_commands", { commands: ["echo '{\"approved\":true}' > /run/user/1000/derm/cline-approvals/a.decision.b.json"] }), deps())).toEqual({ policy: { autoApprove: false } });
  });
  // Review W4-S3: the plugin's own asks (a control file, a secret it cannot
  // rewrite) come after decideCall; under full access they are denies too.
  itDerm("under full access an ask the plugin makes is a skip", async () => {
    // Full access comes from the plugin's environment, which the host's
    // process gives it (the core read process.env; the co-process reads the
    // plugin's env).
    const input = { path: "/w/a.env", new_text: "api_key=abcdef0123456789" };
    const r = await beforeTool(ctx("editor", input), deps({ DERM_FULL_ACCESS: "1" }));
    expect(r).toMatchObject({ skip: true });
    expect((r as { reason: string }).reason).toMatch(/full access/);
  });
  // Review W4-S8: `derm run cline` answers in `~/.cline/derm-approval/<chat>`.
  it("names derm run's approval folder as a control path", async () => {
    expect(clineControlPath("cd /tmp/x && cp d.json ~/derm-approval/chat-1/s.decision.r.json")).toBe("derm-approval/");
  });
});

describe("the plugin module", () => {
  it("is an AgentPlugin named derm with one beforeTool hook", async () => {
    expect(plugin.name).toBe("derm");
    expect(plugin.manifest).toEqual({ capabilities: ["hooks"] });
    expect(Object.keys(plugin.hooks)).toEqual(["beforeTool"]);
  });
  it("package.json names it as the Cline plugin entry", async () => {
    const pkg = JSON.parse(readFileSync(path.join(here, "../package.json"), "utf8"));
    expect(pkg.cline.plugins).toEqual([{ paths: ["./src/plugin.ts"], capabilities: ["hooks"] }]);
  });
  it("reads no file when it loads or is set up (case 46)", async () => {
    const script = [
      'import fs from "node:fs"; import { syncBuiltinESMExports } from "node:module";',
      "const seen = []; let counting = false;",
      'for (const k of ["readFileSync","openSync","statSync","lstatSync","readdirSync","existsSync","realpathSync","fstatSync","readSync"]) { const f = fs[k]; fs[k] = (...a) => { if (counting) seen.push(k); return f(...a); }; }',
      "syncBuiltinESMExports();",
      `const mod = await import(${JSON.stringify(new URL("./plugin.ts", import.meta.url).href)});`,
      'counting = true; mod.default.setup({}, { cwd: "/nonexistent-derm-session" });',
      "process.stdout.write(JSON.stringify({ seen }));",
    ].join("\n");
    const out = JSON.parse(execFileSync(process.execPath, ["--no-warnings", "--input-type=module", "-e", script], { encoding: "utf8", env: { ...process.env, DERM_POLICY: "/nonexistent/derm-policy.json" } }));
    expect(out.seen).toEqual([]);
  });
  it("imports only node: built-ins and files inside src/, so the folder can be copied whole", async () => {
    for (const name of ["plugin.ts", "cline.ts", "control.ts", "responder.ts"]) {
      const text = readFileSync(path.join(here, name), "utf8");
      for (const m of text.matchAll(/^\s*(?:import|export)\s[^;]*?from\s+"([^"]+)"/gms)) {
        const spec = m[1] as string;
        if (spec.startsWith("node:")) continue;
        expect(spec.startsWith("./"), `${name}: ${spec}`).toBe(true);
      }
    }
  });
});

describe("the preset row (crates/derm-cli/src/connect/presets/cline.json)", () => {
  const row = JSON.parse(readFileSync(path.join(here, "../../../crates/derm-cli/src/connect/presets/cline.json"), "utf8"));
  it("names the same shell tools as the dialect (case 82)", async () => {
    expect(row.coverage.shellAliases).toEqual([...CLINE_SHELL_TOOLS]);
  });
  it("names this package and says the plugin fails open", async () => {
    // Built since integration w4 merged this lane and updated
    // contracts/contracts.test.ts (plans/parallel/tk_lane_P.md).
    expect(row.coverage.gate).toMatchObject({ status: "built", lane: "P", package: "packages/derm-cline" });
    expect(row.coverage.failMode).toBe("open");
  });
});

// Lane X's request 7 (integration w5, continue): the gate posts an
// `install.call` record for an install, beside its decision.
describe("install records", () => {
  itDerm("the plugin leaves an ask's installs to the approval file, which records them", async () => {
    let before = daemon.events().length;
    await beforeTool(ctx("run_commands", { commands: ["npm install left-pad@1.3.0"] }), deps());
    await settle();
    expect(daemon.events().slice(before).filter((e) => e.kind === "install.call")).toHaveLength(0);
    before = daemon.events().length;
    await answerRequest({ toolCallId: "t-inst", toolName: "run_commands", input: { commands: ["npm install left-pad@1.3.0"] } }, deps());
    const got = daemon.events().slice(before);
    const recs = got.filter((e) => e.kind === "install.call") as { detail: Record<string, unknown>; harness: string }[];
    expect(recs).toHaveLength(1);
    expect(recs[0]?.harness).toBe("cline");
    expect(recs[0]?.detail).toMatchObject({ manager: "npm", form: "add", packages: [{ name: "left-pad", version: "1.3.0", ecosystem: "npm" }], trust: "client" });
    const decision = (got.find((e) => e.kind === "approval") as { detail: { decision: string } } | undefined)?.detail.decision;
    expect(recs[0]?.detail.decision).toBe(decision);
    expect(recs[0]?.detail.toolUseId).toBe("t-inst");
  });
});

// Case 228: no co-process, no call; and never past Cline's 3 s. Runs with
// or without a derm build.
describe("a co-process that is not running", () => {
  const without = (o: Partial<ConstructorParameters<typeof GateServe>[0]>): Deps => {
    const s = new GateServe({ agent: "cline", env: {}, cwd: () => work, trusted: () => true, startMs: 1200, requestMs: 1200, locate: () => ({ problem: "no derm to run: DERM_BIN is not set" }), ...o });
    return { env: {}, cwd: () => work, serve: () => s };
  };
  it("skips every call with the reason, which Cline counts as an answer, not a failure", async () => {
    expect(await beforeTool(ctx("run_commands", { commands: ["ls"] }), without({}))).toEqual({ skip: true, reason: "derm: the derm gate co-process is not running (no derm to run: DERM_BIN is not set), so the call is refused" });
    expect(await answerRequest({ toolName: "run_commands", input: { commands: ["ls"] } }, without({}))).toMatchObject({ approved: false });
  });
  it("answers within Cline's 3 s when the co-process hangs or never says hello", async () => {
    const hang = without({ locate: () => ({ path: process.execPath }), spawn: () => spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: ["pipe", "pipe", "pipe"] }) });
    const t = Date.now();
    expect(await beforeTool(ctx("run_commands", { commands: ["ls"] }), hang)).toMatchObject({ skip: true, reason: expect.stringContaining("did not answer hello") });
    expect(Date.now() - t).toBeLessThan(2500);
  });
  it("the client copy is byte-identical to derm-pi's canonical one", () => {
    expect(readFileSync(path.join(here, "serve", "client.ts"), "utf8")).toBe(readFileSync(path.join(ROOT, "packages", "derm-pi", "src", "serve", "client.ts"), "utf8"));
  });
});
