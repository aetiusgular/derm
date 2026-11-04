import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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

const here = path.dirname(fileURLToPath(import.meta.url));
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

const deps = (extra: Record<string, string> = {}): Deps => defaultDeps({ DERM_POLICY: policyFile, ...daemon.env(), ...extra }, () => work);
let n = 0;
const ctx = (toolName: string, input: unknown): BeforeToolContext => ({ snapshot: { conversationId: "conv_1" }, toolCall: { toolCallId: `call_${++n}`, toolName, input }, input });
const settle = () => new Promise((r) => setTimeout(r, 50));

describe("the dialect's fixtures (contracts/fixtures/hook-dialects/cline)", () => {
  const fixture = (name: string) => JSON.parse(readFileSync(path.join(here, "../../../contracts/fixtures/hook-dialects/cline", name), "utf8"));
  it("answers the approval request fixture in the answer fixture's shape", async () => {
    expect(await answerRequest(fixture("approval-request.json"), deps())).toEqual(fixture("approval-answer.allow.json"));
    const denied = await answerRequest({ ...fixture("approval-request.json"), toolName: "fetch_web_content", input: { url: "https://x" } }, deps());
    expect(Object.keys(denied).sort()).toEqual(Object.keys(fixture("approval-answer.deny.json")).sort());
    expect(denied).toEqual({ approved: false, reason: "derm: rule fetch_web_content" });
  });
  it("reads the shell call in the file-hook fixture's tool_call the same way", () => {
    const f = fixture("stdin.pre-tool.json");
    expect(gateCallOf(f.tool_call.name, f.tool_call.input, { toolCallId: f.tool_call.id, conversationId: f.taskId }, {})).toMatchObject({ tool: "bash", toolInput: { command: "ls -la" }, chat: "conv_1" });
  });
});

describe("beforeTool (the SDK plugin)", () => {
  it("returns nothing on an allow rule, so Cline's own policy decides (case 72), and records it", async () => {
    const before = daemon.events().length;
    expect(beforeTool(ctx("run_commands", { commands: ["ls"] }), deps())).toBeUndefined();
    await settle();
    expect(daemon.events().slice(before)[0]).toMatchObject({ harness: "cline", kind: "approval", detail: { decision: "allow", tool: "bash", via: "plugin" } });
  });
  it("skips a denied call with the reason, never stop (case 79)", () => {
    expect(beforeTool(ctx("fetch_web_content", { url: "https://x" }), deps())).toEqual({ skip: true, reason: "derm: rule fetch_web_content" });
    expect(beforeTool(ctx("run_commands", { commands: ["git -c core.fsmonitor=./x status"] }), deps())).toEqual({ skip: true, reason: "derm: reject list: core.fsmonitor" });
    const out = beforeTool(ctx("run_commands", { commands: ["ls"] }), deps());
    expect(out).toBeUndefined();
  });
  it("turns an ask into Cline's own approval, whatever --auto-approve says (cases 71, 83)", () => {
    expect(beforeTool(ctx("github__create_issue", { title: "x" }), deps())).toEqual({ policy: { autoApprove: false } });
    // No rule: ask, never Cline's auto-approve (case 72).
    expect(beforeTool(ctx("spawn_agent", { task: "x" }), deps())).toEqual({ policy: { autoApprove: false } });
  });
  it("never waits on the daemon: an unreachable or hanging daemon does not hold the answer (Cline gives a hook 3 s)", () => {
    daemon.setApprove("hang");
    const started = Date.now();
    expect(beforeTool(ctx("github__create_issue", {}), deps())).toEqual({ policy: { autoApprove: false } });
    expect(beforeTool(ctx("run_commands", { commands: ["ls"] }), defaultDeps({ DERM_POLICY: policyFile, DERM_DAEMON_SOCKET: path.join(root, "absent.sock") }, () => work))).toBeUndefined();
    expect(Date.now() - started).toBeLessThan(500);
    daemon.setApprove("yes");
  });
  it("rewrites a secret-like value in an MCP call's input", () => {
    expect(beforeTool(ctx("exa__search", { query: "q", api_key: "abc" }), deps())).toEqual({ input: { query: "q", api_key: REDACTED } });
  });
  it("asks instead of rewriting a shell command or an editor write", () => {
    expect(beforeTool(ctx("run_commands", { commands: ["curl -H 'Authorization: Bearer sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789' h"] }), deps())).toEqual({ policy: { autoApprove: false } });
    expect(beforeTool(ctx("editor", { path: "a.env", new_text: "API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789" }), deps())).toEqual({ policy: { autoApprove: false } });
  });
  it("judges the input Cline will run (an earlier hook's rewrite), not the model's", () => {
    const c: BeforeToolContext = { snapshot: {}, toolCall: { toolCallId: "c1", toolName: "run_commands", input: { commands: ["ls"] } }, input: { commands: ["export ANTHROPIC_BASE_URL=http://x"] } };
    expect(beforeTool(c, deps())).toEqual({ skip: true, reason: "derm: reject list: anthropic_base_url" });
  });
  it("fails closed inside the hook: bad input and a broken policy load skip the call", () => {
    expect(beforeTool({} as BeforeToolContext, deps())).toEqual({ skip: true, reason: "derm: tool call has no tool name" });
    expect(beforeTool(undefined as never, deps())).toMatchObject({ skip: true });
    const broken = { ...deps(), loadPolicy: () => { throw new Error("boom"); } };
    expect(beforeTool(ctx("run_commands", { commands: ["ls"] }), broken)).toEqual({ skip: true, reason: "derm: hook error: boom" });
  });
  it("a policy inside the session folder is not used (a project can set it)", () => {
    const inside = path.join(work, "policy.json");
    writeFileSync(inside, readFileSync(policyFile));
    expect(beforeTool(ctx("run_commands", { commands: ["ls"] }), defaultDeps({ DERM_POLICY: inside }, () => work))).toEqual({ policy: { autoApprove: false } });
  });
});

describe("shell as bash (cases 30, 82)", () => {
  it("reads every shape Cline's normalizer takes, one command per line", () => {
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
  it("refuses input it cannot read the way Cline will (review P-S1)", () => {
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
      expect(beforeTool(ctx("run_commands", bad), deps()), JSON.stringify(bad)).toMatchObject({ skip: true });
    }
  });
  it("checks an argv entry as one command line, so the git checks see it (review P-S3)", () => {
    expect(beforeTool(ctx("run_commands", { command: "git", args: ["-c", "core.fsmonitor=x", "init", "g"] }), deps())).toEqual({ skip: true, reason: "derm: reject list: core.fsmonitor" });
    expect(beforeTool(ctx("run_commands", { commands: [{ command: "git", args: ["-c", "core.hooksPath=/tmp/h", "status"] }] }), deps())).toMatchObject({ skip: true });
  });
  it("case 30's tokens ask under an allow rule, through Cline's shell name", () => {
    for (const tool of CLINE_SHELL_TOOLS) {
      for (const cmd of ["echo $HOME", "ls `id`", "cat ~/.ssh/id_rsa", "rm -rf *", "echo {a,b}", "!!", "ls\\ -la", "print *(e:'x':)"]) {
        expect(beforeTool(ctx(tool, { commands: [cmd] }), deps()), `${tool}: ${cmd}`).toEqual({ policy: { autoApprove: false } });
      }
    }
  });
  it("a second command on its own line is checked too", () => {
    expect(beforeTool(ctx("run_commands", { commands: ["ls", "export CHATGPT_BASE_URL=http://x"] }), deps())).toMatchObject({ skip: true });
  });
  it("commands derm cannot read are refused", () => {
    expect(beforeTool(ctx("run_commands", { commands: [{ argv: ["ls"] }] }), deps())).toEqual({ skip: true, reason: "derm: run_commands holds an entry derm cannot read" });
  });
});

describe("answerRequest (the approval file)", () => {
  it("an allow rule approves; a deny rule and the reject list do not", async () => {
    expect(await answerRequest({ toolName: "run_commands", input: { commands: ["ls"] }, toolCallId: "t1" }, deps())).toEqual({ approved: true });
    expect(await answerRequest({ toolName: "run_commands", input: { commands: ["export ANTHROPIC_BASE_URL=x"] } }, deps())).toEqual({ approved: false, reason: "derm: reject list: anthropic_base_url" });
  });
  it("an ask is the approver's yes, else a deny (Cline's prompt is not reachable from the file)", async () => {
    daemon.setApprove("yes");
    expect(await answerRequest({ toolName: "github__create_issue", input: {}, toolCallId: "t2", conversationId: "conv_9" }, deps())).toEqual({ approved: true });
    // The chat never comes from the file, which the agent can write (review P-S5).
    expect(daemon.approvals().at(-1)).toMatchObject({ harness: "cline", tool: "github/create_issue", chat: "" });
    for (const b of ["no", "none", "timeout", "close"] as const) {
      daemon.setApprove(b);
      expect((await answerRequest({ toolName: "github__create_issue", input: {} }, deps())).approved, b).toBe(false);
    }
    daemon.setApprove("yes");
    expect(await answerRequest({ toolName: "github__create_issue", input: {} }, defaultDeps({ DERM_POLICY: policyFile, DERM_DAEMON_SOCKET: path.join(root, "absent.sock") }, () => work))).toMatchObject({ approved: false, reason: expect.stringContaining("not reachable") });
  });
  it("a secret-like value it cannot redact here asks", async () => {
    daemon.setApprove("none");
    expect((await answerRequest({ toolName: "exa__search", input: { api_key: "abc" } }, deps())).approved).toBe(false);
    daemon.setApprove("yes");
  });
  it("records the answer, as the approval file's", async () => {
    const before = daemon.events().length;
    await answerRequest({ toolName: "read_files", input: { paths: ["a"] }, toolCallId: "t3" }, deps());
    expect(daemon.events().slice(before)[0]).toMatchObject({ harness: "cline", kind: "approval", detail: { decision: "allow", via: "approval-file", toolUseId: "t3" } });
  });
  it("a request with no tool name, or a broken policy load, is a deny", async () => {
    expect(await answerRequest({} as never, deps())).toMatchObject({ approved: false });
    expect(await answerRequest(null as never, deps())).toMatchObject({ approved: false });
    expect(await answerRequest({ toolName: "run_commands", input: { commands: ["ls"] } }, { ...deps(), loadPolicy: () => { throw new Error("boom"); } })).toEqual({ approved: false, reason: "derm: responder error: boom" });
  });
});

describe("redaction rules and cost (review P-S2, P-S6)", () => {
  it("rewrites only for MCP tools and fetch_web_content; apply_patch and editor ask even when a server name would split them", () => {
    const allowAll = { ...deps(), loadPolicy: () => ({ policy: { version: 1 as const, askTimeoutSeconds: 1, servers: ["apply"], rules: [{ tool: "*", action: "allow" as const }] } }) };
    expect(beforeTool(ctx("fetch_web_content", { url: "https://h/?token=zz9" }), allowAll)).toEqual({ input: { url: `https://h/?token=${REDACTED}` } });
    expect(beforeTool(ctx("apply_patch", { patch: "+API_KEY=abc" }), allowAll)).toEqual({ policy: { autoApprove: false } });
    expect(beforeTool(ctx("editor", { path: "a", new_text: "password=hunter22" }), allowAll)).toEqual({ policy: { autoApprove: false } });
  });
  it("refuses input that would make the core's redaction slow, in well under Cline's 3 s", async () => {
    const heavy = "token.".repeat(4000);
    let t = Date.now();
    expect(beforeTool(ctx("run_commands", { commands: [`echo ${heavy}`] }), deps())).toMatchObject({ skip: true, reason: expect.stringContaining("cannot check in time") });
    expect(Date.now() - t).toBeLessThan(500);
    t = Date.now();
    expect(await answerRequest({ toolName: "editor", input: { new_text: heavy } }, deps())).toMatchObject({ approved: false });
    expect(Date.now() - t).toBeLessThan(500);
    // Many medium runs add up too.
    const many = Array.from({ length: 40 }, () => "token.".repeat(170)).join(" ");
    t = Date.now();
    expect(beforeTool(ctx("editor", { new_text: many }), deps())).toMatchObject({ skip: true });
    expect(Date.now() - t).toBeLessThan(500);
    // Ordinary large input passes the guard.
    expect(overBudget({ text: "a".repeat(200_000), b: "token ".repeat(5000) })).toBeUndefined();
  });
});

describe("Cline's control files", () => {
  it("lists the markers in folded form", () => {
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
  ])("%s names %s", (text, marker) => {
    expect(clineControlPath(text)).toBe(marker);
  });
  it("an allowed write into Cline's plugin folder asks", () => {
    expect(beforeTool(ctx("editor", { path: "/home/u/.cline/plugins/x.ts", new_text: "export default {}" }), deps())).toEqual({ policy: { autoApprove: false } });
    expect(beforeTool(ctx("run_commands", { commands: ["echo '{\"approved\":true}' > /run/user/1000/derm/cline-approvals/a.decision.b.json"] }), deps())).toEqual({ policy: { autoApprove: false } });
  });
});

describe("the plugin module", () => {
  it("is an AgentPlugin named derm with one beforeTool hook", () => {
    expect(plugin.name).toBe("derm");
    expect(plugin.manifest).toEqual({ capabilities: ["hooks"] });
    expect(Object.keys(plugin.hooks)).toEqual(["beforeTool"]);
  });
  it("package.json names it as the Cline plugin entry", () => {
    const pkg = JSON.parse(readFileSync(path.join(here, "../package.json"), "utf8"));
    expect(pkg.cline.plugins).toEqual([{ paths: ["./src/plugin.ts"], capabilities: ["hooks"] }]);
  });
  it("reads no file when it loads or is set up (case 46)", () => {
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
  it("imports only node: built-ins and files inside src/, so the folder can be copied whole", () => {
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
  it("names the same shell tools as the dialect (case 82)", () => {
    expect(row.coverage.shellAliases).toEqual([...CLINE_SHELL_TOOLS]);
  });
  it("names this package and says the plugin fails open", () => {
    // `status` stays "planned" until integration w4 merges this lane and
    // updates contracts/contracts.test.ts (plans/parallel/tk_lane_P.md).
    expect(row.coverage.gate).toMatchObject({ status: "planned", lane: "P", package: "packages/derm-cline" });
    expect(row.coverage.failMode).toBe("open");
  });
});
