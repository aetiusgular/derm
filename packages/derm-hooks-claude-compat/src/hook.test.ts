// The eight dialects against their fixtures (contracts/fixtures/hook-dialects/)
// and a fake derm daemon on a real socket: the main path per agent and the
// corner cases a command hook touches (rules section 4: 30, 66, 70 to 72, 76,
// 77, 79, 82, 83).

import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startFakeDaemon, type FakeDaemon } from "../../derm-claude-plugin/src/testing/fakeDaemon.ts";
import { DIALECTS, SHELL_ALIASES } from "./agents.ts";
import { defaultDeps, runHook } from "./hook.ts";
import { REDACTED } from "./core/redact.ts";

const here = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.resolve(here, "..", "..", "..", "contracts", "fixtures", "hook-dialects");
const PRESETS = path.resolve(here, "..", "..", "..", "crates", "derm-cli", "src", "connect", "presets");
const AGENTS = ["openclaude", "qwen-code", "droid", "command-code", "kimi", "auggie", "copilot-cli", "grok"] as const;
type Agent = (typeof AGENTS)[number];

const root = mkdtempSync(path.join(tmpdir(), "derm-l-"));
function policy(name: string, body: unknown): string {
  const f = path.join(root, `${name}.json`);
  writeFileSync(f, JSON.stringify(body), { mode: 0o600 });
  return f;
}
const POL = {
  allowAll: policy("allow", { version: 1, askTimeoutSeconds: 1, servers: ["example-server", "exa"], rules: [{ tool: "*", action: "allow" }] }),
  denyBash: policy("deny", { version: 1, askTimeoutSeconds: 1, rules: [{ tool: "bash", action: "deny" }, { tool: "*", action: "allow" }] }),
  askAll: policy("ask", { version: 1, askTimeoutSeconds: 1, servers: ["example-server", "exa"], rules: [{ tool: "*", action: "ask" }] }),
};

let daemon: FakeDaemon;
beforeAll(async () => {
  daemon = await startFakeDaemon({ root: "/tmp" });
});
afterAll(async () => {
  await daemon.close();
  rmSync(root, { recursive: true, force: true });
});

const fixture = (agent: string, file: string): Record<string, unknown> => JSON.parse(readFileSync(path.join(FIXTURES, agent, file), "utf8")) as Record<string, unknown>;
const env = (policyFile: string, extra: Record<string, string> = {}) => ({ DERM_POLICY: policyFile, ...daemon.env(), ...extra });
const noDaemon = (policyFile: string) => ({ DERM_POLICY: policyFile, DERM_DAEMON_SOCKET: path.join(root, "absent.sock") });

/** The fixture's shell call with another command. */
function shellCall(agent: Agent, command: string, extra: Record<string, unknown> = {}): string {
  const f = fixture(agent, "stdin.pre-tool.json");
  if ("toolArgs" in f) f.toolArgs = { ...(f.toolArgs as object), command };
  else if ("toolInput" in f) f.toolInput = { ...(f.toolInput as object), command };
  else f.tool_input = { ...(f.tool_input as object), command };
  return JSON.stringify({ ...f, ...extra });
}
function mcpCall(agent: Agent, args: unknown, extra: Record<string, unknown> = {}): string | undefined {
  let f: Record<string, unknown>;
  try {
    f = fixture(agent, "stdin.pre-tool.mcp.json");
  } catch {
    return undefined;
  }
  if ("toolInput" in f) f.toolInput = args;
  else f.tool_input = args;
  return JSON.stringify({ ...f, ...extra });
}

const OWN_ASK = new Set<Agent>(["openclaude", "qwen-code", "copilot-cli", "grok"]);
const REWRITES = new Set<Agent>(["openclaude", "qwen-code", "droid", "auggie", "copilot-cli", "grok"]);

/** What a reply means to the agent, read the way the agent reads it. */
function verdict(agent: Agent, r: { stdout: string; stderr: string; exitCode: number }): "allow" | "deny" | "ask" | "none" {
  if (r.exitCode === 2) return "deny";
  expect(r.exitCode).toBe(0);
  if (r.stdout.trim() === "") return "none";
  const o = JSON.parse(r.stdout) as Record<string, unknown>;
  const hso = (o.hookSpecificOutput ?? {}) as Record<string, unknown>;
  const d = (agent === "grok" ? (hso.permissionDecision ?? o.decision) : agent === "copilot-cli" ? o.permissionDecision : hso.permissionDecision) as string;
  return d as "allow" | "deny" | "ask";
}

describe.each(AGENTS)("%s", (agent) => {
  const d = DIALECTS[agent]!;

  it("denies the fixture's shell call under a bash deny rule, with exit 2 and the reason on stderr (cases 79, 82)", async () => {
    const before = daemon.events().length;
    const r = await runHook(agent, "pre", shellCall(agent, "ls -la"), env(POL.denyBash));
    expect(r.exitCode).toBe(2);
    expect(r.stderr).toMatch(/^derm: rule bash/);
    const ev = daemon.events().slice(before);
    expect(ev).toHaveLength(1);
    expect(ev[0]).toMatchObject({ harness: agent, kind: "approval", detail: { decision: "deny", tool: "bash" } });
    // Case 77: the record and the reply never carry the tool input.
    expect(JSON.stringify(ev[0])).not.toContain("ls -la");
    expect(r.stdout + r.stderr).not.toContain("ls -la");
  });

  it("allows the shell call only where a rule says allow (case 72)", async () => {
    const r = await runHook(agent, "pre", shellCall(agent, "ls -la"), env(POL.allowAll));
    const v = verdict(agent, r);
    if (agent === "kimi") expect(v).toBe("none");
    else expect(v).toBe("allow");
  });

  it("matches the fixture's deny reply shape", async () => {
    const r = await runHook(agent, "pre", shellCall(agent, "ls -la"), env(POL.denyBash));
    const want = fixture(agent, "reply.deny.json");
    const got = JSON.parse(r.stdout) as Record<string, unknown>;
    const keys = (o: Record<string, unknown>) => Object.keys(o).filter((k) => !["continue", "systemMessage", "suppressOutput", "stopReason"].includes(k)).sort();
    expect(keys(got)).toEqual(keys(want));
    if (want.hookSpecificOutput) {
      expect((got.hookSpecificOutput as Record<string, unknown>).permissionDecision).toBe("deny");
    }
    // Case 79: no reply ends the run.
    expect(got.continue).toBeUndefined();
    expect(Number(readFileSync(path.join(FIXTURES, agent, "reply.deny.exit"), "utf8").trim())).toBe(r.exitCode);
  });

  it("an ask with an approver's yes is an allow, a no is a deny", async () => {
    daemon.setApprove("yes");
    const yes = await runHook(agent, "pre", shellCall(agent, "ls"), env(POL.askAll));
    daemon.setApprove("no");
    const no = await runHook(agent, "pre", shellCall(agent, "ls"), env(POL.askAll));
    daemon.setApprove("none");
    expect(verdict(agent, yes)).toBe(agent === "kimi" ? "none" : "allow");
    expect(verdict(agent, no)).toBe("deny");
  });

  it(`with no approver, an ask is ${OWN_ASK.has(agent) ? "the agent's own prompt" : "a deny"} (case 71)`, async () => {
    daemon.setApprove("none");
    const r = await runHook(agent, "pre", shellCall(agent, "ls"), env(POL.askAll));
    expect(verdict(agent, r)).toBe(OWN_ASK.has(agent) ? "ask" : "deny");
    const off = await runHook(agent, "pre", shellCall(agent, "ls"), noDaemon(POL.askAll));
    expect(verdict(agent, off)).toBe(OWN_ASK.has(agent) ? "ask" : "deny");
  });

  // Copilot's input names no permission mode; Copilot itself denies a hook's
  // ask in autopilot and wherever it cannot ask (runtime.node strings,
  // changelog 1.0.97), which fails safe. Its --allow-all run is the contract
  // check copilot-derm-full-access.
  if (OWN_ASK.has(agent) && agent !== "copilot-cli") {
    it("under a bypass mode an ask never goes to the agent's prompt (case 83)", async () => {
      const modeKey = agent === "grok" ? "permissionMode" : "permission_mode";
      for (const mode of ["bypassPermissions", "yolo", "autopilot"]) {
        const r = await runHook(agent, "pre", shellCall(agent, "ls", { [modeKey]: mode }), noDaemon(POL.askAll));
        expect(verdict(agent, r)).toBe("deny");
      }
    });
  }

  it("the reject list denies under an allow-all rule", async () => {
    const r = await runHook(agent, "pre", shellCall(agent, "echo export ANTHROPIC_BASE_URL=http://x >> .envrc"), env(POL.allowAll));
    expect(r.exitCode).toBe(2);
    expect(r.stderr).toContain("reject list: anthropic_base_url");
  });

  it("case 30's shell text asks under an allowed shell (through its alias, case 82), and is denied with no approver", async () => {
    for (const command of ["echo $HOME", "ls ~", "cat *.env", "echo `id`"]) {
      const r = await runHook(agent, "pre", shellCall(agent, command), noDaemon(POL.allowAll));
      expect(verdict(agent, r), command).toBe(OWN_ASK.has(agent) ? "ask" : "deny");
    }
  });

  it("an allowed call that names one of the eight agents' control files asks", async () => {
    for (const command of ["cat ~/.factory/hooks.json", "echo x >> .qwen/settings.json", "rm .grok/hooks/derm.json", "export KIMI_CODE_HOME=/tmp/k"]) {
      const r = await runHook(agent, "pre", shellCall(agent, command.replace("~", "/home/u")), noDaemon(POL.allowAll));
      expect(verdict(agent, r), command).toBe(OWN_ASK.has(agent) ? "ask" : "deny");
    }
  });

  it("refuses input it cannot read: not JSON, not an object, no tool, another event", async () => {
    for (const text of ["not json", "[]", "{}", JSON.stringify({ hook_event_name: "PostToolUse", tool_name: "Bash", tool_input: {} })]) {
      const r = await runHook(agent, "pre", text, env(POL.allowAll));
      expect(r.exitCode, text).toBe(2);
    }
  });

  const mcp = mcpCall(agent, { query: "x", apiKey: "sk-ant-api03-" + "a".repeat(80) });
  if (mcp !== undefined) {
    it(`a secret in an allowed MCP call's input is ${REWRITES.has(agent) ? "rewritten" : "asked about"}, never sent as it is`, async () => {
      const r = await runHook(agent, "pre", mcp, noDaemon(POL.allowAll));
      expect(r.stdout + r.stderr).not.toContain("a".repeat(80));
      if (agent === "auggie" || agent === "droid") {
        // Auggie: no mcp_metadata in the fixture, so the server is not known.
        // Droid: its `<server>___<tool>` is not yet a declared separator in
        // the core (W2-R1), so the split is in doubt. Either way an allow
        // asks, and with no approver that is a deny.
        expect(verdict(agent, r)).toBe("deny");
      } else if (REWRITES.has(agent)) {
        expect(verdict(agent, r)).toBe("allow");
        expect(r.stdout).toContain(REDACTED);
      } else {
        expect(verdict(agent, r)).toBe("deny");
      }
    });
  }

  it("its shell aliases equal its preset row's coverage.shellAliases", () => {
    const row = JSON.parse(readFileSync(path.join(PRESETS, `${agent}.json`), "utf8")) as { coverage: { shellAliases: string[] } };
    expect([...(SHELL_ALIASES[agent] ?? [])].sort()).toEqual([...row.coverage.shellAliases].sort());
    expect(d.id).toBe(agent);
  });
});

describe("Auggie's MCP names", () => {
  it("with includeMCPMetadata the server and tool come from mcp_metadata, so a server rule applies", async () => {
    const f = fixture("auggie", "stdin.pre-tool.mcp.json");
    const meta = { timestamp: "t", mcpDecision: "yes", mcpTotalToolsCount: 3, mcpExecutedToolName: "example_tool", mcpExecutedToolServerName: "exa" };
    const pol = policy("auggie-mcp", { version: 1, servers: ["exa"], rules: [{ tool: "exa/*", action: "deny" }, { tool: "*", action: "allow" }] });
    const r = await runHook("auggie", "pre", JSON.stringify({ ...f, tool_name: "example_tool_exa", mcp_metadata: meta }), noDaemon(pol));
    expect(r.exitCode).toBe(2);
    expect(r.stderr).toContain("rule exa/*");
  });

  it("without mcp_metadata an allowed MCP call asks, since the server is not known (case 73)", async () => {
    const r = await runHook("auggie", "pre", JSON.stringify(fixture("auggie", "stdin.pre-tool.mcp.json")), noDaemon(POL.allowAll));
    expect(r.exitCode).toBe(2);
    expect(r.stderr).toContain("Auggie did not name the MCP server");
  });
});

describe("the chat token when the agent strips it (case 76)", () => {
  it("Command Code: with DERM_CHAT_TOKEN and DERM_CHAT_TOKEN_FILE stripped, the hook finds the token file from DERM_CHAT_ID and DERM_DAEMON_SOCKET", async () => {
    const chat = "derm-0123456789ab";
    const chats = path.join(daemon.dir, "chats");
    mkdirSync(chats, { recursive: true, mode: 0o700 });
    const file = path.join(chats, `${chat}.token`);
    writeFileSync(file, `${daemon.chatToken}\n`, { mode: 0o600 });
    chmodSync(file, 0o600);
    daemon.setApprove("yes");
    try {
      const stripped = { DERM_POLICY: POL.askAll, DERM_DAEMON_SOCKET: daemon.socket, DERM_CHAT_ID: chat };
      // The fake daemon's folder stands in for derm's own socket folder (L-S6).
      const r = await runHook("command-code", "pre", shellCall("command-code", "ls"), stripped, defaultDeps(stripped, [path.dirname(daemon.socket)]));
      expect(verdict("command-code", r)).toBe("allow");
      const last = daemon.approvals().at(-1);
      expect(last).toMatchObject({ harness: "command-code", chat });
      // The same socket outside derm's own folders: no token is derived, so
      // the approver cannot be asked and the ask is a deny.
      const before = daemon.approvals().length;
      const planted = await runHook("command-code", "pre", shellCall("command-code", "ls"), stripped);
      expect(verdict("command-code", planted)).toBe("deny");
      expect(daemon.approvals()).toHaveLength(before);
    } finally {
      daemon.setApprove("none");
      rmSync(chats, { recursive: true, force: true });
    }
  });

  it("a chat id with a separator or a dot is not used to find a file", async () => {
    const { derivedTokenFile } = await import("./env.ts");
    const dirs = ["/run/user/1/derm"];
    for (const chat of ["../x", "a/b", ".hidden", "", "x".repeat(65)]) {
      expect(derivedTokenFile({ DERM_CHAT_ID: chat, DERM_DAEMON_SOCKET: "/run/user/1/derm/daemon.sock" }, dirs), chat).toBeUndefined();
    }
    expect(derivedTokenFile({ DERM_CHAT_ID: "derm-0123456789ab", DERM_DAEMON_SOCKET: "relative/daemon.sock" }, ["relative"])).toBeUndefined();
    expect(derivedTokenFile({ DERM_CHAT_ID: "derm-0123456789ab", DERM_DAEMON_SOCKET: "/run/user/1/derm/daemon.sock" }, dirs)).toBe("/run/user/1/derm/chats/derm-0123456789ab.token");
  });
});

describe("the launcher", () => {
  const bin = path.resolve(here, "..", "bin", "derm-hook.mjs");
  it("blocks with exit 2 for an unknown agent or event, and never prints the input", () => {
    for (const args of [["nope", "pre"], ["grok", "post"], []]) {
      const r = spawnSync(process.execPath, ["--no-warnings", bin, ...args], { input: JSON.stringify({ tool_name: "Bash", tool_input: { command: "secret-cmd" } }), encoding: "utf8" });
      expect(r.status, args.join(" ")).toBe(2);
      expect(r.stdout + r.stderr).not.toContain("secret-cmd");
    }
  });

  it("runs the hook end to end for each agent's fixture", () => {
    for (const agent of AGENTS) {
      const r = spawnSync(process.execPath, ["--no-warnings", bin, agent, "pre"], { input: shellCall(agent, "ls"), encoding: "utf8", env: { PATH: process.env.PATH ?? "", HOME: root, ...noDaemon(POL.denyBash) } });
      expect(r.status, agent).toBe(2);
      expect(r.stderr, agent).toMatch(/^derm: rule bash/);
    }
  });
});

// Lane X's request 7 (integration w5, continue): the gate posts an
// `install.call` record for an install, beside its decision.
describe.each(AGENTS)("%s install records", (agent) => {
  it("posts install.call beside the decision", async () => {
    const before = daemon.events().length;
    await runHook(agent, "pre", shellCall(agent, "npm install left-pad@1.3.0"), env(POL.denyBash));
    const ev = daemon.events().slice(before);
    const recs = ev.filter((e) => e.kind === "install.call") as { detail: Record<string, unknown>; harness: string }[];
    expect(recs).toHaveLength(1);
    expect(recs[0]?.harness).toBe(agent);
    expect(recs[0]?.detail).toMatchObject({ manager: "npm", form: "add", packages: [{ name: "left-pad", version: "1.3.0", ecosystem: "npm" }], trust: "client" });
    const decision = (ev.find((e) => e.kind === "approval") as { detail: { decision: string } } | undefined)?.detail.decision;
    expect(recs[0]?.detail.decision).toBe(decision);
  });
});
