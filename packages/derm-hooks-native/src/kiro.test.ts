import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { kiro } from "./dialects/kiro.ts";
import { kiroServerNames } from "./kiroServers.ts";
import { runPre } from "./runner.ts";
import { CASE_30, fixture, type Fixture } from "./testing.ts";

let f: Fixture;
let work: string;
beforeAll(async () => {
  f = await fixture();
  mkdirSync(path.join(f.dir, ".kiro", "settings"), { recursive: true });
  writeFileSync(path.join(f.dir, ".kiro", "settings", "mcp.json"), JSON.stringify({ mcpServers: { exa: {}, github: {}, "my-server": {} } }));
  work = path.join(f.dir, "work");
  mkdirSync(work);
});
afterAll(async () => {
  await f.close();
});

// kiro.dev/docs/hooks/types, "MCP tool hooks" (V3), with its fields.
const stdin = (tool: string, toolInput: unknown) => JSON.stringify({ hook_event_name: "PreToolUse", cwd: work, session_id: "abc123-def456-789", tool_name: tool, tool_input: toolInput });

describe("Kiro PreToolUse", () => {
  it("allow is exit 0 with nothing printed, since stdout would reach the model (case 77)", async () => {
    expect(await runPre(kiro, stdin("execute_bash", { command: "ls" }), f.env())).toEqual({ stdout: "", stderr: "", exitCode: 0 });
  });

  it("deny is exit 2 with the reason on stderr", async () => {
    expect(await runPre(kiro, stdin("mcp_my-server_write", {}), f.env())).toEqual({ stdout: "", stderr: "derm: rule my_server/*\n", exitCode: 2 });
  });

  it("the docs' MCP example splits at the configured server; an ask goes to the approver or denies", async () => {
    const strict = await fixture({ rules: [{ tool: "postgres/query", action: "ask" }] });
    try {
      mkdirSync(path.join(strict.dir, ".kiro", "settings"), { recursive: true });
      writeFileSync(path.join(strict.dir, ".kiro", "settings", "mcp.json"), JSON.stringify({ mcpServers: { postgres: {} } }));
      const input = JSON.stringify({ hook_event_name: "PreToolUse", cwd: work, session_id: "s", tool_name: "mcp_postgres_query", tool_input: { sql: "SELECT * FROM orders LIMIT 10;" } });
      expect((await runPre(kiro, input, strict.env())).stderr).toMatch(/rule postgres\/query; ask needs an approver/);
      strict.daemon.setApprove("yes");
      expect((await runPre(kiro, input, strict.env())).exitCode).toBe(0);
    } finally {
      await strict.close();
    }
  });

  it("a workspace server that starts like exa makes exa's allow ask (W2-R1)", async () => {
    expect((await runPre(kiro, stdin("mcp_exa_evil_t", {}), f.env())).exitCode).toBe(0);
    mkdirSync(path.join(work, ".kiro", "settings"), { recursive: true });
    writeFileSync(path.join(work, ".kiro", "settings", "mcp.json"), JSON.stringify({ mcpServers: { exa_evil: {} } }));
    const r = await runPre(kiro, stdin("mcp_exa_evil_t", {}), f.env());
    expect(r.stderr).toMatch(/more than one configured Kiro MCP server name fits/);
    writeFileSync(path.join(work, ".kiro", "settings", "mcp.json"), "{}");
  });

  it("a Markdown agent profile or Powers make the server list incomplete", () => {
    mkdirSync(path.join(work, ".kiro", "agents"), { recursive: true });
    writeFileSync(path.join(work, ".kiro", "agents", "a.md"), "---\nmcpServers: {}\n---\n");
    expect(kiroServerNames({}, work, f.dir).complete).toBe(false);
  });

  it("execute_bash runs case 30's checks (case 82)", async () => {
    for (const cmd of CASE_30) expect((await runPre(kiro, stdin("execute_bash", { command: cmd }), f.env())).exitCode, cmd).toBe(2);
  });

  it("a Kiro control file in an allowed command asks", async () => {
    expect((await runPre(kiro, stdin("execute_bash", { command: "cat /home/u/.kiro/hooks/derm.json" }), f.env())).exitCode).toBe(2);
  });

  it("bad input denies", async () => {
    expect((await runPre(kiro, JSON.stringify({ hook_event_name: "PostToolUse", tool_name: "x" }), f.env())).exitCode).toBe(2);
    expect((await runPre(kiro, "", f.env())).exitCode).toBe(2);
  });
});
