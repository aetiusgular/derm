import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mistralVibe, vibeName } from "./dialects/mistralVibe.ts";
import { runPre } from "./runner.ts";
import { CASE_30, fixture, type Fixture } from "./testing.ts";

const FIX = new URL("../../../contracts/fixtures/hook-dialects/mistral-vibe/", import.meta.url);
const stdin = (tool: string, toolInput: unknown, extra: Record<string, unknown> = {}) =>
  JSON.stringify({ session_id: "v-1", transcript_path: "/t", cwd: "/w", parent_session_id: null, hook_event_name: "pre_tool", tool_name: tool, tool_call_id: "call_1", tool_input: toolInput, ...extra });

let f: Fixture;
beforeAll(async () => {
  f = await fixture({ rules: [{ tool: "bash", action: "allow" }, { tool: "read_file", action: "allow" }, { tool: "write_file", action: "allow" }, { tool: "exa/*", action: "allow" }, { tool: "my_server/*", action: "deny" }, { tool: "github/*", action: "ask" }] });
});
afterAll(async () => {
  await f.close();
});

describe("Mistral Vibe pre_tool", () => {
  it("allow prints nothing, so Vibe's own permission check follows (a hook cannot pre-approve)", async () => {
    expect(await runPre(mistralVibe, readFileSync(new URL("stdin.pre-tool.json", FIX), "utf8"), f.env())).toEqual({ stdout: "", stderr: "", exitCode: 0 });
  });

  it("deny is the JSON deny on exit 0, never exit 2 (a failure to Vibe)", async () => {
    const r = await runPre(mistralVibe, stdin("mcp_my_server.write", { a: 1 }), f.env());
    expect(r).toEqual({ stdout: `${JSON.stringify({ decision: "deny", reason: "derm: rule my_server/*" })}\n`, stderr: "", exitCode: 0 });
  });

  it("an ask goes to the approver or denies (the fixture's MCP call)", async () => {
    let r = await runPre(mistralVibe, readFileSync(new URL("stdin.pre-tool.mcp.json", FIX), "utf8"), f.env());
    expect(JSON.parse(r.stdout).decision).toBe("deny");
    f.daemon.setApprove("yes");
    r = await runPre(mistralVibe, readFileSync(new URL("stdin.pre-tool.mcp.json", FIX), "utf8"), f.env());
    expect(r).toEqual({ stdout: "", stderr: "", exitCode: 0 });
    f.daemon.setApprove("none");
  });

  it("names: one dot splits an MCP name; more asks; built-ins take the model's names", () => {
    expect(vibeName("mcp_exa.web_search_exa")).toEqual({ tool: "mcp__exa__web_search_exa" });
    expect(vibeName("mcp_exa.evil.t").ambiguous).toBeDefined();
    expect(vibeName("mcp_.t").ambiguous).toBeDefined();
    expect(vibeName("file_system.read_file")).toEqual({ tool: "read_file" });
    expect(vibeName("agents.spawn")).toEqual({ tool: "agents_spawn" });
  });

  it("a server name that folds into exa does not take exa's allow (W2-R1, W2-S2)", async () => {
    // Vibe folds a server name to identifier characters, so `exa-evil` reaches the hook as mcp_exa_evil.
    expect(JSON.parse((await runPre(mistralVibe, stdin("mcp_exa_evil.t", {}), f.env())).stdout).decision).toBe("deny");
    expect((await runPre(mistralVibe, stdin("mcp_exa.t", {}), f.env())).stdout).toBe("");
  });

  it("file_system.bash, process.start and process.write run case 30's checks (case 82)", async () => {
    for (const cmd of CASE_30) {
      for (const [tool, input] of [["file_system.bash", { command: cmd }], ["process.start", { command: cmd, cwd: "/w" }], ["process.write", { processId: "p1", text: cmd }]] as const) {
        const r = await runPre(mistralVibe, stdin(tool, input), f.env());
        expect(JSON.parse(r.stdout || "{}").decision, `${tool} ${cmd}`).toBe("deny");
      }
    }
    const b64 = Buffer.from("git -c core.fsmonitor=x status").toString("base64");
    expect(JSON.parse((await runPre(mistralVibe, stdin("process.write", { processId: "p1", bytesBase64: b64 }), f.env())).stdout).reason).toMatch(/reject list/);
  });

  it("a redacted MCP input is rewritten; a built-in tool's asks instead", async () => {
    const key = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789";
    const mcp = JSON.parse((await runPre(mistralVibe, stdin("mcp_exa.search", { q: "x", api_key: key }), f.env())).stdout);
    expect(JSON.stringify(mcp.hook_specific_output.tool_input)).toContain("[redacted by derm]");
    const w = JSON.parse((await runPre(mistralVibe, stdin("file_system.write_file", { file_path: "/w/a", content: key }), f.env())).stdout);
    expect(w.decision).toBe("deny");
    expect(w.reason).toMatch(/secret-like value in input/);
  });

  it("a Vibe control file in an allowed command asks", async () => {
    for (const cmd of ["cat /home/u/.vibe/hooks.toml", "VIBE_HOME=/tmp/x vibe"]) {
      expect(JSON.parse((await runPre(mistralVibe, stdin("file_system.bash", { command: cmd }), f.env())).stdout).decision, cmd).toBe("deny");
    }
  });

  it("bad input denies with Vibe's own deny", async () => {
    for (const bad of ["nope", JSON.stringify({ hook_event_name: "post_tool", tool_name: "x" }), JSON.stringify({ hook_event_name: "pre_tool" })]) {
      const r = await runPre(mistralVibe, bad, f.env());
      expect(JSON.parse(r.stdout).decision).toBe("deny");
      expect(r.exitCode).toBe(0);
    }
  });
});
