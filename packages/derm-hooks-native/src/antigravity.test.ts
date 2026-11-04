import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { antigravity } from "./dialects/antigravity.ts";
import { runPre } from "./runner.ts";
import { CASE_30, fixture, type Fixture } from "./testing.ts";

// antigravity.google/docs/hooks, PreToolUse "Example" input (read 3 Nov 2026).
const DOC_EXAMPLE = {
  toolCall: { name: "run_command", args: { CommandLine: "npm test", Cwd: "/workspace/project", WaitMsBeforeAsync: 5000 } },
  stepIdx: 19,
  conversationId: "ec33ebf9-0cba-4100-8142-c61503f6c587",
  workspacePaths: ["/workspace/project"],
  transcriptPath: "~/.gemini/antigravity/brain/ec33ebf9-0cba-4100-8142-c61503f6c587/.system_generated/logs/transcript.jsonl",
  artifactDirectoryPath: "~/.gemini/antigravity/brain/ec33ebf9-0cba-4100-8142-c61503f6c587",
  modelName: "gemini-3.6-flash-medium",
};
const call = (name: string, args: unknown) => JSON.stringify({ ...DOC_EXAMPLE, toolCall: { name, args } });
const decision = (r: { stdout: string }) => (JSON.parse(r.stdout) as { decision: string }).decision;

let f: Fixture;
beforeAll(async () => {
  f = await fixture();
});
afterAll(async () => {
  await f.close();
});

describe("Antigravity PreToolUse", () => {
  it("the docs' run_command example is bash: allowed with an explicit allow on exit 0", async () => {
    const r = await runPre(antigravity, JSON.stringify(DOC_EXAMPLE), f.env());
    expect(r).toEqual({ stdout: `${JSON.stringify({ decision: "allow", reason: "derm: rule bash" })}\n`, stderr: "", exitCode: 0 });
  });

  it("deny is the JSON deny on exit 0", async () => {
    const r = await runPre(antigravity, call("call_mcp_tool", { ServerName: "my-server", ToolName: "write", Arguments: {} }), f.env());
    expect(r).toEqual({ stdout: `${JSON.stringify({ decision: "deny", reason: "derm: rule my_server/*" })}\n`, stderr: "", exitCode: 0 });
  });

  it("an ask with no approver is force_ask, so a remembered Always Allow cannot answer it", async () => {
    expect(decision(await runPre(antigravity, call("call_mcp_tool", { ServerName: "github", ToolName: "create_issue", Arguments: {} }), f.env()))).toBe("force_ask");
    f.daemon.setApprove("no");
    expect(decision(await runPre(antigravity, call("call_mcp_tool", { ServerName: "github", ToolName: "create_issue", Arguments: {} }), f.env()))).toBe("deny");
    f.daemon.setApprove("none");
  });

  it("an MCP dispatcher call with no server derm can read asks on an allow", async () => {
    const strict = await fixture({ rules: [{ tool: "*", action: "allow" }] });
    try {
      expect(decision(await runPre(antigravity, call("call_mcp_tool", { q: "x" }), strict.env()))).toBe("force_ask");
      expect(decision(await runPre(antigravity, call("view_file", { AbsolutePath: "/w/a" }), strict.env()))).toBe("allow");
    } finally {
      await strict.close();
    }
  });

  it("run_command and manage_task send_input run case 30's checks (case 82); other manage_task actions are not shell", async () => {
    for (const cmd of CASE_30) {
      expect(decision(await runPre(antigravity, call("run_command", { CommandLine: cmd, Cwd: "/w" }), f.env())), cmd).toBe("force_ask");
      expect(decision(await runPre(antigravity, call("manage_task", { Action: "send_input", TaskId: "t", Input: cmd }), f.env())), cmd).toBe("force_ask");
    }
    expect(decision(await runPre(antigravity, call("run_command", { CommandLine: "git -c core.fsmonitor=x status", Cwd: "/w" }), f.env()))).toBe("deny");
  });

  it("an Antigravity control file in an allowed command asks", async () => {
    for (const cmd of ["cat /home/u/.gemini/config/hooks.json", "ls /w/.agents/hooks.json"]) {
      expect(decision(await runPre(antigravity, call("run_command", { CommandLine: cmd, Cwd: "/w" }), f.env())), cmd).toBe("force_ask");
    }
  });

  it("bad input denies with the JSON deny", async () => {
    for (const bad of ["x", JSON.stringify({ stepIdx: 1 }), JSON.stringify({ toolCall: { args: {} } })]) {
      const r = await runPre(antigravity, bad, f.env());
      expect(decision(r)).toBe("deny");
      expect(r.exitCode).toBe(0);
    }
  });
});
