import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { cursor } from "./dialects/cursor.ts";
import { runPre } from "./runner.ts";
import { CASE_30, fixture, type Fixture } from "./testing.ts";

// Built from cursor.com/docs/agent/hooks (read 3 Nov 2026): preToolUse's
// documented input example and beforeMCPExecution's fields, plus the common
// fields every hook gets.
const common = { conversation_id: "conv-1", generation_id: "gen-1", model: "m", cursor_version: "2026.10.22", workspace_roots: ["/project"], user_email: "u@example.com", transcript_path: "/t" };
const pre = (tool: string, toolInput: unknown) => JSON.stringify({ ...common, hook_event_name: "preToolUse", tool_name: tool, tool_input: toolInput, tool_use_id: "abc123", cwd: "/project" });
const mcp = (server: string | undefined, tool: string, toolInput: unknown) =>
  JSON.stringify({ ...common, hook_event_name: "beforeMCPExecution", tool_name: tool, tool_input: JSON.stringify(toolInput), ...(server !== undefined ? { mcp_server_name: server } : {}), url: "https://x", mcp_server_url: "https://x" });

let f: Fixture;
beforeAll(async () => {
  f = await fixture();
});
afterAll(async () => {
  await f.close();
});

const permission = (r: { stdout: string }) => (JSON.parse(r.stdout) as { permission: string }).permission;

describe("Cursor preToolUse", () => {
  it("allows the documented Shell example under allow-bash with an explicit allow", async () => {
    const r = await runPre(cursor, pre("Shell", { command: "npm install", working_directory: "/project" }), f.env());
    expect(r).toEqual({ stdout: `${JSON.stringify({ permission: "allow" })}\n`, stderr: "", exitCode: 0 });
  });

  it("denies with Cursor's JSON on exit 0, the reason to the user and the agent", async () => {
    const r = await runPre(cursor, pre("Write", { file_path: "/project/a" }), f.env());
    // write: ask, Cursor does not enforce ask on preToolUse, no approver: deny.
    expect(JSON.parse(r.stdout)).toMatchObject({ permission: "deny" });
    expect(JSON.parse(r.stdout).agent_message).toMatch(/^derm: rule write; ask needs an approver/);
    expect(r.exitCode).toBe(0);
  });

  it("never sends ask on preToolUse: an approver's yes allows, no denies", async () => {
    f.daemon.setApprove("yes");
    expect(permission(await runPre(cursor, pre("Write", { file_path: "/project/a" }), f.env()))).toBe("allow");
    f.daemon.setApprove("no");
    expect(permission(await runPre(cursor, pre("Write", { file_path: "/project/a" }), f.env()))).toBe("deny");
    f.daemon.setApprove("none");
  });

  it("an MCP:<tool> call names no server: denied outright where the policy denies the name, else left to beforeMCPExecution (case 73)", async () => {
    const strict = await fixture({ rules: [{ tool: "delete_repo", action: "deny" }, { tool: "exa/*", action: "allow" }] });
    try {
      expect(permission(await runPre(cursor, pre("MCP:delete_repo", {}), strict.env()))).toBe("deny");
      const r = await runPre(cursor, pre("MCP:web_search", { q: "x" }), strict.env());
      expect(permission(r)).toBe("allow");
      const ev = strict.daemon.events().at(-1) as { detail: { decision: string } };
      expect(ev.detail.decision).toBe("deferred");
    } finally {
      await strict.close();
    }
  });

  it("Shell runs case 30's checks", async () => {
    for (const cmd of CASE_30) expect(permission(await runPre(cursor, pre("Shell", { command: cmd }), f.env())), cmd).toBe("deny");
  });

  it("a Cursor control file in an allowed command asks", async () => {
    expect(permission(await runPre(cursor, pre("Shell", { command: "cat /home/u/.cursor/hooks.json" }), f.env()))).toBe("deny");
  });
});

describe("Cursor beforeMCPExecution", () => {
  it("decides by server and tool, with Cursor's own prompt for an ask", async () => {
    expect(permission(await runPre(cursor, mcp("exa", "web_search_exa", { q: "x" }), f.env()))).toBe("allow");
    expect(permission(await runPre(cursor, mcp("my-server", "write", {}), f.env()))).toBe("deny");
    const r = await runPre(cursor, mcp("github", "create_issue", { title: "x" }), f.env());
    expect(JSON.parse(r.stdout)).toMatchObject({ permission: "ask" });
  });

  it("a missing server name denies, as Cursor's docs advise", async () => {
    expect(permission(await runPre(cursor, mcp(undefined, "web_search_exa", {}), f.env()))).toBe("deny");
  });

  it("a secret-like value in an MCP input is a deny (no updated_input on this event)", async () => {
    const r = await runPre(cursor, mcp("exa", "search", { api_key: "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789" }), f.env());
    expect(permission(r)).toBe("deny");
    expect(r.stdout).not.toContain("abcdefghijklmnop");
  });

  it("an unknown event or bad input denies", async () => {
    expect(permission(await runPre(cursor, JSON.stringify({ hook_event_name: "beforeReadFile", file_path: "/x" }), f.env()))).toBe("deny");
    expect(permission(await runPre(cursor, "{", f.env()))).toBe("deny");
  });
});
