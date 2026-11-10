import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { goose } from "./dialects/goose.ts";
import { runPre } from "./runner.ts";
import { CASE_30, fixture, type Fixture } from "./testing.ts";

const FIX = new URL("../../../contracts/fixtures/hook-dialects/goose/", import.meta.url);
const stdin = (tool: string, toolInput: unknown, extra: Record<string, unknown> = {}) =>
  JSON.stringify({ event: "PreToolUse", session_id: "g-1", matcher_context: tool, tool_name: tool, tool_input: toolInput, tool_call_id: "call_1", working_dir: "/w", ...extra });

let f: Fixture;
beforeAll(async () => {
  f = await fixture();
});
afterAll(async () => {
  await f.close();
});

describe("goose PreToolUse", () => {
  it("allow is exit 0 with nothing printed (goose's documented allow)", async () => {
    expect(await runPre(goose, readFileSync(new URL("stdin.pre-tool.json", FIX), "utf8"), f.env())).toEqual({ stdout: "", stderr: "", exitCode: 0 });
  });

  it("deny is exit 2 with the reason on stderr and a block on stdout, so either reading denies", async () => {
    const r = await runPre(goose, stdin("my-server__write", { a: 1 }), f.env());
    expect(r.exitCode).toBe(2);
    expect(JSON.parse(r.stdout)).toEqual({ decision: "block", reason: "derm: rule my_server/*" });
    expect(r.stderr).toBe("derm: rule my_server/*\n");
  });

  it("an extension tool is matched as <extension>/<tool> (the fixture's MCP call)", async () => {
    const r = await runPre(goose, readFileSync(new URL("stdin.pre-tool.mcp.json", FIX), "utf8"), f.env());
    // github/* asks; goose has no prompt for a hook and no approver is connected: deny.
    expect(r.exitCode).toBe(2);
    expect(r.stderr).toMatch(/ask needs an approver and none is connected/);
  });

  it("an ask goes to the daemon approver: yes allows, no denies (case 71)", async () => {
    f.daemon.setApprove("yes");
    expect((await runPre(goose, stdin("github__create_issue", { title: "x" }), f.env())).exitCode).toBe(0);
    f.daemon.setApprove("no");
    expect((await runPre(goose, stdin("github__create_issue", { title: "x" }), f.env())).exitCode).toBe(2);
    f.daemon.setApprove("none");
  });

  it("an extension name with two runs of __ asks instead of taking exa's allow", async () => {
    const r = await runPre(goose, stdin("exa__evil__t", {}), f.env());
    expect(r.exitCode).toBe(2);
    expect(r.stderr).toMatch(/ambiguous extension name/);
    expect((await runPre(goose, stdin("exa__search", {}), f.env())).exitCode).toBe(0);
  });

  it("the shell tool runs case 30's checks (case 82)", async () => {
    for (const cmd of CASE_30) {
      const r = await runPre(goose, stdin("shell", { command: cmd }), f.env());
      expect(r.exitCode, cmd).toBe(2);
    }
    expect((await runPre(goose, stdin("shell", { command: "git -c core.fsmonitor=x status" }), f.env())).stderr).toMatch(/reject list/);
  });

  it("a goose control file in an allowed command asks", async () => {
    for (const cmd of ["cat ~/.agents/plugins/derm/hooks/hooks.json", "rm .config/goose/permission.yaml", "env GOOSE_MODE=auto true"]) {
      const r = await runPre(goose, stdin("shell", { command: cmd.replace("~/", "/home/u/") }), f.env());
      expect(r.exitCode, cmd).toBe(2);
    }
  });

  it("bad input denies", async () => {
    expect((await runPre(goose, "not json", f.env())).exitCode).toBe(2);
    expect((await runPre(goose, JSON.stringify({ event: "PreToolUse" }), f.env())).exitCode).toBe(2);
    expect((await runPre(goose, JSON.stringify({ event: "PostToolUse", tool_name: "shell" }), f.env())).exitCode).toBe(2);
  });

  it("records the decision under goose's call id and never echoes the input", async () => {
    const before = f.daemon.events().length;
    await runPre(goose, stdin("shell", { command: "ls secret-token-value" }, { tool_call_id: "call_rec" }), f.env());
    const ev = f.daemon.events().slice(before).at(-1) as { id: string; detail: Record<string, unknown> };
    expect(ev.id).toMatch(/^goose-call_rec-decision-[0-9a-f]{32}$/);
    expect(ev.detail.toolUseId).toBe("call_rec");
    expect(JSON.stringify(ev)).not.toContain("secret-token-value");
  });
});

// Lane X's request 7 (integration w5, continue): the gate posts an
// `install.call` record for an install, beside its decision.
describe("goose install records", () => {
  it("posts install.call beside the decision", async () => {
    const before = f.daemon.events().length;
    await runPre(goose, stdin("shell", { command: "npm install left-pad@1.3.0" }), f.env());
    const ev = f.daemon.events().slice(before);
    const recs = ev.filter((e) => e.kind === "install.call") as { detail: Record<string, unknown>; harness: string }[];
    expect(recs).toHaveLength(1);
    expect(recs[0]?.harness).toBe("goose");
    expect(recs[0]?.detail).toMatchObject({ manager: "npm", form: "add", packages: [{ name: "left-pad", version: "1.3.0", ecosystem: "npm" }], trust: "client" });
    const decision = (ev.find((e) => e.kind === "approval") as { detail: { decision: string } } | undefined)?.detail.decision;
    expect(recs[0]?.detail.decision).toBe(decision);
  });
});
