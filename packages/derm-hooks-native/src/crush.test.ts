import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { crush } from "./dialects/crush.ts";
import { runPre } from "./runner.ts";
import { CASE_30, fixture, type Fixture } from "./testing.ts";

const FIX = new URL("../../../contracts/fixtures/hook-dialects/crush/", import.meta.url);

let f: Fixture;
let work: string;
beforeAll(async () => {
  f = await fixture();
  // HOME is the fixture folder: Crush's global config there names exa and github.
  mkdirSync(path.join(f.dir, ".config", "crush"), { recursive: true });
  writeFileSync(path.join(f.dir, ".config", "crush", "crush.json"), JSON.stringify({ mcp: { exa: {}, github: {}, "my-server": {} } }));
  work = path.join(f.dir, "work");
  mkdirSync(path.join(work, ".git"), { recursive: true });
});
afterAll(async () => {
  await f.close();
});

const stdin = (tool: string, toolInput: unknown, extra: Record<string, unknown> = {}) =>
  JSON.stringify({ event: "PreToolUse", session_id: "c-1", cwd: work, tool_name: tool, tool_input: toolInput, ...extra });

describe("Crush PreToolUse", () => {
  it("allow pre-approves with Crush's envelope, only for a rule's allow (case 72)", async () => {
    const r = await runPre(crush, stdin("bash", { command: "ls -la" }), f.env());
    expect(r.exitCode).toBe(0);
    expect(JSON.parse(r.stdout)).toEqual({ version: 1, decision: "allow", reason: "derm: rule bash" });
  });

  it("the documented example's rm -rf / is allowed by an allow-bash rule; the policy, not the dialect, decides", async () => {
    const r = await runPre(crush, readFileSync(new URL("stdin.pre-tool.json", FIX), "utf8"), f.env());
    expect(r.exitCode).toBe(0);
  });

  it("deny is exit 2 with the reason on stderr and nothing on stdout (never exit 49 or halt, case 79)", async () => {
    const r = await runPre(crush, stdin("mcp_my-server_write", { a: 1 }), f.env());
    expect(r).toEqual({ stdout: "", stderr: "derm: rule my_server/*\n", exitCode: 2 });
  });

  it("an ask goes to the approver or denies; never Crush's no-opinion (cases 71, 72)", async () => {
    let r = await runPre(crush, readFileSync(new URL("stdin.pre-tool.mcp.json", FIX), "utf8").replace('"cwd"', '"cwd_unused"'), f.env());
    expect(r.exitCode).toBe(2);
    f.daemon.setApprove("yes");
    r = await runPre(crush, stdin("mcp_github_create_pull_request", { title: "x" }), f.env());
    expect(JSON.parse(r.stdout).decision).toBe("allow");
    f.daemon.setApprove("timeout");
    r = await runPre(crush, stdin("mcp_github_create_pull_request", { title: "x" }), f.env());
    expect(r.exitCode).toBe(2);
    f.daemon.setApprove("none");
  });

  it("a single-underscore name splits at the configured server (W2-R1)", async () => {
    expect((await runPre(crush, stdin("mcp_exa_web_search_exa", { q: "x" }), f.env())).exitCode).toBe(0);
    // Crush is configured with exa alone, so this is exa's tool `evil_t`.
    expect((await runPre(crush, stdin("mcp_exa_evil_t", {}), f.env())).exitCode).toBe(0);
    // No configured server fits: asks, and with no approver, denies.
    const r = await runPre(crush, stdin("mcp_zz_a_b", {}), f.env());
    expect(r.exitCode).toBe(2);
    expect(r.stderr).toMatch(/ask needs an approver/);
  });

  it("a project file that adds exa_evil makes the split ambiguous, not exa's", async () => {
    writeFileSync(path.join(work, ".crush.json"), JSON.stringify({ mcp: { exa_evil: {} } }));
    const r = await runPre(crush, stdin("mcp_exa_evil_t", {}), f.env());
    expect(r.stderr).toMatch(/more than one/);
    writeFileSync(path.join(work, ".crush.json"), "{}");
  });

  it("a redacted MCP input goes back as updated_input on an allow", async () => {
    const r = await runPre(crush, stdin("mcp_exa_search", { q: "x", api_key: "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789" }), f.env());
    const out = JSON.parse(r.stdout);
    expect(out.decision).toBe("allow");
    expect(JSON.stringify(out.updated_input)).toContain("[redacted by derm]");
    expect(JSON.stringify(out)).not.toContain("abcdefghijklmnop");
  });

  it("bash runs case 30's checks", async () => {
    for (const cmd of CASE_30) expect((await runPre(crush, stdin("bash", { command: cmd }), f.env())).exitCode, cmd).toBe(2);
  });

  it("a Crush control file in an allowed command asks", async () => {
    for (const cmd of ["cat .crush.json", "echo x >> /home/u/.config/crush/crushrc", "CRUSH_GLOBAL_CONFIG=/tmp/x crush"]) {
      expect((await runPre(crush, stdin("bash", { command: cmd }), f.env())).exitCode, cmd).toBe(2);
    }
  });

  it("bad input denies", async () => {
    expect((await runPre(crush, "[]", f.env())).exitCode).toBe(2);
    expect((await runPre(crush, JSON.stringify({ event: "Stop", tool_name: "bash" }), f.env())).exitCode).toBe(2);
  });
});
