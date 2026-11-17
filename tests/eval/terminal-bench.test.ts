// Eval pass 1, E1-4c: the Terminal-Bench glue. The task runs need Docker and
// a local model (the box); what is held here is the part that is text and
// files: the bundle, the trust entries, the subset, the score, and the one
// line of Harbor's that the agent rewrites.
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { trustToml as checkTrust } from "../cli-contract/checks/dermCodex.mjs";
import { DATASET, SUBSET, buildBundle, readJob, summarize, trustToml } from "./lib/terminal-bench.mjs";

const REPO = path.resolve(__dirname, "..", "..");
const root = mkdtempSync(path.join(tmpdir(), "derm-tb-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

describe("terminal-bench bundle", () => {
  it("trusts the plugin's hooks the way the contract check does", () => {
    const hooks = JSON.parse(readFileSync(path.join(REPO, "packages", "derm-codex-plugin", "hooks", "hooks.json"), "utf8"));
    expect(trustToml(hooks)).toBe(checkTrust(hooks, "derm@derm"));
    expect(trustToml(hooks)).toContain('[hooks.state."derm@derm:hooks/hooks.json:pre_tool_use:0:0"]');
  });

  it("holds the binaries, a local marketplace, the trust entries and a policy that is a policy", () => {
    const bin = path.join(root, "fake-bin");
    writeFileSync(bin, "#!/bin/sh\n");
    const out = path.join(root, "bundle");
    buildBundle({ out, derm: bin, daemon: bin });
    for (const f of ["bin/derm", "bin/derm-daemon", "mkt/.agents/plugins/marketplace.json", "mkt/derm/.codex-plugin/plugin.json", "mkt/derm/hooks/hooks.json", "mkt/derm/hooks/derm-gate.sh", "trust.toml", "policy.json"]) {
      expect(existsSync(path.join(out, f)), f).toBe(true);
    }
    expect(statSync(path.join(out, "bin", "derm")).mode & 0o111).not.toBe(0);
    const policy = JSON.parse(readFileSync(path.join(out, "policy.json"), "utf8"));
    expect(policy.version).toBe(1);
    expect(policy.rules.length).toBeGreaterThan(10);
    expect(policy.$comment).toBeUndefined();
    expect(() => buildBundle({ out, derm: path.join(root, "missing"), daemon: bin })).toThrow(/no such file/);
  });

  it("names Terminal-Bench's own ten-task sample, not a hand-picked list", () => {
    expect(DATASET).toBe("terminal-bench-sample@2.0");
    expect(SUBSET).toHaveLength(10);
    expect(new Set(SUBSET).size).toBe(10);
  });
});

describe("terminal-bench score", () => {
  it("counts only trials that were scored, and names the rest", () => {
    const job = path.join(root, "job");
    const trial = (name: string, result: object, agent?: Record<string, string>) => {
      mkdirSync(path.join(job, name, "agent"), { recursive: true });
      writeFileSync(path.join(job, name, "result.json"), JSON.stringify(result));
      for (const [f, text] of Object.entries(agent ?? {})) writeFileSync(path.join(job, name, "agent", f), text);
    };
    const ev = (source: string, kind: string, detail = {}) => JSON.stringify({ source, kind, detail });
    trial(
      "a",
      { task_name: "regex-log", verifier_result: { rewards: { reward: 1 } }, agent_execution: { started_at: "2026-11-17T00:00:00Z", finished_at: "2026-11-17T00:01:00Z" } },
      {
        "derm-report.json": JSON.stringify({ events: 9, flags: 0, bySource: { otel: 4, adapter: 3 } }),
        "derm-events.jsonl": [ev("adapter", "approval", { decision: "allow" }), ev("adapter", "approval", { decision: "deny" }), ev("otel", "approval"), "not json"].join("\n"),
      },
    );
    trial("b", { task_name: "fix-git", verifier_result: { rewards: { reward: 0 } } }, { "derm-report.json": JSON.stringify({ events: 3, flags: 1, bySource: {} }), "derm-events.jsonl": "" });
    trial("c", { task_name: "qemu-startup", exception_info: { exception_type: "AgentTimeoutError" } });
    const s = summarize("job", readJob(job));
    expect(s).toMatchObject({ trials: 3, scored: 2, passed: 1, gateCalls: 2, denied: 1, flags: 1, otelRecords: 4, withDermRecord: 2, medianAgentSeconds: 60 });
    expect(s.notScored).toEqual(["qemu-startup: AgentTimeoutError"]);
    // Telemetry is required: a derm trial with none is named, never averaged away.
    expect(s.trialsWithNoOtel).toEqual(["fix-git"]);
  });
});

describe("the Harbor agent's rewrite of Harbor's exec line", () => {
  const py = spawnSync("python3", ["--version"]).status === 0;
  const wrap = (arm: string, command: string) =>
    execFileSync(
      "python3",
      [
        "-c",
        [
          "import sys,types",
          `sys.path.insert(0, ${JSON.stringify(path.join(REPO, "tests", "eval", "harbor"))})`,
          "mods=['harbor','harbor.agents','harbor.agents.installed','harbor.agents.installed.codex','harbor.environments','harbor.environments.base']",
          "[sys.modules.__setitem__(n, types.ModuleType(n)) for n in mods]",
          "sys.modules['harbor.agents.installed.codex'].Codex=object",
          "sys.modules['harbor.agents.installed.codex'].CodexOptions=object",
          "sys.modules['harbor.environments.base'].BaseEnvironment=object",
          "import derm_codex",
          "sys.stdout.write(derm_codex.wrap_exec(sys.argv[2], sys.argv[1], '/logs/agent'))",
        ].join("\n"),
        arm,
        command,
      ],
      { encoding: "utf8" },
    );
  // Harbor 0.25.0, agents/installed/codex.py:2069-2083.
  const harbor = "if [ -s ~/.nvm/nvm.sh ]; then . ~/.nvm/nvm.sh; fi; CODEX_API_KEY= codex exec --dangerously-bypass-approvals-and-sandbox --skip-git-repo-check --model m --json --enable unified_exec -- 'do it' 2>&1 </dev/null | tee /logs/agent/codex.txt";

  it.skipIf(!py)("starts Codex through derm run, with the record read out after", () => {
    const gate = wrap("gate", harbor);
    expect(gate).toContain(`CODEX_API_KEY= derm run codex --boundary none --chat "$DERM_TB_CHAT" --no-tap -- exec --dangerously-bypass-approvals-and-sandbox`);
    expect(gate).not.toContain("codex exec ");
    expect(gate.indexOf("codex plugin add derm@derm")).toBeLessThan(gate.indexOf("derm run codex"));
    expect(gate.indexOf("derm-daemon --foreground")).toBeLessThan(gate.indexOf("derm run codex"));
    expect(gate.indexOf("derm-report.json")).toBeGreaterThan(gate.indexOf("derm run codex"));
    expect(gate.trimEnd().endsWith("exit $derm_rc")).toBe(true);
    expect(wrap("standard", harbor)).toContain("--no-tap --tier standard -- exec ");
  });

  it.skipIf(!py)("leaves the control arm and every other command alone", () => {
    expect(wrap("off", harbor)).toBe(harbor);
    expect(wrap("gate", "mkdir -p /x && codex --version")).toBe("mkdir -p /x && codex --version");
  });
});
