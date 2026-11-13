// Sends derm-authored scenarios (source `derm`) to a hook as Claude Code's
// PreToolUse payloads, the way MoatBench does, and reads the reply as Claude Code
// does. MoatBench's scenarios are compiled into OpenMoat, so derm's own control
// paths (case 222) cannot go through `openmoat bench`.
//
// The payload is MoatBench 0.19.0's Claude Code payload, field for field, as
// recorded from `openmoat bench --hook ... --host claude-code --verbose`
// (tests/eval/fixtures/moatbench-claude-code-verbose.txt): cwd, hook_event_name,
// session_id, tool_input, tool_name, tool_use_id, turn_id; `~` is the throwaway
// home; the hook runs through `sh -c` with PATH, HOME and USERPROFILE only.
// The reply is read by Claude Code's documented hook contract
// (https://code.claude.com/docs/en/hooks, "PreToolUse decision control"): exit 2
// blocks; exit 0 with `hookSpecificOutput.permissionDecision` allow, deny or ask
// does that; exit 0 with no decision leaves the call to Claude Code's own
// permissions (defer); anything else is an error. tests/eval/eval.test.ts holds this
// reading to MoatBench's own on every payload of a recorded derm run.
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TOOL = { shell: "Bash", read: "Read", write: "Write", edit: "Edit", fetch: "WebFetch" };

export function payload(step, { home, project, session, i }) {
  const abs = (p) => (p.startsWith("~/") ? join(home, p.slice(2)) : p.startsWith("/") ? p : join(project, p));
  let tool_input;
  switch (step.kind) {
    case "shell": tool_input = { command: step.input.command }; break;
    case "read": tool_input = { file_path: abs(step.input.path) }; break;
    case "write": tool_input = { content: "written by the agent", file_path: abs(step.input.path) }; break;
    case "edit": tool_input = { file_path: abs(step.input.path), new_string: "written by the agent", old_string: "old" }; break;
    case "fetch": tool_input = { prompt: "summarise", url: step.input.url }; break;
    case "mcp": return {
      cwd: project, hook_event_name: "PreToolUse", session_id: session,
      tool_input: step.input.args ?? {}, tool_name: `mcp__${step.input.server}__${step.input.tool}`,
      tool_use_id: `${session}#${i}`, turn_id: "t-1",
    };
    default: throw new Error(`unknown step kind ${step.kind}`);
  }
  return { cwd: project, hook_event_name: "PreToolUse", session_id: session, tool_input, tool_name: TOOL[step.kind], tool_use_id: `${session}#${i}`, turn_id: "t-1" };
}

export function readClaudeCode(code, stdout) {
  if (code === 2) return "deny";
  if (code !== 0) return "error";
  const text = stdout.trim();
  if (text === "") return "defer";
  let doc;
  try { doc = JSON.parse(text); } catch { return "error"; }
  const d = doc?.hookSpecificOutput?.permissionDecision;
  if (d === "allow" || d === "deny" || d === "ask") return d;
  if (doc?.decision === "block") return "deny";
  return "defer";
}

export function probe(scenario, hook) {
  const root = mkdtempSync(join(tmpdir(), "derm-eval-probe-"));
  const home = join(root, "home");
  const project = join(home, "proj");
  mkdirSync(project, { recursive: true });
  const session = `${scenario.id}@claude-code`;
  const env = { PATH: process.env.PATH, HOME: home, USERPROFILE: home };
  try {
    return scenario.steps.map((step, i) => {
      const body = JSON.stringify(payload(step, { home, project, session, i }));
      const t0 = process.hrtime.bigint();
      const r = spawnSync("sh", ["-c", hook], { input: body, env, cwd: project, encoding: "utf8", timeout: 45_000 });
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      return { answer: r.error ? "error" : readClaudeCode(r.status, r.stdout ?? ""), msPerCall: Math.round(ms * 100) / 100 };
    });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}
