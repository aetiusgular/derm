// Lane X (wave 5): package installs at the gate, against the real Claude
// Code with the derm plugin (its hook runs the canonical core, so lane X's
// installs/ folder is what it runs), the fake Messages server and a fake derm
// daemon. Policy `bash: allow`, so only lane X's step turns a call into an ask.
//
//   x-claude-installs   an allowed `npm install <made-up name>` and `pnpm dlx`
//                       ask (the daemon's approver is asked; "no" denies, and
//                       npm never runs); `echo` and `npm test` still run; the
//                       ask's card names the package (rules cases 130, 131)
//   x-claude-full-access the same install under DERM_FULL_ACCESS=1 is denied,
//                       the reason reaching the model (case 83)
//
//   node tests/cli-contract/run.mjs --claude <path> --only x-claude-installs,x-claude-full-access
//
// Codex, Gemini CLI and the other hook packages run a synced copy of the core
// (`sync-core.mjs`), which this lane does not edit: their checks run at the
// phase merge, after the sync (plans/parallel/tk_lane_X.md, Requests).

import { writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { startFakeMessages, textBlock, toolUse, lastUserText } from "../../lib/fakeMessages.mjs";
import { ClaudeSession } from "../../lib/claudeDriver.mjs";
import { makeTempDirs } from "../../lib/codexDriver.mjs";
import { startFakeDaemon } from "../../../../packages/derm-claude-plugin/src/testing/fakeDaemon.ts";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PLUGIN = path.resolve(HERE, "..", "..", "..", "..", "packages", "derm-claude-plugin");
const MADE_UP = "derm-made-up-name-x7q2z9";

function toolResult(fake, id) {
  for (const r of [...fake.requests].reverse()) {
    for (const m of r.body?.messages ?? []) {
      for (const c of Array.isArray(m.content) ? m.content : []) {
        if (c?.type === "tool_result" && c.tool_use_id === id) {
          return { text: typeof c.content === "string" ? c.content : JSON.stringify(c.content), isError: c.is_error === true };
        }
      }
    }
  }
  return null;
}

function scripted(plan, used) {
  return (body) => {
    const last = (body?.messages ?? []).at(-1);
    if (last?.role === "user" && Array.isArray(last.content) && last.content.some((c) => c?.type === "tool_result")) return [textBlock("done")];
    const said = lastUserText(body);
    const p = Object.keys(plan).find((k) => new RegExp(`(^|\\s)${k}(\\s|$)`).test(said));
    if (!p) return [textBlock("ok")];
    const block = toolUse("Bash", { command: plan[p], description: p });
    used[p] = block.id;
    return [block];
  };
}

async function session({ claudePath, env, plan, used, prompts }) {
  const dirs = makeTempDirs("dermx-");
  const policy = path.join(dirs.root, "policy.json");
  writeFileSync(policy, JSON.stringify({ version: 1, askTimeoutSeconds: 5, servers: [], rules: [{ tool: "bash", action: "allow" }] }));
  writeFileSync(path.join(dirs.work, "package.json"), JSON.stringify({ name: "x", version: "1.0.0", scripts: { test: "echo test-ran" } }));
  const fake = await startFakeMessages({ script: scripted(plan, used) });
  const s = new ClaudeSession({
    claudePath,
    dirs,
    baseUrl: fake.baseUrl,
    settings: { env: { ENABLE_TOOL_SEARCH: "false" } },
    args: ["--plugin-dir", PLUGIN],
    env: { DERM_POLICY: policy, ...env },
    onControl: (req) => {
      prompts.push({ tool: req.request?.tool_name, request: JSON.stringify(req.request ?? {}) });
      return { behavior: "deny", message: "denied by the contract check" };
    },
  });
  return { s, fake, dirs };
}

async function checkInstalls({ claudePath }) {
  const daemon = await startFakeDaemon();
  const used = {};
  const prompts = [];
  const plan = {
    "x-install": `npm install ${MADE_UP}`,
    "x-dlx": "pnpm dlx cowsay hi",
    "x-echo": "echo plain-ran",
    "x-test": "npm test",
  };
  const { s, fake } = await session({ claudePath, env: daemon.env(), plan, used, prompts });
  const seen = {};
  try {
    daemon.setApprove("no");
    await s.send("x-install");
    seen.install = toolResult(fake, used["x-install"]);
    await s.send("x-dlx");
    seen.dlx = toolResult(fake, used["x-dlx"]);
    seen.approvals = daemon.approvals().map((a) => ({ tool: a.tool, harness: a.harness, text: JSON.stringify(a) }));
    await s.send("x-echo");
    seen.echo = toolResult(fake, used["x-echo"]);
    await s.send("x-test");
    seen.test = toolResult(fake, used["x-test"]);
  } catch (error) {
    seen.error = error.message;
  } finally {
    seen.stderr = s.stderr.slice(-400);
    await s.close();
    await fake.close();
    await daemon.close();
  }
  const approvalText = (seen.approvals ?? []).map((a) => a.text).join("\n");
  const checks = {
    installAskedTheApprover: (seen.approvals ?? []).filter((a) => a.tool === "bash" && a.harness === "claude-code").length >= 2,
    installCardNamesThePackage: approvalText.includes(MADE_UP) || approvalText.includes("package install"),
    installDidNotRun: !!seen.install && !/added \d+ package|npm error|ERR!/i.test(seen.install.text),
    dlxDidNotRun: !!seen.dlx && !seen.dlx.text.includes("hi\n"),
    echoRan: !!seen.echo && seen.echo.text.includes("plain-ran"),
    npmTestRan: !!seen.test && seen.test.text.includes("test-ran"),
  };
  const pass = Object.values(checks).every(Boolean) && !seen.error;
  return {
    status: pass ? "pass" : "fail",
    finding: pass
      ? "An allowed npm install of a made-up name and a pnpm dlx each asked the daemon's approver, whose no denied them before npm ran; echo and npm test ran under the same bash allow."
      : `Checks: ${JSON.stringify(checks)}${seen.error ? `; error ${seen.error}` : ""}`,
    seen: { ...seen, prompts },
  };
}

async function checkFullAccess({ claudePath }) {
  const daemon = await startFakeDaemon();
  const used = {};
  const prompts = [];
  const { s, fake } = await session({ claudePath, env: { ...daemon.env(), DERM_FULL_ACCESS: "1" }, plan: { "x-install": `npm install ${MADE_UP}` }, used, prompts });
  const seen = {};
  try {
    daemon.setApprove("yes");
    await s.send("x-install");
    seen.install = toolResult(fake, used["x-install"]);
    seen.approvals = daemon.approvals().length;
  } catch (error) {
    seen.error = error.message;
  } finally {
    seen.stderr = s.stderr.slice(-400);
    await s.close();
    await fake.close();
    await daemon.close();
  }
  const text = seen.install?.text ?? "";
  const checks = {
    denied: text.includes("package install") && text.includes(MADE_UP),
    saysFullAccess: text.includes("full access"),
    noApproverAsked: seen.approvals === 0,
    noPrompt: prompts.length === 0,
  };
  const pass = Object.values(checks).every(Boolean) && !seen.error;
  return {
    status: pass ? "pass" : "fail",
    finding: pass ? "Under DERM_FULL_ACCESS=1 the install's ask became a deny whose reason, naming the package, reached the model; no approver or prompt was asked." : `Checks: ${JSON.stringify(checks)}${seen.error ? `; error ${seen.error}` : ""}; result ${text.slice(0, 300)}`,
    seen: { ...seen, prompts },
  };
}

export const checks = [
  { id: "x-claude-installs", title: "derm Claude Code plugin: an allowed install asks, other bash runs (lane X)", harness: "claude", flag: "lane X, cases 130 and 131", run: checkInstalls },
  { id: "x-claude-full-access", title: "derm Claude Code plugin: an install under full access is denied (lane X)", harness: "claude", flag: "lane X, case 83", run: checkFullAccess },
];
