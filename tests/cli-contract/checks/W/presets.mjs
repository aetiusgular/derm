// Lane W (wave 5): derm setup's workspace-write preset (the default, and the
// policy derm's sbx kit copies into the VM) against the real Claude Code with
// the derm plugin (its hook runs the canonical core), the fake Messages server
// and a fake derm daemon.
//
//   w-preset-vm     the VM's shape: DERM_FULL_ACCESS=1, so every ask is a
//                   deny (case 83). Ordinary work runs (`echo`, `git init`);
//                   a push, a privileged container and `derm setup` are
//                   denied with derm's reason and never run.
//   w-preset-host   the host's shape: the push asks the daemon's approver
//                   (whose "no" denies it), `git status` runs, a privileged
//                   container is denied without a question.
//
//   node tests/cli-contract/run.mjs --claude <path> --only w-preset-vm,w-preset-host
//
// Both report `info` until integration applies request W-1 (command rules in
// the matchers): before it, the preset fails the matcher's schema, so every
// call asks (a deny under full access), ordinary work included. That is the
// state the check names; it never reports `pass` for it.

import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { startFakeMessages, textBlock, toolUse, lastUserText } from "../../lib/fakeMessages.mjs";
import { ClaudeSession } from "../../lib/claudeDriver.mjs";
import { makeTempDirs } from "../../lib/codexDriver.mjs";
import { startFakeDaemon } from "../../../../packages/derm-claude-plugin/src/testing/fakeDaemon.ts";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..", "..", "..", "..");
const PLUGIN = path.join(ROOT, "packages", "derm-claude-plugin");
const PRESET = path.join(ROOT, "crates", "derm-cli", "src", "setup", "presets", "workspace-write.json");

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

async function run(claudePath, env, plan, approve) {
  const daemon = await startFakeDaemon();
  const dirs = makeTempDirs("dermw-");
  const policy = path.join(dirs.root, "policy.json");
  writeFileSync(policy, JSON.stringify(JSON.parse(readFileSync(PRESET, "utf8")).policy), { mode: 0o600 });
  const used = {};
  const prompts = [];
  const fake = await startFakeMessages({ script: scripted(plan, used) });
  const s = new ClaudeSession({
    claudePath,
    dirs,
    baseUrl: fake.baseUrl,
    settings: { env: { ENABLE_TOOL_SEARCH: "false" } },
    args: ["--plugin-dir", PLUGIN],
    env: { DERM_POLICY: policy, ...daemon.env(), ...env },
    onControl: (req) => {
      prompts.push({ tool: req.request?.tool_name });
      return { behavior: "deny", message: "denied by the contract check" };
    },
  });
  const seen = {};
  try {
    daemon.setApprove(approve);
    for (const k of Object.keys(plan)) {
      await s.send(k);
      seen[k] = toolResult(fake, used[k]);
    }
    seen.approvals = daemon.approvals().map((a) => JSON.stringify(a));
  } catch (error) {
    seen.error = error.message;
  } finally {
    seen.stderr = s.stderr.slice(-400);
    await s.close();
    await fake.close();
    await daemon.close();
  }
  return { seen, prompts };
}

const text = (r) => r?.text ?? "";
const notApplied = (r) => /policy file invalid|unknown field command|no rule/i.test(text(r));

async function checkVm({ claudePath }) {
  const plan = {
    "w-echo": "echo quiet-ran",
    "w-push": "git push origin main",
    "w-priv": "docker run --privileged alpine true",
    "w-setup": "derm setup",
  };
  const { seen, prompts } = await run(claudePath, { DERM_FULL_ACCESS: "1" }, plan, "yes");
  if (!seen.error && notApplied(seen["w-echo"])) {
    return { status: "info", finding: `W-1 not applied: the preset fails the matcher, so every call is denied under full access (${text(seen["w-echo"]).slice(0, 160)})`, seen };
  }
  const checks = {
    echoRan: text(seen["w-echo"]).includes("quiet-ran"),
    pushDenied: text(seen["w-push"]).includes("rule bash git push") && text(seen["w-push"]).includes("full access"),
    privilegedDenied: text(seen["w-priv"]).includes("rule bash docker run --privileged"),
    setupDenied: text(seen["w-setup"]).includes("rule bash derm setup"),
    noApprover: (seen.approvals ?? []).length === 0,
    noPrompt: prompts.length === 0,
  };
  const pass = Object.values(checks).every(Boolean) && !seen.error;
  return {
    status: pass ? "pass" : "fail",
    finding: pass
      ? "Under the VM's full access with the workspace-write preset, echo ran; git push, docker run --privileged and derm setup were denied with derm's reason and never ran; no approver or prompt was asked."
      : `Checks: ${JSON.stringify(checks)}${seen.error ? `; error ${seen.error}` : ""}`,
    seen: { ...seen, prompts },
  };
}

async function checkHost({ claudePath }) {
  const plan = {
    "w-status": "git status --short",
    "w-push": "git push origin main",
    "w-priv": "docker run --privileged alpine true",
  };
  const { seen, prompts } = await run(claudePath, {}, plan, "no");
  if (!seen.error && notApplied(seen["w-status"])) {
    return { status: "info", finding: `W-1 not applied: the preset fails the matcher, so every call asks (${text(seen["w-status"]).slice(0, 160)})`, seen };
  }
  const approvals = (seen.approvals ?? []).join("\n");
  const checks = {
    statusRan: !!seen["w-status"] && !text(seen["w-status"]).includes("derm:"),
    pushAsked: approvals.includes("rule bash git push"),
    pushDidNotRun: !!seen["w-push"] && !/To |Everything up-to-date/.test(text(seen["w-push"])),
    privilegedDenied: text(seen["w-priv"]).includes("rule bash docker run --privileged"),
  };
  const pass = Object.values(checks).every(Boolean) && !seen.error;
  return {
    status: pass ? "pass" : "fail",
    finding: pass
      ? "On the host with the workspace-write preset, git status ran, git push asked the daemon's approver (whose no denied it), and docker run --privileged was denied with no question."
      : `Checks: ${JSON.stringify(checks)}${seen.error ? `; error ${seen.error}` : ""}`,
    seen: { ...seen, prompts },
  };
}

export const checks = [
  { id: "w-preset-vm", title: "derm setup's workspace-write preset under full access, the in-VM shape (lane W)", harness: "claude", flag: "lane W, case 83, O1", run: checkVm },
  { id: "w-preset-host", title: "derm setup's workspace-write preset on the host: a push asks, ordinary work runs (lane W)", harness: "claude", flag: "lane W, section 7", run: checkHost },
];
