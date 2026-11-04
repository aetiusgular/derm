// Lane L: contract checks for derm's gate in Grok Build (T2.5), against the
// real CLI (npm @xai-official/grok) with a custom model in ~/.grok/config.toml
// (`[model.fake]`, api_backend chat_completions; the binary's bundled
// 11-custom-models.md) pointed at the fake OpenAI chat-completions server, a
// dummy XAI_API_KEY, `grok -p -m fake`, and a fake derm daemon. `--yolo` is
// Grok's bypassPermissions (its permissionMode in the hook input), the closest
// to Orca's full access; without it a headless run cannot approve a shell call
// and skips it ("permission required ... a headless run cannot ask").
//
//   node tests/cli-contract/run.mjs --cli grok=/tmp/cli/grok/node_modules/.bin/grok

import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { startFakeChat, toolResults } from "../../lib/fakeChat.mjs";
import { ALLOW, ASK, DENY, brief, hookCommand, oneRun } from "./_lib.mjs";

const gateGroup = (handler = {}) => ({ matcher: "*", hooks: [{ type: "command", command: hookCommand("grok"), timeout: 120, failClosed: true, ...handler }] });
const COMPAT_OFF = "[compat.claude]\nhooks = false\n\n[compat.cursor]\nhooks = false\n\n";

/** True when `v` (as run.mjs read it) is at least 1.0.71, where failClosed exists. */
function hasFailClosed(v) {
  const m = /(\d+)\.(\d+)\.(\d+)/.exec(String(v ?? ""));
  if (!m) return false;
  const [a, b, c] = m.slice(1).map(Number);
  return a > 1 || (a === 1 && (b > 0 || c >= 71));
}

async function turn(bin, { policy, command, approve, yolo = true, groups, compat = COMPAT_OFF, claudeSettings }) {
  const fake = await startFakeChat({ script: (_b, n) => (n === 0 ? { tool: "run_terminal_command", args: { command, description: "step" } } : { text: "done" }) });
  try {
    return await oneRun({
      prefix: "gk-derm",
      policy,
      approve,
      collect: () => toolResults(fake),
      setup: ({ home }) => {
        mkdirSync(path.join(home, ".grok", "hooks"), { recursive: true });
        writeFileSync(path.join(home, ".grok", "hooks", "derm.json"), JSON.stringify({ hooks: { PreToolUse: groups ?? [gateGroup()] } }));
        writeFileSync(path.join(home, ".grok", "config.toml"), `${compat}[model.fake]\nmodel = "fake-model"\nbase_url = "${fake.baseUrl}"\napi_key = "sk-fake"\napi_backend = "chat_completions"\n`);
        if (claudeSettings) {
          mkdirSync(path.join(home, ".claude"), { recursive: true });
          writeFileSync(path.join(home, ".claude", "settings.json"), JSON.stringify(claudeSettings));
        }
        return { bin, args: ["-p", "run the step", "-m", "fake", ...(yolo ? ["--yolo"] : [])], env: { PATH: process.env.PATH, XAI_API_KEY: "xai-fake" } };
      },
    });
  } finally {
    await fake.close();
  }
}

export const checks = [
  {
    id: "grok-derm-allow",
    title: "Under --yolo an allowed shell call runs, recorded as bash (run_terminal_command mapped, case 82); without --yolo derm's allow does not approve it (Grok: allow means not blocked)",
    harness: "grok",
    async run({ binPath }) {
      const a = await turn(binPath, { policy: ALLOW, command: "echo gk-allowed > ran.txt" });
      const b = await turn(binPath, { policy: ALLOW, yolo: false, command: "echo gk-not-approved > ran.txt" });
      const rec = a.events.find((e) => e.kind === "approval" && e.harness === "grok");
      const ok = a.ran.includes("gk-allowed") && rec?.detail?.tool === "bash" && !b.ran;
      return { status: ok ? "pass" : "fail", finding: `yolo: ${brief(a)}; record tool ${rec?.detail?.tool} | default: ${brief(b)}` };
    },
  },
  {
    id: "grok-derm-deny",
    title: "Under --yolo (bypassPermissions, case 83) a denied shell call does not run and the model reads derm's reason",
    harness: "grok",
    async run({ binPath }) {
      const t = await turn(binPath, { policy: DENY, command: "echo gk-denied > ran.txt" });
      const reason = t.results.some((x) => x.includes("derm: rule bash"));
      return { status: !t.ran && reason ? "pass" : "fail", finding: brief(t) };
    },
  },
  {
    id: "grok-derm-reject",
    title: "The reject list blocks a write of an endpoint key under an allow rule",
    harness: "grok",
    async run({ binPath }) {
      const t = await turn(binPath, { policy: ALLOW, command: "echo export ANTHROPIC_BASE_URL=http://x > ran.txt" });
      const reason = t.results.some((x) => x.includes("reject list: anthropic_base_url"));
      return { status: !t.ran && reason ? "pass" : "fail", finding: brief(t) };
    },
  },
  {
    id: "grok-derm-ask",
    title: "Under --yolo an ask never goes to Grok's prompt (which bypassPermissions approves): the approver's yes runs it, a no or no approver denies it",
    harness: "grok",
    async run({ binPath }) {
      const yes = await turn(binPath, { policy: ASK, approve: "yes", command: "echo gk-approved > ran.txt" });
      const no = await turn(binPath, { policy: ASK, approve: "no", command: "echo gk-declined > ran.txt" });
      const none = await turn(binPath, { policy: ASK, approve: "none", command: "echo gk-unanswered > ran.txt" });
      const ok = yes.ran.includes("gk-approved") && !no.ran && !none.ran && none.results.some((x) => x.includes("ask needs an approver"));
      return { status: ok ? "pass" : "fail", finding: `yes: ${brief(yes)} | no: ${brief(no)} | none: ${brief(none)}` };
    },
  },
  {
    id: "grok-derm-compat-once",
    title: "With Grok's compat imports off, a derm gate in Claude Code's settings does not run a second time (case 75); with them on it does (recorded)",
    harness: "grok",
    async run({ binPath }) {
      const claudeSettings = { hooks: { PreToolUse: [{ matcher: "*", hooks: [{ type: "command", command: hookCommand("grok"), timeout: 120 }] }] } };
      const off = await turn(binPath, { policy: DENY, claudeSettings, command: "echo gk-compat > ran.txt" });
      const on = await turn(binPath, { policy: DENY, claudeSettings, compat: "", command: "echo gk-compat-on > ran.txt" });
      const n = (t) => t.events.filter((e) => e.kind === "approval").length;
      // Recorded, not required: whether Grok imports Claude Code's hook file
      // at all in this run (its compat import may need more than the file).
      const ok = !off.ran && n(off) === 1;
      return { status: ok ? "pass" : "fail", finding: `compat off: ${brief(off)}; derm decisions ${n(off)} | compat on: derm decisions ${n(on)} (2 means the gate ran twice)` };
    },
  },
  {
    id: "grok-derm-beside-orca",
    title: "Beside another PreToolUse hook (Orca's status hook, case 75), a deny still wins and derm's gate runs once",
    harness: "grok",
    async run({ binPath }) {
      const groups = [{ matcher: "*", hooks: [{ type: "command", command: "true", timeout: 10 }] }, gateGroup()];
      const t = await turn(binPath, { policy: DENY, groups, command: "echo gk-beside > ran.txt" });
      const decisions = t.events.filter((e) => e.kind === "approval").length;
      return { status: !t.ran && decisions === 1 ? "pass" : "fail", finding: `${brief(t)}; derm decisions ${decisions}` };
    },
  },
  {
    id: "grok-derm-killed",
    title: "A gate killed mid-call (case 70): with failClosed (1.0.71 and later) the call is denied; on 1.0.70 it runs",
    harness: "grok",
    async run({ binPath, version }) {
      // Grok rewrites `$$` in a hook's command line, so the hook kills itself from a script.
      const script = path.join(mkdtempSync(path.join(process.env.CLI_CONTRACT_TMP ?? tmpdir(), "gk-kill-")), "killself.sh");
      writeFileSync(script, "#!/bin/sh\nkill -9 $$\n", { mode: 0o700 });
      const groups = [gateGroup({ command: script, timeout: 10 })];
      const t = await turn(binPath, { policy: DENY, groups, command: "echo gk-killed-ran > ran.txt" });
      const closed = hasFailClosed(version);
      const ok = closed ? !t.ran : Boolean(t.ran);
      return { status: closed ? (ok ? "pass" : "fail") : "info", finding: `version ${version}; failClosed ${closed}; the call ran: ${Boolean(t.ran)}. ${brief(t)}` };
    },
  },
];
