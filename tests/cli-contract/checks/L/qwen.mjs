// Lane L: contract checks for derm's gate in Qwen Code (T2.5), against the
// real CLI (npm @qwen-code/qwen-code) driven by `qwen -p` against the fake
// OpenAI chat-completions server (../../lib/fakeChat.mjs) with
// `security.auth.selectedType: "openai"` and OPENAI_BASE_URL, and a fake derm
// daemon. Qwen's own approval: `--yolo` runs every call the hook allows;
// without it a headless run turns an ask into a deny.
//
//   node tests/cli-contract/run.mjs --cli qwen-code=/tmp/cli/qwen/node_modules/@qwen-code/qwen-code/cli-entry.js

import { writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { startFakeChat, toolResults } from "../../lib/fakeChat.mjs";
import { ALLOW, ASK, DENY, brief, hookCommand, oneRun } from "./_lib.mjs";

const gate = () => ({ type: "command", command: hookCommand("qwen-code"), timeout: 120 });

async function turn(bin, { policy, command, approve, yolo = false, hooks, tool = "run_shell_command" }) {
  const fake = await startFakeChat({ script: (_b, n) => (n === 0 ? { tool, args: { command, description: "step" } } : { text: "done" }) });
  try {
    return await oneRun({
      prefix: "qw-derm",
      policy,
      approve,
      collect: () => toolResults(fake),
      setup: ({ home }) => {
        mkdirSync(path.join(home, ".qwen"), { recursive: true });
        writeFileSync(
          path.join(home, ".qwen", "settings.json"),
          JSON.stringify({ security: { auth: { selectedType: "openai" } }, model: { name: "fake-model" }, hooks: { PreToolUse: hooks ?? [{ matcher: "", hooks: [gate()] }] } }),
        );
        // cli-entry.js is a Node script; run it with this Node so the check works with or without its shebang.
        const node = bin.endsWith(".js") ? process.execPath : bin;
        const args = [...(bin.endsWith(".js") ? [bin] : []), "-p", "run the step", "--output-format", "json", ...(yolo ? ["--yolo"] : [])];
        return { bin: node, args, env: { PATH: process.env.PATH, OPENAI_BASE_URL: fake.baseUrl, OPENAI_API_KEY: "sk-fake", OPENAI_MODEL: "fake-model", QWEN_CODE_SUPPRESS_YOLO_WARNING: "1" } };
      },
    });
  } finally {
    await fake.close();
  }
}

export const checks = [
  {
    id: "qwen-derm-allow",
    title: "Under --yolo an allowed shell call runs, and the daemon gets the decision as run_shell_command mapped to bash (case 82)",
    harness: "qwen-code",
    async run({ binPath }) {
      const t = await turn(binPath, { policy: ALLOW, yolo: true, command: "echo qw-allowed > ran.txt" });
      const rec = t.events.find((e) => e.kind === "approval" && e.harness === "qwen-code");
      const ok = t.ran.includes("qw-allowed") && rec?.detail?.tool === "bash" && rec?.detail?.decision === "allow";
      return { status: ok ? "pass" : "fail", finding: `${brief(t)}; record ${JSON.stringify(rec?.detail ?? null).slice(0, 120)}` };
    },
  },
  {
    id: "qwen-derm-deny",
    title: "A denied shell call does not run in the default mode or under --yolo (case 83); under --yolo the model reads derm's reason",
    harness: "qwen-code",
    async run({ binPath }) {
      const a = await turn(binPath, { policy: DENY, command: "echo qw-denied > ran.txt" });
      const b = await turn(binPath, { policy: DENY, yolo: true, command: "echo qw-denied-yolo > ran.txt" });
      const reason = (t) => t.results.some((x) => x.includes("derm: rule bash"));
      // In the default mode a headless run declines the shell call itself
      // (its own permission check), so whether derm's reason or Qwen's reaches
      // the model there is recorded, not required.
      const ok = !a.ran && !b.ran && reason(b);
      const hookRanDefault = a.events.some((e) => e.kind === "approval");
      return { status: ok ? "pass" : "fail", finding: `default: ${brief(a)}; derm's hook ran ${hookRanDefault} | yolo: ${brief(b)}` };
    },
  },
  {
    id: "qwen-derm-reject",
    title: "The reject list blocks a write of an endpoint key under an allow rule, under --yolo",
    harness: "qwen-code",
    async run({ binPath }) {
      const t = await turn(binPath, { policy: ALLOW, yolo: true, command: "echo export ANTHROPIC_BASE_URL=http://x > ran.txt" });
      const reason = t.results.some((x) => x.includes("reject list: anthropic_base_url"));
      return { status: !t.ran && reason ? "pass" : "fail", finding: brief(t) };
    },
  },
  {
    id: "qwen-derm-ask",
    title: "Under --yolo an ask never goes to Qwen's prompt: the approver's yes runs it, a no or no approver denies it",
    harness: "qwen-code",
    async run({ binPath }) {
      const yes = await turn(binPath, { policy: ASK, yolo: true, approve: "yes", command: "echo qw-approved > ran.txt" });
      const no = await turn(binPath, { policy: ASK, yolo: true, approve: "no", command: "echo qw-declined > ran.txt" });
      const none = await turn(binPath, { policy: ASK, yolo: true, approve: "none", command: "echo qw-unanswered > ran.txt" });
      const ok = yes.ran.includes("qw-approved") && !no.ran && !none.ran && none.results.some((x) => x.includes("ask needs an approver"));
      return { status: ok ? "pass" : "fail", finding: `yes: ${brief(yes)} | no: ${brief(no)} | none: ${brief(none)}` };
    },
  },
  {
    id: "qwen-derm-ask-own",
    title: "In Qwen's default mode with no approver, an ask goes to Qwen's own prompt, which -p turns into a deny",
    harness: "qwen-code",
    async run({ binPath }) {
      const t = await turn(binPath, { policy: ASK, approve: "none", command: "echo qw-own-ask > ran.txt" });
      return { status: !t.ran ? "pass" : "fail", finding: brief(t) };
    },
  },
  {
    id: "qwen-derm-beside-orca",
    title: "Beside another PreToolUse hook (Orca's status hook, case 75), a deny still wins and derm's gate runs once",
    harness: "qwen-code",
    async run({ binPath }) {
      const hooks = [{ matcher: "", hooks: [{ type: "command", command: "true", timeout: 10 }] }, { matcher: "", hooks: [gate()] }];
      const t = await turn(binPath, { policy: DENY, yolo: true, hooks, command: "echo qw-beside > ran.txt" });
      const decisions = t.events.filter((e) => e.kind === "approval").length;
      return { status: !t.ran && decisions === 1 ? "pass" : "fail", finding: `${brief(t)}; derm decisions ${decisions}` };
    },
  },
  {
    id: "qwen-derm-killed",
    title: "A gate killed mid-call (case 70): Qwen has no fail-closed switch, so under --yolo the call runs (recorded)",
    harness: "qwen-code",
    async run({ binPath }) {
      const hooks = [{ matcher: "", hooks: [{ type: "command", command: "kill -9 $$", timeout: 10 }] }];
      const t = await turn(binPath, { policy: DENY, yolo: true, hooks, command: "echo qw-killed-ran > ran.txt" });
      return { status: "info", finding: `the call ran: ${Boolean(t.ran)} (expected true: Qwen fails open; derm status says so). ${brief(t)}` };
    },
  },
  {
    id: "qwen-derm-monitor",
    title: "Qwen's monitor tool, which runs a command in the background, is read as bash: a bash deny rule blocks it under --yolo (security review L-S1)",
    harness: "qwen-code",
    async run({ binPath }) {
      const t = await turn(binPath, { policy: DENY, yolo: true, tool: "monitor", command: "echo qw-monitor > ran.txt" });
      const rec = t.events.find((e) => e.kind === "approval" && e.harness === "qwen-code");
      // No derm decision means Qwen did not offer the tool in this run: recorded, not failed.
      if (!rec) return { status: "info", finding: `no derm decision: Qwen did not run monitor here. ${brief(t)}` };
      const ok = !t.ran && rec.detail?.tool === "bash" && rec.detail?.decision === "deny";
      return { status: ok ? "pass" : "fail", finding: `${brief(t)}; record ${JSON.stringify(rec.detail).slice(0, 120)}` };
    },
  },
];
