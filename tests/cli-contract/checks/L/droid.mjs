// Lane L: contract checks for derm's gate in Droid (T2.5), against the real
// binary (npm @factory/cli-linux-x64) in airgap mode (FACTORY_AIRGAP_ENABLED=1,
// which skips Factory's sign-in and allows only BYOK models; 1.3.0 binary
// strings, dR()) with a `customModels` entry of provider
// generic-chat-completion-api pointed at the fake OpenAI chat-completions
// server, `droid exec --model custom:fake-model`, and a fake derm daemon.
// Droid's Execute tool needs `riskLevel` in its input.
//
//   node tests/cli-contract/run.mjs --cli droid=/tmp/cli/droid/node_modules/@factory/cli-linux-x64/bin/droid

import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { startFakeChat, toolResults } from "../../lib/fakeChat.mjs";
import { ALLOW, ASK, DENY, brief, hookCommand, oneRun } from "./_lib.mjs";

const gateGroup = (command = hookCommand("droid")) => ({ matcher: "*", hooks: [{ type: "command", command, timeout: 120 }] });

async function turn(bin, { policy, command, approve, auto = ["--auto", "high"], groups, hooksJson }) {
  const fake = await startFakeChat({ script: (_b, n) => (n === 0 ? { tool: "Execute", args: { command, riskLevel: "low", riskLevelReason: "a test step" } } : { text: "done" }) });
  try {
    return await oneRun({
      prefix: "dr-derm",
      policy,
      approve,
      collect: () => toolResults(fake),
      setup: ({ home }) => {
        mkdirSync(path.join(home, ".factory"), { recursive: true });
        writeFileSync(
          path.join(home, ".factory", "settings.json"),
          JSON.stringify({
            customModels: [{ model: "fake-model", displayName: "fake", provider: "generic-chat-completion-api", baseUrl: fake.baseUrl, apiKey: "sk-fake" }],
            hooks: { PreToolUse: groups ?? [gateGroup()] },
          }),
        );
        if (hooksJson) writeFileSync(path.join(home, ".factory", "hooks.json"), JSON.stringify(hooksJson));
        return { bin, args: ["exec", ...auto, "--model", "custom:fake-model", "run the step"], env: { PATH: process.env.PATH, FACTORY_AIRGAP_ENABLED: "1" } };
      },
    });
  } finally {
    await fake.close();
  }
}

export const checks = [
  {
    id: "droid-derm-allow",
    title: "An allowed Execute call runs, recorded as bash (Execute mapped, case 82)",
    harness: "droid",
    async run({ binPath }) {
      const t = await turn(binPath, { policy: ALLOW, command: "echo dr-allowed > ran.txt" });
      const rec = t.events.find((e) => e.kind === "approval" && e.harness === "droid");
      const ok = t.ran.includes("dr-allowed") && rec?.detail?.tool === "bash";
      return { status: ok ? "pass" : "fail", finding: `${brief(t)}; record tool ${rec?.detail?.tool}${ok ? "" : `; ${t.err.slice(-300)}`}` };
    },
  },
  {
    id: "droid-derm-deny",
    title: "A denied Execute call does not run, under --skip-permissions-unsafe too (case 83), and the model reads derm's reason",
    harness: "droid",
    async run({ binPath }) {
      const a = await turn(binPath, { policy: DENY, command: "echo dr-denied > ran.txt" });
      const b = await turn(binPath, { policy: DENY, auto: ["--skip-permissions-unsafe"], command: "echo dr-denied-skip > ran.txt" });
      const reason = (t) => t.results.some((x) => x.includes("derm: rule bash"));
      const ok = !a.ran && !b.ran && reason(a) && reason(b);
      return { status: ok ? "pass" : "fail", finding: `auto high: ${brief(a)} | skip-permissions-unsafe: ${brief(b)}` };
    },
  },
  {
    id: "droid-derm-reject",
    title: "The reject list blocks a write of an endpoint key under an allow rule",
    harness: "droid",
    async run({ binPath }) {
      const t = await turn(binPath, { policy: ALLOW, command: "echo export ANTHROPIC_BASE_URL=http://x > ran.txt" });
      const reason = t.results.some((x) => x.includes("reject list: anthropic_base_url"));
      return { status: !t.ran && reason ? "pass" : "fail", finding: brief(t) };
    },
  },
  {
    id: "droid-derm-ask",
    title: "An ask is the derm approver's yes; a no or no approver is a deny (Droid's own ask only logs)",
    harness: "droid",
    async run({ binPath }) {
      const yes = await turn(binPath, { policy: ASK, approve: "yes", command: "echo dr-approved > ran.txt" });
      const no = await turn(binPath, { policy: ASK, approve: "no", command: "echo dr-declined > ran.txt" });
      const none = await turn(binPath, { policy: ASK, approve: "none", auto: ["--skip-permissions-unsafe"], command: "echo dr-unanswered > ran.txt" });
      const ok = yes.ran.includes("dr-approved") && !no.ran && !none.ran;
      return { status: ok ? "pass" : "fail", finding: `yes: ${brief(yes)} | no: ${brief(no)} | none: ${brief(none)}` };
    },
  },
  {
    id: "droid-derm-beside-orca",
    title: "Beside another PreToolUse hook (Orca's status hook, case 75), a deny still wins and derm's gate runs once",
    harness: "droid",
    async run({ binPath }) {
      const groups = [{ matcher: "*", hooks: [{ type: "command", command: "true", timeout: 10 }] }, gateGroup()];
      const t = await turn(binPath, { policy: DENY, groups, command: "echo dr-beside > ran.txt" });
      const decisions = t.events.filter((e) => e.kind === "approval").length;
      return { status: !t.ran && decisions === 1 ? "pass" : "fail", finding: `${brief(t)}; derm decisions ${decisions}` };
    },
  },
  {
    id: "droid-derm-hooks-json-shadow",
    title: "A PreToolUse array in ~/.factory/hooks.json shadows derm's in settings.json (recorded; derm never writes that file and derm doctor checks it)",
    harness: "droid",
    async run({ binPath }) {
      const t = await turn(binPath, { policy: DENY, hooksJson: { PreToolUse: [{ matcher: "*", hooks: [{ type: "command", command: "true", timeout: 10 }] }] }, command: "echo dr-shadowed-ran > ran.txt" });
      const decisions = t.events.filter((e) => e.kind === "approval").length;
      return { status: "info", finding: `the call ran: ${Boolean(t.ran)}; derm decisions ${decisions} (expected: ran, 0 decisions). ${brief(t)}` };
    },
  },
  {
    id: "droid-derm-killed",
    title: "A gate killed mid-call (case 70): Droid has no fail-closed switch, so the call runs (recorded)",
    harness: "droid",
    async run({ binPath }) {
      const script = path.join(mkdtempSync(path.join(process.env.CLI_CONTRACT_TMP ?? tmpdir(), "dr-kill-")), "killself.sh");
      writeFileSync(script, "#!/bin/sh\nkill -9 $$\n", { mode: 0o700 });
      const t = await turn(binPath, { policy: DENY, groups: [gateGroup(script)], command: "echo dr-killed-ran > ran.txt" });
      return { status: "info", finding: `the call ran: ${Boolean(t.ran)} (expected true: Droid fails open; derm status says so). ${brief(t)}` };
    },
  },
];
