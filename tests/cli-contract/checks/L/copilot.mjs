// Lane L: contract checks for derm's gate in Copilot CLI (T2.5), against the
// real CLI (npm @github/copilot) run offline: COPILOT_OFFLINE=true with a
// local provider (COPILOT_PROVIDER_BASE_URL, _TYPE openai, _WIRE_API
// completions, COPILOT_MODEL; package/cli-main.js help text, 1.0.105), so no
// GitHub sign-in, against the fake OpenAI chat-completions server and a fake
// derm daemon. The gate is a file of its own, $HOME/.copilot/hooks/derm.json.
//
//   node tests/cli-contract/run.mjs --cli copilot-cli=/tmp/cli/copilot/node_modules/.bin/copilot

import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { startFakeChat, toolResults } from "../../lib/fakeChat.mjs";
import { ALLOW, ASK, DENY, brief, hookCommand, oneRun } from "./_lib.mjs";

const gate = () => ({ type: "command", bash: hookCommand("copilot-cli"), timeoutSec: 120 });

async function turn(bin, { policy, command, approve, allowAll = false, files }) {
  const fake = await startFakeChat({ script: (_b, n) => (n === 0 ? { tool: "bash", args: { command, description: "step" } } : { text: "done" }) });
  try {
    return await oneRun({
      prefix: "cp-derm",
      policy,
      approve,
      collect: () => toolResults(fake),
      setup: ({ home }) => {
        const dir = path.join(home, ".copilot", "hooks");
        mkdirSync(dir, { recursive: true });
        for (const [name, body] of Object.entries(files ?? { "derm.json": { version: 1, hooks: { preToolUse: [gate()] } } })) writeFileSync(path.join(dir, name), JSON.stringify(body));
        return {
          bin,
          args: ["-p", "run the step", ...(allowAll ? ["--allow-all"] : [])],
          env: {
            PATH: process.env.PATH,
            COPILOT_OFFLINE: "true",
            COPILOT_PROVIDER_BASE_URL: fake.baseUrl,
            COPILOT_PROVIDER_TYPE: "openai",
            COPILOT_PROVIDER_API_KEY: "sk-fake",
            COPILOT_PROVIDER_WIRE_API: "completions",
            COPILOT_MODEL: "fake-model",
          },
        };
      },
    });
  } finally {
    await fake.close();
  }
}

export const checks = [
  {
    id: "copilot-derm-allow",
    title: "In -p, an allowed bash call runs without Copilot's prompt, and the daemon gets the decision",
    harness: "copilot-cli",
    async run({ binPath }) {
      const t = await turn(binPath, { policy: ALLOW, command: "echo cp-allowed > ran.txt" });
      const recorded = t.events.some((e) => e.kind === "approval" && e.harness === "copilot-cli" && e.detail?.decision === "allow");
      const ok = t.ran.includes("cp-allowed") && recorded;
      return { status: ok ? "pass" : "fail", finding: `${brief(t)}; recorded ${recorded}${ok ? "" : `; ${t.err.slice(-300)}`}` };
    },
  },
  {
    id: "copilot-derm-deny",
    title: "A denied bash call does not run, under --allow-all too (case 83), and the model reads derm's reason",
    harness: "copilot-cli",
    async run({ binPath }) {
      const a = await turn(binPath, { policy: DENY, command: "echo cp-denied > ran.txt" });
      const b = await turn(binPath, { policy: DENY, allowAll: true, command: "echo cp-denied-all > ran.txt" });
      const reason = (t) => t.results.some((x) => x.includes("derm: rule bash"));
      const ok = !a.ran && !b.ran && reason(a) && reason(b);
      return { status: ok ? "pass" : "fail", finding: `plain: ${brief(a)} | allow-all: ${brief(b)}` };
    },
  },
  {
    id: "copilot-derm-reject",
    title: "The reject list blocks a write of an endpoint key under an allow rule",
    harness: "copilot-cli",
    async run({ binPath }) {
      const t = await turn(binPath, { policy: ALLOW, allowAll: true, command: "echo export ANTHROPIC_BASE_URL=http://x > ran.txt" });
      const reason = t.results.some((x) => x.includes("reject list: anthropic_base_url"));
      return { status: !t.ran && reason ? "pass" : "fail", finding: brief(t) };
    },
  },
  {
    id: "copilot-derm-ask",
    title: "An ask is the derm approver's yes; a no denies; with no approver Copilot's own ask, which -p cannot show, denies, under --allow-all too (cases 71, 83)",
    harness: "copilot-cli",
    async run({ binPath }) {
      const yes = await turn(binPath, { policy: ASK, approve: "yes", command: "echo cp-approved > ran.txt" });
      const no = await turn(binPath, { policy: ASK, approve: "no", command: "echo cp-declined > ran.txt" });
      const none = await turn(binPath, { policy: ASK, approve: "none", allowAll: true, command: "echo cp-unanswered > ran.txt" });
      const ok = yes.ran.includes("cp-approved") && !no.ran && !none.ran;
      return { status: ok ? "pass" : "fail", finding: `yes: ${brief(yes)} | no: ${brief(no)} | none, allow-all: ${brief(none)}` };
    },
  },
  {
    id: "copilot-derm-beside-orca",
    title: "Beside another preToolUse hook file (Orca's status hook, case 75), a deny still wins and derm's gate runs once",
    harness: "copilot-cli",
    async run({ binPath }) {
      const files = { "a-orca.json": { version: 1, hooks: { preToolUse: [{ type: "command", bash: "true", timeoutSec: 10 }] } }, "derm.json": { version: 1, hooks: { preToolUse: [gate()] } } };
      const t = await turn(binPath, { policy: DENY, allowAll: true, files, command: "echo cp-beside > ran.txt" });
      const decisions = t.events.filter((e) => e.kind === "approval").length;
      return { status: !t.ran && decisions === 1 ? "pass" : "fail", finding: `${brief(t)}; derm decisions ${decisions}` };
    },
  },
  {
    id: "copilot-derm-killed",
    title: "A gate killed mid-call (case 70): Copilot denies a hook that crashes (recorded)",
    harness: "copilot-cli",
    async run({ binPath }) {
      const files = { "derm.json": { version: 1, hooks: { preToolUse: [{ type: "command", bash: "kill -9 $$", timeoutSec: 10 }] } } };
      const t = await turn(binPath, { policy: DENY, allowAll: true, files, command: "echo cp-killed-ran > ran.txt" });
      return { status: t.ran ? "fail" : "pass", finding: `the call ran: ${Boolean(t.ran)} (expected false: a crash denies). ${brief(t)}` };
    },
  },
];
