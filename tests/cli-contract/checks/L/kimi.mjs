// Lane L: contract checks for derm's gate in Kimi Code (T2.5), against the
// real CLI (npm @moonshot-ai/kimi-code) driven by `kimi -p` against the fake
// OpenAI chat-completions server (../../lib/fakeChat.mjs) through Kimi's env
// model (KIMI_MODEL_PROVIDER_TYPE=openai, KIMI_MODEL_BASE_URL, KIMI_MODEL_NAME,
// KIMI_MODEL_API_KEY; dist/main.mjs applyEnvModelConfig, 2.4.1), and a fake
// derm daemon. Prompt mode runs in Kimi's "Never Ask" mode (main.mjs
// runV2Print, setMode("auto")), so derm's gate is the only check, as under
// Orca's full access (case 83). Kimi reads only a deny from a hook.
//
//   node tests/cli-contract/run.mjs --cli kimi=/tmp/cli/kimi/node_modules/.bin/kimi

import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { startFakeChat, toolResults } from "../../lib/fakeChat.mjs";
import { ALLOW, ASK, DENY, brief, hookCommand, oneRun } from "./_lib.mjs";

const tomlString = (s) => `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
const gateToml = (command = hookCommand("kimi")) => `[[hooks]]\nevent = "PreToolUse"\ncommand = ${tomlString(command)}\ntimeout = 120\n`;

async function turn(bin, { policy, command, approve, config }) {
  const fake = await startFakeChat({ script: (_b, n) => (n === 0 ? { tool: "Bash", args: { command } } : { text: "done" }) });
  try {
    return await oneRun({
      prefix: "km-derm",
      policy,
      approve,
      collect: () => toolResults(fake),
      setup: ({ home }) => {
        mkdirSync(path.join(home, ".kimi-code"), { recursive: true });
        writeFileSync(path.join(home, ".kimi-code", "config.toml"), config ?? gateToml());
        return {
          bin,
          args: ["-p", "run the step", "--output-format", "stream-json"],
          env: {
            PATH: process.env.PATH,
            KIMI_MODEL_PROVIDER_TYPE: "openai",
            KIMI_MODEL_BASE_URL: fake.baseUrl,
            KIMI_MODEL_API_KEY: "sk-fake",
            KIMI_MODEL_NAME: "fake-model",
            KIMI_MODEL_MAX_CONTEXT_SIZE: "131072",
            KIMI_MODEL_CAPABILITIES: "",
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
    id: "kimi-derm-allow",
    title: "An allowed Bash call runs (Kimi reads no allow; the gate prints nothing), and the daemon gets the decision",
    harness: "kimi",
    async run({ binPath }) {
      const t = await turn(binPath, { policy: ALLOW, command: "echo km-allowed > ran.txt" });
      const recorded = t.events.some((e) => e.kind === "approval" && e.harness === "kimi" && e.detail?.decision === "allow");
      const ok = t.ran.includes("km-allowed") && recorded;
      return { status: ok ? "pass" : "fail", finding: `${brief(t)}; recorded ${recorded}${ok ? "" : `; ${t.err.slice(-300)}`}` };
    },
  },
  {
    id: "kimi-derm-deny",
    title: "In prompt mode (Never Ask), a denied Bash call does not run and the model reads derm's reason (case 83)",
    harness: "kimi",
    async run({ binPath }) {
      const t = await turn(binPath, { policy: DENY, command: "echo km-denied > ran.txt" });
      const reason = t.results.some((x) => x.includes("derm: rule bash"));
      return { status: !t.ran && reason ? "pass" : "fail", finding: `${brief(t)}${!t.ran && reason ? "" : `; ${t.err.slice(-300)}`}` };
    },
  },
  {
    id: "kimi-derm-reject",
    title: "The reject list blocks a write of an endpoint key under an allow rule",
    harness: "kimi",
    async run({ binPath }) {
      const t = await turn(binPath, { policy: ALLOW, command: "echo export ANTHROPIC_BASE_URL=http://x > ran.txt" });
      const reason = t.results.some((x) => x.includes("reject list: anthropic_base_url"));
      return { status: !t.ran && reason ? "pass" : "fail", finding: brief(t) };
    },
  },
  {
    id: "kimi-derm-ask",
    title: "An ask is the derm approver's yes; a no or no approver is a deny (Kimi has no ask)",
    harness: "kimi",
    async run({ binPath }) {
      const yes = await turn(binPath, { policy: ASK, approve: "yes", command: "echo km-approved > ran.txt" });
      const no = await turn(binPath, { policy: ASK, approve: "no", command: "echo km-declined > ran.txt" });
      const none = await turn(binPath, { policy: ASK, approve: "none", command: "echo km-unanswered > ran.txt" });
      const ok = yes.ran.includes("km-approved") && !no.ran && !none.ran;
      return { status: ok ? "pass" : "fail", finding: `yes: ${brief(yes)} | no: ${brief(no)} | none: ${brief(none)}` };
    },
  },
  {
    id: "kimi-derm-beside-orca",
    title: "Beside another PreToolUse hook (Orca's status hook, case 75), a deny still wins and derm's gate runs once",
    harness: "kimi",
    async run({ binPath }) {
      const config = `[[hooks]]\nevent = "PreToolUse"\ncommand = "true"\ntimeout = 10\n\n${gateToml()}`;
      const t = await turn(binPath, { policy: DENY, config, command: "echo km-beside > ran.txt" });
      const decisions = t.events.filter((e) => e.kind === "approval").length;
      return { status: !t.ran && decisions === 1 ? "pass" : "fail", finding: `${brief(t)}; derm decisions ${decisions}` };
    },
  },
  {
    id: "kimi-derm-fifth-key",
    title: "A fifth key in a hook entry makes Kimi drop its whole config (recorded; derm's entry never adds one)",
    harness: "kimi",
    async run({ binPath }) {
      const config = gateToml().replace("timeout = 120\n", "timeout = 120\nname = \"derm\"\n");
      const t = await turn(binPath, { policy: DENY, config, command: "echo km-fifth-ran > ran.txt" });
      return { status: "info", finding: `the call ran: ${Boolean(t.ran)}; ${brief(t)}; stderr ${JSON.stringify(t.err.slice(-200))}` };
    },
  },
  {
    id: "kimi-derm-killed",
    title: "A gate killed mid-call (case 70): Kimi has no fail-closed switch, so the call runs (recorded)",
    harness: "kimi",
    async run({ binPath }) {
      const config = `[[hooks]]\nevent = "PreToolUse"\ncommand = "kill -9 $$"\ntimeout = 10\n`;
      const t = await turn(binPath, { policy: DENY, config, command: "echo km-killed-ran > ran.txt" });
      return { status: "info", finding: `the call ran: ${Boolean(t.ran)} (expected true: Kimi fails open; derm status says so). ${brief(t)}` };
    },
  },
];
