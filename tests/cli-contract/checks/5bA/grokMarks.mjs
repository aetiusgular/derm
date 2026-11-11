// Lane 5bA: Grok Build runs the hooks in Claude Code's ~/.claude/settings.json
// with its compat import on, its default (BCR-7; recorded by this lane from
// Grok 1.0.77: Grok's input, both spellings, reaches the Claude Code hook).
// derm's Claude Code hook must not decide in Claude Code's dialect for it
// (contracts/hook-dialects.md section 9.2, case 109): with derm's own Grok
// gate registered and failing closed it defers (no decision, no record), so
// the gate runs once per call (case 75); without it, it blocks and names
// the fix. Run against the real Grok, as lane L's checks are, with the
// Rust hook (`derm hook ...`) in both places.

import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { startFakeChat, toolResults } from "../../lib/fakeChat.mjs";
import { ALLOW, DENY, brief, oneRun } from "../L/_lib.mjs";

async function turn(bin, derm, { policy, grokGate, command }) {
  const fake = await startFakeChat({ script: (_b, n) => (n === 0 ? { tool: "run_terminal_command", args: { command, description: "step" } } : { text: "done" }) });
  try {
    return await oneRun({
      prefix: "gk-5bA",
      policy,
      collect: () => toolResults(fake),
      setup: ({ home }) => {
        mkdirSync(path.join(home, ".grok", "hooks"), { recursive: true });
        mkdirSync(path.join(home, ".claude"), { recursive: true });
        const hook = (agent) => ({ type: "command", command: `"${derm}" hook ${agent} pre`, timeout: 120, failClosed: true });
        if (grokGate) writeFileSync(path.join(home, ".grok", "hooks", "derm.json"), JSON.stringify({ hooks: { PreToolUse: [{ matcher: "*", hooks: [hook("grok")] }] } }));
        // derm's user-level Claude Code gate, as `derm connect claude-code --gate` would write it.
        writeFileSync(path.join(home, ".claude", "settings.json"), JSON.stringify({ hooks: { PreToolUse: [{ matcher: "*", hooks: [{ type: "command", command: `"${derm}" hook claude-code pre`, timeout: 120 }] }] } }));
        // Grok's compat imports left on (its default).
        writeFileSync(path.join(home, ".grok", "config.toml"), `[model.fake]\nmodel = "fake-model"\nbase_url = "${fake.baseUrl}"\napi_key = "sk-fake"\napi_backend = "chat_completions"\n`);
        return { bin, args: ["-p", "run the step", "-m", "fake", "--yolo"], env: { PATH: process.env.PATH, XAI_API_KEY: "xai-fake" } };
      },
    });
  } finally {
    await fake.close();
  }
}

// run.mjs wants a `checks` array from every file in a lane folder; rust.mjs
// takes these through `grokMarksChecks`, with derm's binary.
export const checks = [];

const decisions = (t) => t.events.filter((e) => e.kind === "approval");

export function grokMarksChecks(derm) {
  return [
    {
      id: "grok-5bA-claude-hook-blocks-without-grok-gate",
      title: "Grok runs derm's Claude Code hook with no derm Grok gate: the hook blocks the call and names Grok and the fix; nothing is decided as Claude Code (case 109, BCR-7)",
      harness: "grok",
      async run({ binPath }) {
        const t = await turn(binPath, derm, { policy: ALLOW, grokGate: false, command: "echo gk5a-block > ran.txt" });
        const said = JSON.stringify(t.results);
        const ok = !t.ran && said.includes("Grok ran derm's Claude Code hook") && decisions(t).length === 0;
        return { status: ok ? "pass" : "fail", finding: `${brief(t)}; derm decisions ${decisions(t).length}` };
      },
    },
    {
      id: "grok-5bA-claude-hook-defers-to-grok-gate",
      title: "With derm's Grok gate registered failing closed, derm's Claude Code hook defers: an allow runs and a deny blocks, each decided once, as grok (case 75)",
      harness: "grok",
      async run({ binPath }) {
        const a = await turn(binPath, derm, { policy: ALLOW, grokGate: true, command: "echo gk5a-allow > ran.txt" });
        const d = await turn(binPath, derm, { policy: DENY, grokGate: true, command: "echo gk5a-deny > ran.txt" });
        const harnesses = [...decisions(a), ...decisions(d)].map((e) => e.harness);
        const ok = Boolean(a.ran) && !d.ran && decisions(a).length === 1 && decisions(d).length === 1 && harnesses.every((h) => h === "grok");
        return { status: ok ? "pass" : "fail", finding: `allow: ${brief(a)}; deny: ${brief(d)}; decisions by ${JSON.stringify(harnesses)}` };
      },
    },
  ];
}
