// The deny each lane N agent reads when nothing else works (an unknown
// argument, a Node that cannot run TypeScript, a module that does not
// load). Plain JavaScript, no imports. Each entry equals its dialect's own
// deny (src/dialects/*.ts), held so by src/bin.test.ts.

export const FALLBACK = {
  cursor: (r) => ({ stdout: `${JSON.stringify({ permission: "deny", user_message: r, agent_message: r })}\n`, stderr: "", exitCode: 0 }),
  antigravity: (r) => ({ stdout: `${JSON.stringify({ decision: "deny", reason: r })}\n`, stderr: "", exitCode: 0 }),
  goose: (r) => ({ stdout: `${JSON.stringify({ decision: "block", reason: r })}\n`, stderr: `${r}\n`, exitCode: 2 }),
  "mistral-vibe": (r) => ({ stdout: `${JSON.stringify({ decision: "deny", reason: r })}\n`, stderr: "", exitCode: 0 }),
  crush: (r) => ({ stdout: "", stderr: `${r}\n`, exitCode: 2 }),
  kiro: (r) => ({ stdout: "", stderr: `${r}\n`, exitCode: 2 }),
};
