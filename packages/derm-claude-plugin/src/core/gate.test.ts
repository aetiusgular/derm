// The text a shell call is checked on (integration w1, security finding S7):
// the command, and every other value the harness gives the shell tool except
// its free-text description, so a working folder (OpenCode's bash `workdir`)
// cannot carry a control path the command leaves out.

import { describe, expect, it } from "vitest";
import { decideCall, inputTextFor, resolveAsk, type GateAnswer } from "./gate.ts";
import { parsePolicy, type LoadedPolicy, type PolicyFile } from "./policy.ts";

const policy = parsePolicy({ version: 1, rules: [{ tool: "bash", action: "allow" }] }) as PolicyFile;
const loaded: LoadedPolicy = { policy };

describe("inputTextFor a shell tool", () => {
  it("checks a workdir beside the command", () => {
    const a = decideCall(loaded, { harness: "opencode", tool: "bash", toolInput: { command: "sed -i s/a/b/ settings.json", workdir: "/home/u/.claude" } });
    expect(a.action).toBe("ask");
    const b = decideCall(loaded, { harness: "opencode", tool: "bash", toolInput: { command: "cat policy.json", workdir: "/home/u/.derm/" } });
    expect(b.action).toBe("ask");
    expect(b.reason).toMatch(/control file/);
  });

  it("leaves the description out, so its prose does not make a plain command ask", () => {
    const a = decideCall(loaded, { harness: "claude-code", tool: "Bash", toolInput: { command: "ls -la", description: "List the files in ~ (all of them!)", timeout: 5000 } });
    expect(a.action).toBe("allow");
    expect(inputTextFor("bash", { command: "ls", description: "x ~", timeout: 5 })).toBe("ls\n5");
  });

  it("is the command alone when nothing else is given", () => {
    expect(inputTextFor("bash", { command: "ls -la" })).toBe("ls -la");
  });
});

// Lane R's request 1 (case 83): under full access an ask is a deny, and the
// reason says so; an allow and a deny are unchanged (integration w4).
describe("full access", () => {
  const ask = { policy: parsePolicy({ version: 1, rules: [{ tool: "bash", action: "ask" }, { tool: "read", action: "allow" }] }) as PolicyFile };
  it("turns an ask into a deny when the call or DERM_FULL_ACCESS=1 says so", () => {
    const call = { harness: "copilot-cli", tool: "bash", toolInput: { command: "ls" } };
    expect(decideCall(ask, call).action).toBe("ask");
    const a = decideCall(ask, { ...call, fullAccess: true });
    expect(a.action).toBe("deny");
    expect(a.reason).toMatch(/^rule bash; the chat runs in full access/);
    const before = process.env.DERM_FULL_ACCESS;
    process.env.DERM_FULL_ACCESS = "1";
    try {
      expect(decideCall(ask, call).action).toBe("deny");
      expect(decideCall(ask, { ...call, fullAccess: false }).action).toBe("ask");
      expect(decideCall(ask, { harness: "copilot-cli", tool: "read", toolInput: { path: "a" } }).action).toBe("allow");
      // A secret-like value in a command asks, so it is denied too.
      expect(decideCall(loaded, { ...call, toolInput: { command: "TOKEN=abc ls" } }).action).toBe("deny");
    } finally {
      if (before === undefined) delete process.env.DERM_FULL_ACCESS;
      else process.env.DERM_FULL_ACCESS = before;
    }
  });

  // Review W4-S3: adapters also make asks after decideCall (an unresolved
  // name, a secret they cannot rewrite) and hand them to resolveAsk; under
  // full access none of them may go back to the agent's own prompt, which is
  // off, nor wait for an approver.
  it("denies an ask that reaches resolveAsk, without asking anyone", async () => {
    const answer = decideCall(ask, { harness: "grok", tool: "bash", toolInput: { command: "ls" } }) as GateAnswer;
    expect(answer.action).toBe("ask");
    let asked = 0;
    const none = async () => (asked++, { answer: "no" as const, by: "none" as const });
    const call = { harness: "grok", tool: "bash", toolInput: { command: "ls" } };
    expect((await resolveAsk(answer, call, true, none)).kind).toBe("harness");
    asked = 0;
    const r = await resolveAsk(answer, { ...call, fullAccess: true }, true, none);
    expect(r.kind).toBe("deny");
    expect(r.reason).toMatch(/full access/);
    expect(asked).toBe(0);
    const before = process.env.DERM_FULL_ACCESS;
    process.env.DERM_FULL_ACCESS = "1";
    try {
      const yes = async () => (asked++, { answer: "yes" as const, by: "approver" as const });
      expect((await resolveAsk(answer, call, true, yes)).kind).toBe("deny");
      expect(asked).toBe(0);
    } finally {
      if (before === undefined) delete process.env.DERM_FULL_ACCESS;
      else process.env.DERM_FULL_ACCESS = before;
    }
  });
});
