// The text a shell call is checked on (integration w1, security finding S7):
// the command, and every other value the harness gives the shell tool except
// its free-text description, so a working folder (OpenCode's bash `workdir`)
// cannot carry a control path the command leaves out.

import { describe, expect, it } from "vitest";
import { decideCall, inputTextFor } from "./gate.ts";
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
});
