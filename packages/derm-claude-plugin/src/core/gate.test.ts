// The text a shell call is checked on (integration w1, security finding S7):
// the command, and every other value the harness gives the shell tool except
// its free-text description, so a working folder (OpenCode's bash `workdir`)
// cannot carry a control path the command leaves out.

import { describe, expect, it } from "vitest";
import { decideCall, inputTextFor, installEvents, MAX_INSTALL_RECORDS, resolveAsk, type GateAnswer } from "./gate.ts";
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

// Lane X's request 7 (integration w5, continue): every gated hook posts an
// `install.call` record for a shell call the gate read as an install, so the
// daemon can diff the lockfile and credit an install script's writes
// (contracts/events.md section 5; cases 132, 133).
describe("installEvents", () => {
  const ask = { policy: parsePolicy({ version: 1, rules: [{ tool: "bash", action: "ask" }] }) as PolicyFile };
  const call = (command: string, toolUseId?: string) => ({
    harness: "claude-code",
    tool: "Bash",
    toolInput: { command },
    ...(toolUseId !== undefined ? { toolUseId } : {}),
  });

  it("gives one record per install, whatever the policy said", () => {
    const c = call("npm install left-pad@1.3.0 && pip install six", "toolu_01");
    for (const p of [loaded, ask]) {
      const answer = decideCall(p, c);
      const events = installEvents(c, answer, answer.action, "chat-1");
      expect(events.map((e) => e.kind)).toEqual(["install.call", "install.call"]);
      expect(events.map((e) => e.detail.manager)).toEqual(["npm", "pip"]);
      expect(events[0]?.detail.packages).toEqual([{ name: "left-pad", version: "1.3.0", ecosystem: "npm", inLockfile: null }]);
      expect(events[0]?.detail.toolUseId).toBe("toolu_01");
      expect(events[0]?.detail.decision).toBe(answer.action);
      expect(events[0]?.chatId).toBe("chat-1");
      expect(events[0]?.harness).toBe("claude-code");
    }
  });

  // Security finding W5C-S9 (integration w5 continue): a package name or
  // version the redactor flags (a token's shape) never reaches the record;
  // the record counts what it left out.
  it("leaves out a package the redactor flags, and counts it", () => {
    // Fake keys built at run time, so no scanner reads them as live.
    const token = ["sk", "proj", "abcdefghijklmnopqrstuvwxyz0123456789"].join("-");
    const ant = ["sk", "ant", "api03", "abcdefghijklmnopqrstuvwxyz"].join("-");
    for (const cmd of [`pip install ${token}`, `npm i left-pad ${ant}`, `npm i left-pad@${token}`]) {
      const c = call(cmd, "t9");
      const events = installEvents(c, decideCall(loaded, c), "ask", "c");
      expect(events.length, cmd).toBe(1);
      const text = JSON.stringify(events);
      expect(text, cmd).not.toContain(token);
      expect(text, cmd).not.toContain(ant);
      expect(events[0]?.detail.redacted, cmd).toBe(1);
    }
    const kept = installEvents(call(`npm i left-pad ${ant}`, "t9"), decideCall(loaded, call("npm i x")), "ask", "c");
    expect(kept[0]?.detail.packages).toEqual([{ name: "left-pad", version: null, ecosystem: "npm", inLockfile: null }]);
    expect(kept[0]?.summary).toBe("npm add left-pad ask");
    // Nothing flagged: no count.
    const plain = installEvents(call("npm i left-pad", "t9"), decideCall(loaded, call("npm i x")), "ask", "c");
    expect(plain[0]?.detail.redacted).toBeUndefined();
  });

  it("gives none for a call that is not an install, or a tool that is not a shell", () => {
    const plain = call("npm test");
    expect(installEvents(plain, decideCall(loaded, plain), "allow", "c")).toEqual([]);
    const write = { harness: "claude-code", tool: "Write", toolInput: { file_path: "a.txt", content: "npm install left-pad" } };
    expect(installEvents(write, decideCall(loaded, write), "ask", "c")).toEqual([]);
  });

  it("names the decision the harness got, not the policy's", () => {
    const c = call("npx cowsay hi", "t2");
    const answer = decideCall(loaded, c);
    expect(answer.action).toBe("ask");
    expect(installEvents(c, answer, "deny", "c")[0]?.detail.decision).toBe("deny");
  });

  it("gives each record an id the agent cannot work out first", () => {
    const c = call("npm i a b", "t3");
    const a = installEvents(c, decideCall(loaded, c), "ask", "c");
    const b = installEvents(c, decideCall(loaded, c), "ask", "c");
    expect(a[0]?.id).toMatch(/^claude-code-t3-install-0-[0-9a-f]{32}$/);
    expect(a[0]?.id).not.toBe(b[0]?.id);
  });

  it("reads the folded text, so look-alike letters do not hide an install", () => {
    const c = call("ｎｐｍ install left-pad");
    const events = installEvents(c, decideCall(loaded, c), "ask", "c");
    expect(events.length).toBe(1);
    expect(events[0]?.detail.toolUseId).toBeNull();
  });

  it("posts at most eight records for one call", () => {
    const c = call(Array.from({ length: 12 }, (_, i) => `npm i p${i}`).join(" && "));
    expect(installEvents(c, decideCall(loaded, c), "ask", "c").length).toBe(MAX_INSTALL_RECORDS);
  });
});
