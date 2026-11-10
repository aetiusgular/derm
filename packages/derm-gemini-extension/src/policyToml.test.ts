import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { parsePolicy, type LoadedPolicy, type PolicyFile } from "./core/policy.ts";
import { policyToToml } from "./policyToml.ts";

function loaded(value: unknown): LoadedPolicy {
  const p = parsePolicy(value);
  if (typeof p === "string") throw new Error(p);
  return { policy: p as PolicyFile };
}

describe("policyToToml", () => {
  const toml = policyToToml(
    loaded({
      version: 1,
      servers: ["my-server", "exa"],
      rules: [
        { tool: "run_shell_command", action: "allow" },
        { tool: "write_file", action: "ask" },
        { tool: "my_server/*", action: "deny" },
        { tool: "exa/search", action: "allow", descriptionSha256: "a".repeat(64) },
        { tool: "read_file", harness: "gemini", action: "deny" },
        { tool: "bash", harness: "pi", action: "allow" },
        { tool: "read_file", chat: "c1", action: "allow" },
      ],
    }),
  );

  it("maps each rule to Gemini's rule shape", () => {
    expect(toml).toContain('[[rule]]\ntoolName = "run_shell_command"\ndecision = "allow"\npriority = 201');
    expect(toml).toContain('[[rule]]\ntoolName = "write_file"\ndecision = "ask_user"\npriority = 211');
    // The server's own spelling, from the policy's servers list.
    expect(toml).toContain('[[rule]]\nmcpName = "my-server"\ntoolName = "*"\ndecision = "deny"\npriority = 121');
  });

  it("a harness rule outranks a general one; a chat rule and another harness's rule are skipped", () => {
    expect(toml).toContain('toolName = "read_file"\ndecision = "deny"\npriority = 521');
    expect(toml).toContain("# skipped: bash allow for harness pi");
    expect(toml).toContain("# skipped: read_file allow for one chat");
  });

  it("an allow with a description pin asks, because Gemini cannot check the pin", () => {
    expect(toml).toContain('mcpName = "exa"\ntoolName = "search"\ndecision = "ask_user"');
  });

  it("ends with derm's default: ask when no rule matches", () => {
    expect(toml.trimEnd().endsWith('toolName = "*"\ndecision = "ask_user"\npriority = 0')).toBe(true);
    const withStar = policyToToml(loaded({ version: 1, rules: [{ tool: "*", action: "deny" }] }));
    expect(withStar.match(/\[\[rule\]\]/g)?.length).toBe(1);
  });

  // Lane Q's request 10: derm's `bash` is Gemini's run_shell_command, to
  // deny or ask only; the printout said toolName = "bash" until integration w4.
  it("writes a bash deny or ask as run_shell_command and skips a bash allow", () => {
    const t = policyToToml(
      loaded({ version: 1, rules: [{ tool: "bash", action: "deny" }, { tool: "bash", harness: "gemini", action: "ask" }, { tool: "bash", action: "allow" }] }),
    );
    // Ranks since review W4-S6 (221 and 511 before): above every allow.
    expect(t).toContain('[[rule]]\ntoolName = "run_shell_command"\ndecision = "deny"\npriority = 950\ndenyMessage = "derm: rule bash"');
    expect(t).toContain('[[rule]]\ntoolName = "run_shell_command"\ndecision = "ask_user"\npriority = 522');
    expect(t).toContain("# skipped: bash allow");
    expect(t).not.toContain('toolName = "bash"');
    expect(t).not.toMatch(/toolName = "run_shell_command"\ndecision = "allow"/);
  });

  // Review W4-S6: in the hook a `bash` deny narrows run_shell_command
  // whatever rule allows it, so in the printout it outranks every allow; a
  // `bash` ask outranks every allow too, unless a deny could reach the shell,
  // which it must not outrank (it then keeps its own rank, and says so).
  it("ranks a bash deny above every allow, and a bash ask above every allow when no deny reaches the shell", () => {
    const rank = (t: string, decision: string) =>
      Number(new RegExp(`toolName = "run_shell_command"\\ndecision = "${decision}"\\npriority = (\\d+)`).exec(t)?.[1]);
    const deny = policyToToml(
      loaded({ version: 1, rules: [{ tool: "run_shell_command", harness: "gemini", action: "allow" }, { tool: "bash", action: "deny" }] }),
    );
    expect(rank(deny, "deny")).toBeGreaterThan(rank(deny, "allow"));
    const ask = policyToToml(
      loaded({ version: 1, rules: [{ tool: "run_shell_command", harness: "gemini", action: "allow" }, { tool: "bash", action: "ask" }] }),
    );
    expect(rank(ask, "ask_user")).toBeGreaterThan(rank(ask, "allow"));
    const both = policyToToml(
      loaded({ version: 1, rules: [{ tool: "run_shell_command", action: "deny" }, { tool: "bash", action: "ask" }] }),
    );
    expect(rank(both, "ask_user")).toBeLessThan(rank(both, "deny"));
    expect(both).toContain("# bash ask: kept at its own rank");
  });

  it("stays inside Gemini's priority range (0 to 999)", () => {
    for (const m of toml.matchAll(/priority = (\d+)/g)) expect(Number(m[1])).toBeLessThanOrEqual(999);
  });
});

describe("the extension's own policies/derm.toml", () => {
  // Gemini matches argsPattern as a JavaScript regex against the call's
  // arguments as JSON. Both deny rules name derm's folder and, since the
  // rename, the old name's, which derm never reads (rename review R1).
  const file = readFileSync(new URL("../policies/derm.toml", import.meta.url), "utf8");
  const patterns = [...file.matchAll(/^argsPattern = '([^']*)'$/gm)].map((m) => new RegExp(m[1] ?? ""));

  it("denies writes and shell text that name .derm/ or .tk/", () => {
    expect(patterns).toHaveLength(2);
    const [write, shell] = patterns as [RegExp, RegExp];
    for (const p of ["/home/u/.derm/policy.json", "/home/u/.tk/policy.json"]) {
      expect(write.test(JSON.stringify({ file_path: p, content: "{}" }))).toBe(true);
      expect(shell.test(JSON.stringify({ command: `cat ${p}` }))).toBe(true);
    }
    expect(write.test(JSON.stringify({ file_path: "/home/u/proj/tk/notes.md" }))).toBe(false);
    // The .tk web domain is not the old folder: a hard deny would refuse it
    // (the rename re-review, F3).
    expect(write.test(JSON.stringify({ file_path: "/home/u/site.tk/index.html" }))).toBe(false);
    expect(shell.test(JSON.stringify({ command: "curl https://example.tk/api" }))).toBe(false);
  });

  // The rename re-review's F2: the daemon's own folder.
  it("denies the daemon's token", () => {
    const [write, shell] = patterns as [RegExp, RegExp];
    for (const p of ["/run/user/1000/derm/daemon.token", "/run/user/1000/tk/daemon.token"]) {
      expect(shell.test(JSON.stringify({ command: `cat ${p}` })), p).toBe(true);
      expect(write.test(JSON.stringify({ file_path: p })), p).toBe(true);
    }
    expect(shell.test(JSON.stringify({ command: "ls /run/user/1000/derm/" }))).toBe(false);
  });

  // Gemini 0.66.0 drops a rule whose argsPattern fails isSafeRegExp
  // (bundle chunk-HJ5KJXNZ.js:292070-292083, transcribed): the pattern must
  // compile, be at most 2,048 characters, and not match its nested-quantifier
  // check. Integration w4's first F2 fix used `(?:[^"\\]|\\.)*` and Gemini
  // dropped both rules (contract checks gemini-derm-second-layer and
  // gemini-derm-fail-open, run on 0.66.0).
  it("passes Gemini's own isSafeRegExp, or Gemini drops the rule", () => {
    const sources = [...file.matchAll(/^argsPattern = '([^']*)'$/gm)].map((m) => m[1] ?? "");
    expect(sources).toHaveLength(2);
    const isSafeRegExp = (pattern: string) => {
      try {
        new RegExp(pattern);
      } catch {
        return false;
      }
      if (pattern.length > 2048) return false;
      return !/\([^)]*[*+?{].*\)[*+?{]/.test(pattern);
    };
    for (const p of sources) expect(isSafeRegExp(p), p).toBe(true);
    expect(isSafeRegExp('"x":"(?:[^"\\\\]|\\\\.)*y')).toBe(false);
  });
});

describe("policyToToml and command rules (wave 5 lane W, contracts/policy.md section 7)", () => {
  it("leaves a command rule to the hook: never a whole-shell deny or allow", () => {
    const toml = policyToToml(
      loaded({
        version: 1,
        rules: [
          { tool: "bash", command: ["gh", "repo", "delete"], action: "deny" },
          { tool: "bash", command: ["gh", "pr", "view"], action: "allow" },
        ],
      }),
    );
    expect(toml).not.toContain('toolName = "run_shell_command"');
    expect(toml).toContain("# skipped: bash gh repo delete deny (a command rule; the derm hook applies it)");
    expect(toml).toContain("# skipped: bash gh pr view allow (a command rule; the derm hook applies it)");
  });
});
