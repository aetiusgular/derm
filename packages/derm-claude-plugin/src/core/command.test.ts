import { describe, expect, it } from "vitest";
import invalid from "../../../../contracts/fixtures/policy/invalid.json" with { type: "json" };
import { commandAllows, commandNarrows, commandProblem, commandReason, headCommands } from "./command.ts";
import { evaluate, parsePolicy, type LoadedPolicy } from "./policy.ts";

const hit = (rule: string[], text: string) => headCommands(text, new Set([rule[0] as string])).some((c) => commandNarrows(rule, c));

describe("command rules (contracts/policy.md section 7)", () => {
  it("takes plain lowercase words, and flags after the first", () => {
    expect(commandProblem(["gh", "pr", "create"])).toBeUndefined();
    expect(commandProblem(["git", "push", "--force"])).toBeUndefined();
    expect(commandProblem(["git", "push", "-f"])).toBeUndefined();
    for (const bad of [[], ["--force"], ["Git"], ["git", "$x"], ["git push"], ["git", "---x"], Array(9).fill("a"), "git"]) {
      expect(commandProblem(bad), JSON.stringify(bad)).toBeDefined();
    }
  });

  it("narrows through separators, wrappers, shells, eval, backticks, backslashes and global flags", () => {
    const r = ["git", "push"];
    for (const t of [
      "git push",
      "ls && git push origin main",
      "make; git push",
      "true || git push",
      "cat x | git push",
      "sleep 1 & git push",
      "sudo -u me git push",
      "env a=1 git push",
      "env -s 'git push'",
      "bash -c 'git push'",
      "sh -lc \"git push\"",
      "eval git push",
      "timeout 10 git push",
      "nohup git push",
      "xargs git push",
      "git -c repo push",
      "/usr/bin/git push",
      "echo `git push`",
      "x=$(git push)",
      "g\\it push",
      "git_dir=x git push",
    ]) {
      expect(hit(r, t), t).toBe(true);
    }
    for (const t of ["git commit -m \"push the fix\"", "echo git push", "git status", "gitpush", "git log --grep push"]) {
      expect(hit(r, t), t).toBe(false);
    }
  });

  it("meets a flag word anywhere after the words before it, and a short flag inside a cluster", () => {
    expect(hit(["git", "push", "--force"], "git push origin main --force")).toBe(true);
    expect(hit(["git", "push", "--force"], "git push --force-with-lease")).toBe(false);
    expect(hit(["git", "push", "--force-with-lease"], "git push --force-with-lease=main:abc")).toBe(true);
    expect(hit(["git", "push", "-f"], "git push -fu origin x")).toBe(true);
    expect(hit(["git", "push", "-f"], "git push -u origin x")).toBe(false);
    expect(hit(["docker", "run", "--privileged"], "docker run --rm --privileged img")).toBe(true);
  });

  it("allows only one plain simple command whose first words are the rule's, exactly", () => {
    const r = ["gh", "pr", "view"];
    expect(commandAllows(r, "gh pr view 12")).toBe(true);
    expect(commandAllows(r, "  gh   pr view")).toBe(true);
    for (const t of ["gh pr view 12; rm -rf x", "gh pr view 12 && x", "sudo gh pr view", "/usr/bin/gh pr view", "gh pr view > out", "gh pr view # x", "gh pr", "gh pr list", "(gh pr view)", "gh pr view\nrm x"]) {
      expect(commandAllows(r, t), t).toBe(false);
    }
  });

  it("gives `rule bash <words>`", () => {
    expect(commandReason(["git", "push", "--force"])).toBe("rule bash git push --force");
  });

  it("every matcher refuses each command shape the schema refuses (contracts/fixtures/policy/invalid.json)", () => {
    for (const p of invalid.policies) expect(typeof parsePolicy(p.policy), p.id).toBe("string");
  });

  it("a command rule is never a rule for the whole tool", () => {
    const parsed = parsePolicy({ version: 1, rules: [{ tool: "bash", command: ["gh", "pr", "view"], action: "allow" }] });
    if (typeof parsed === "string") throw new Error(parsed);
    const loaded: LoadedPolicy = { policy: parsed };
    expect(evaluate(loaded, { tool: "Bash", harness: "claude-code", inputText: "rm -rf build" })).toMatchObject({ action: "ask", reason: "no rule" });
    expect(evaluate(loaded, { tool: "Bash", harness: "claude-code", inputText: "gh pr view 3" })).toMatchObject({ action: "allow", reason: "rule bash gh pr view" });
    const deny = parsePolicy({ version: 1, rules: [{ tool: "bash", action: "allow" }, { tool: "bash", command: ["gh", "repo", "delete"], action: "deny" }] });
    if (typeof deny === "string") throw new Error(deny);
    // A command deny never reaches a shell under another name as a whole-tool deny.
    expect(evaluate({ policy: deny }, { tool: "run_shell_command", harness: "gemini", inputText: "ls -la" }).action).toBe("ask");
    expect(evaluate({ policy: deny }, { tool: "run_shell_command", harness: "gemini", inputText: "gh repo delete a/b" }).action).toBe("deny");
  });
});
