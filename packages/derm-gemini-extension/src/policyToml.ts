// Your derm policy as Gemini CLI policy rules, for the user tier
// (~/.gemini/policies/derm.toml). Gemini's own engine then enforces them even
// when the hook does not run: a crashed or timed-out hook lets a call through
// (run, 28 Oct), and a hook cannot approve, only deny or ask
// (scheduler.ts:676-686 at v0.66.0).
//
// The TOML shape is gemini-cli v0.66.0 packages/core/src/policy/toml-loader.ts
// (PolicyRuleSchema, lines 39-60: toolName required, mcpName optional,
// decision allow | deny | ask_user, priority an integer 0 to 999) and
// policy-engine.ts:140-200 (toolName "*" matches every tool; mcpName with
// toolName "*" every tool of that server). The highest priority wins.
//
// What does not carry over, and stays with the hook: the reject list, the
// control files, the shell-text check, redaction, description pins (a pinned
// allow becomes ask_user here), chat-scoped rules, and rules for another
// harness. Each one skipped is named in a comment.
//
// Printed, never written: `derm connect gemini --rules --write` (wave 4 lane
// Q) writes the same file with the policy's deny rules only.

import { lowerName, type LoadedPolicy, type Rule } from "./core/policy.ts";

const HARNESS = "gemini";
const DECISION = { allow: "allow", ask: "ask_user", deny: "deny" } as const;
const SEVERITY = { allow: 0, ask: 1, deny: 2 } as const;

function tomlString(s: string): string {
  return JSON.stringify(s); // a TOML basic string is a JSON string for these characters
}

/** derm's precedence (chat, harness, specificity, then severity) as a Gemini priority. */
export function priorityOf(rule: Rule, action: keyof typeof SEVERITY): number {
  const spec = rule.tool === "*" ? 0 : rule.tool.endsWith("/*") ? 1 : 2;
  return 1 + (rule.harness ? 300 : 0) + spec * 100 + SEVERITY[action] * 10;
}

/** The server name as Gemini knows it: the policy's own `servers` entry whose normalized form matches, else the normalized name. */
function serverName(normalized: string, servers: readonly string[]): string {
  return servers.find((s) => lowerName(s) === normalized) ?? normalized;
}

/** A `bash` deny, above every rule priorityOf ranks; a `bash` ask, above every allow and ask. */
export const BASH_DENY_PRIORITY = 950;
export const BASH_ASK_PRIORITY = 522;

export function policyToToml(loaded: LoadedPolicy): string {
  const lines: string[] = [
    "# derm policy for Gemini CLI, user tier. Generated from your derm policy by",
    "# derm-gemini-extension (bin/derm-gemini-policy.mjs); save as ~/.gemini/policies/derm.toml.",
    "# Regenerate after every change to ~/.derm/policy.json. The derm hook still runs",
    "# first and also applies the reject list, the control files and the shell check.",
    "",
  ];
  if (loaded.problem) lines.push(`# The derm policy did not load cleanly: ${loaded.problem}`, "");
  const { policy } = loaded;
  let hasCatchAll = false;
  // In the hook a `bash` deny or ask narrows run_shell_command whatever rule
  // allows it (step 3a), so here a bash deny outranks every rule and a bash
  // ask every allow and ask (the highest priorityOf gives is 521). A bash ask
  // must not outrank a deny that reaches the shell, so with one in the policy
  // it keeps its own rank (review W4-S6).
  const applies = (r: (typeof policy.rules)[number]) => r.chat === undefined && (r.harness === undefined || r.harness === HARNESS);
  const denyReachesShell = policy.rules.some((r) => applies(r) && r.command === undefined && r.action === "deny" && (r.tool === "run_shell_command" || r.tool === "*"));
  for (const rule of policy.rules) {
    // A command rule (contracts/policy.md section 7) names one command, not
    // run_shell_command: as a Gemini rule it would deny or allow the whole
    // shell. The hook applies it.
    if (rule.command !== undefined) {
      lines.push(`# skipped: bash ${rule.command.join(" ")} ${rule.action} (a command rule; the derm hook applies it)`, "");
      continue;
    }
    if (rule.chat !== undefined) {
      lines.push(`# skipped: ${rule.tool} ${rule.action} for one chat (Gemini rules have no chat)`, "");
      continue;
    }
    if (rule.harness !== undefined && rule.harness !== HARNESS) {
      lines.push(`# skipped: ${rule.tool} ${rule.action} for harness ${rule.harness}`, "");
      continue;
    }
    const action = rule.action === "allow" && rule.descriptionSha256 !== undefined ? "ask" : rule.action;
    // derm's `bash` names every shell, Gemini's run_shell_command included
    // (base-declarations.ts:56 at v0.66.0), but only to narrow it: a `bash`
    // deny or ask reaches run_shell_command in the hook, an allow does not
    // (integration w4, lane Q's request 10). The same here, so a saved
    // printout denies the shell, and never allows it past Gemini's prompt.
    if (rule.tool === "bash" && action === "allow") {
      lines.push("# skipped: bash allow (derm's bash names Gemini's run_shell_command only to deny or ask; name run_shell_command to allow it)", "");
      continue;
    }
    const out = ["[[rule]]"];
    if (rule.tool === "*") {
      out.push(`toolName = "*"`);
      hasCatchAll = true;
    } else if (rule.tool.includes("/")) {
      const [server, tool] = rule.tool.split("/") as [string, string];
      out.push(`mcpName = ${tomlString(serverName(server, policy.servers))}`, `toolName = ${tomlString(tool)}`);
    } else {
      out.push(`toolName = ${tomlString(rule.tool === "bash" ? "run_shell_command" : rule.tool)}`);
    }
    let priority = priorityOf(rule, action);
    if (rule.tool === "bash" && action === "deny") priority = BASH_DENY_PRIORITY;
    else if (rule.tool === "bash" && !denyReachesShell) priority = BASH_ASK_PRIORITY;
    else if (rule.tool === "bash") lines.push("# bash ask: kept at its own rank, because a deny in your policy reaches run_shell_command and must outrank it; a run_shell_command allow above it is not asked about here (the hook still asks)");
    out.push(`decision = "${DECISION[action]}"`, `priority = ${priority}`);
    if (action === "deny") out.push(`denyMessage = ${tomlString(`derm: rule ${rule.tool}${rule.harness ? ` harness=${rule.harness}` : ""}`)}`);
    if (action !== rule.action) lines.push(`# ${rule.tool}: allow with a description pin; Gemini cannot check the pin, so it asks`);
    lines.push(...out, "");
  }
  if (!hasCatchAll) {
    lines.push("# derm asks when no rule matches; so does this, at the lowest priority.", "[[rule]]", 'toolName = "*"', 'decision = "ask_user"', "priority = 0", "");
  }
  return `${lines.join("\n").trimEnd()}\n`;
}
