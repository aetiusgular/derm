// What Amp's own dialog shows for a call derm asks about: the input as text,
// the way derm's gate reads it. `inputTextFor` and its helpers are the hook
// core's (src/core/gate.ts and SHELL_TOOLS of policy.ts at e29ce27), word for
// word, moved here on 19 Nov 2026 when the TypeScript gate left this plugin
// and with it the core's matcher: the decision is `derm gate serve`'s, and
// this text is only the preview a person reads before answering.

/** The tool name and input the gate checks for one call. */
export type GateCall = {
  harness: string;
  /** The tool name as the harness gave it. */
  tool: string;
  toolInput: unknown;
  chat?: string;
  toolUseId?: string;
};

const SHELL_TOOLS = ["bash", "shell", "exec_command", "local_shell", "run_shell_command", "user_bash", "terminal", "powershell", "monitor", "shell_command", "run_commands"] as const;

function isShellTool(normalized: string): boolean {
  return (SHELL_TOOLS as readonly string[]).includes(normalized);
}

/** Every string, number and boolean value under `v`, in order (keys left out). */
function valuesOf(v: unknown, out: string[], depth: number): void {
  if (depth > 64) throw new Error("tool input nested too deep to check");
  if (typeof v === "string") out.push(v);
  else if (typeof v === "number" || typeof v === "boolean") out.push(String(v));
  else if (Array.isArray(v)) for (const x of v) valuesOf(x, out, depth + 1);
  else if (typeof v === "object" && v !== null) for (const x of Object.values(v)) valuesOf(x, out, depth + 1);
}

/**
 * The text the reject list and the shell check run over. For a shell tool:
 * the command, then on their own lines the values of every other field except
 * the free-text `description`, so a working folder (OpenCode's bash `workdir`)
 * is checked too (integration w1, security finding S7). Otherwise the
 * serialized input.
 */
export function inputTextFor(normalizedTool: string, toolInput: unknown): string {
  if (isShellTool(normalizedTool) && typeof toolInput === "object" && toolInput !== null && !Array.isArray(toolInput)) {
    const fields = toolInput as Record<string, unknown>;
    const command = fields.command;
    const head =
      typeof command === "string"
        ? command
        : Array.isArray(command) && command.every((c) => typeof c === "string")
          ? command.join(" ")
          : undefined;
    if (head !== undefined) {
      const rest: string[] = [];
      for (const [k, v] of Object.entries(fields)) if (k !== "command" && k !== "description") valuesOf(v, rest, 0);
      // A folder value is also read with a trailing `/`, so `/home/u/.claude`
      // meets the `.claude/` control marker.
      for (const v of [...rest]) if (v.includes("/") && !v.endsWith("/")) rest.push(`${v}/`);
      return rest.length ? `${head}\n${rest.join("\n")}` : head;
    }
  }
  if (typeof toolInput === "string") return toolInput;
  let serialized = "";
  try {
    serialized = JSON.stringify(toolInput) ?? "";
  } catch {
    serialized = "";
  }
  // Serializing doubles every backslash, which would hide `_` from the
  // escape decoder; so every string key and value also goes in as it is.
  const leaves: string[] = [];
  const walk = (v: unknown, depth: number): void => {
    if (depth > 64) return;
    if (typeof v === "string") leaves.push(v);
    else if (Array.isArray(v)) for (const x of v) walk(x, depth + 1);
    else if (typeof v === "object" && v !== null) {
      for (const [k, x] of Object.entries(v)) {
        leaves.push(k);
        walk(x, depth + 1);
      }
    }
  };
  walk(toolInput, 0);
  return leaves.length ? `${serialized}\n${leaves.join("\n")}` : serialized;
}
