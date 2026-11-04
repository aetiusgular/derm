// derm's Amp plugin entry (T2.7). Amp loads a directory plugin from
// `~/.config/amp/plugins/<name>/index.ts` (or `$XDG_CONFIG_HOME/amp/plugins/`)
// with Bun and calls its default export with the plugin API; the entry may
// import files beside it by relative path, and must resolve inside its plugin
// folder (https://ampcode.com/docs/customize/plugins; the binary's "Plugin must
// resolve inside its plugin directory"). So this folder is copied whole, never
// linked: index.ts, amp.ts, control.ts and core/ (README.md, "Install").
//
// Nothing is read when the plugin loads (rules case 46): the policy file is
// read on the first tool call. No import of @ampcode/plugin: its licence is
// Amp's, and the types are not needed at run time.

import { defaultDeps, onToolCall, onToolResult, type ShellCommand, type ToolCallEvent, type ToolResultEvent, type HandlerContext } from "./amp.ts";

export const description = "derm: checks each tool call against your derm policy (~/.derm/policy.json), asks where it says ask, and records the call";

type AmpUri = { toString(): string };
export type AmpLike = {
  on: (event: string, handler: (event: never, ctx: never) => unknown) => unknown;
  helpers?: {
    shellCommandFromToolCall?: (event: ToolCallEvent) => ShellCommand | null;
    isPluginUINotAvailableError?: (error: Error) => boolean;
    filePathFromURI?: (uri: AmpUri) => string;
  };
  system?: { workspaceRoot?: AmpUri | null };
};

/** The workspace root as a local path, read when a call needs it; else the plugin process's folder. */
function workspaceFolder(amp: AmpLike): string {
  try {
    const root = amp.system?.workspaceRoot;
    const toPath = amp.helpers?.filePathFromURI;
    if (root && toPath) {
      const p = toPath(root);
      if (typeof p === "string" && p !== "") return p;
    }
  } catch {
    // Fall back below.
  }
  return process.cwd();
}

export default function (amp: AmpLike): void {
  const shellCommand = amp.helpers?.shellCommandFromToolCall;
  const uiUnavailable = amp.helpers?.isPluginUINotAvailableError;
  const deps = {
    ...defaultDeps(process.env, () => workspaceFolder(amp)),
    ...(shellCommand ? { shellCommand: (e: ToolCallEvent) => shellCommand.call(amp.helpers, e) } : {}),
    ...(uiUnavailable ? { uiUnavailable: (e: Error) => uiUnavailable.call(amp.helpers, e) } : {}),
  };
  amp.on("tool.call", ((event: ToolCallEvent, ctx: HandlerContext) => onToolCall(event, ctx, deps)) as never);
  amp.on("tool.result", ((event: ToolResultEvent) => onToolResult(event, deps)) as never);
}
