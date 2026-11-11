// derm's Cline SDK plugin (T2.7). Cline 3.0.74 loads a plugin module from
// `$CLINE_DIR/plugins/` (default `~/.cline/plugins/`): a folder whose
// package.json names its entry under `cline.plugins`, here this file
// (sdk/packages/shared/src/storage/paths.ts:618-625, 700-747). Each session
// imports it fresh in its own worker thread (docs/sdk/plugins.mdx, "How
// Plugins Run"), so module state here belongs to one session.
//
// Nothing is read when the plugin loads or is set up (rules case 46): the
// co-process (`derm gate serve`, wave 5b) starts on the first tool call and
// reads the policy then. `setup` keeps only the session's folder, for the
// policy's and the token's folder checks, and stops the co-process when the
// session ends (`ctx.onDispose`, docs/sdk/plugins.mdx at 071e1b2, "Setup and
// Call Context"). No import of @cline/sdk: the host provides it, and the
// types are not needed at run time.

import { beforeTool, defaultDeps, type BeforeToolContext, type BeforeToolResult } from "./cline.ts";

let sessionFolder: string | undefined;
const deps = defaultDeps(process.env, () => sessionFolder ?? process.cwd());

const plugin = {
  name: "derm",
  manifest: { capabilities: ["hooks"] },
  setup(_api: unknown, ctx?: { cwd?: unknown; onDispose?: unknown }): void {
    if (typeof ctx?.cwd === "string" && ctx.cwd !== "") sessionFolder = ctx.cwd;
    if (typeof ctx?.onDispose === "function") (ctx.onDispose as (fn: () => void) => void)(() => deps.serve().close());
  },
  hooks: {
    beforeTool(context: BeforeToolContext): Promise<BeforeToolResult> {
      return beforeTool(context, deps);
    },
  },
};

export default plugin;
