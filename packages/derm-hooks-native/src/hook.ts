// Entry point bin/derm-hook.mjs loads: picks the agent's dialect and runs
// its pre-tool input through the shared runner.

import { readStdin, runPre, type Dialect } from "./runner.ts";
import { antigravity } from "./dialects/antigravity.ts";
import { crush } from "./dialects/crush.ts";
import { cursor } from "./dialects/cursor.ts";
import { goose } from "./dialects/goose.ts";
import { kiro } from "./dialects/kiro.ts";
import { mistralVibe } from "./dialects/mistralVibe.ts";

export const DIALECTS: Readonly<Record<string, Dialect>> = {
  cursor,
  antigravity,
  goose,
  "mistral-vibe": mistralVibe,
  crush,
  kiro,
};

export async function main(agent: string): Promise<number> {
  const dialect = DIALECTS[agent];
  if (dialect === undefined) {
    process.stderr.write(`derm: unknown agent ${agent.slice(0, 40)}\n`);
    return 2;
  }
  const result = await runPre(dialect, await readStdin());
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  return result.exitCode;
}
