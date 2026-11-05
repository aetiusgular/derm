// Registers derm's Claude Code hooks in a settings file, merging with what
// is there. Run by the sbx kit's install script as root inside the VM
// (packaging/sbx-kit/claude/install.sh):
//
//   node register-hooks.mjs <settings.json> <node> <derm-hook.mjs>
//
// Plain JavaScript with no dependencies: it runs on the image's Node before
// anything else of derm's is there. The entries use Claude Code's exec form
// (`command` is the program, `args` its arguments, spawned with no shell)
// and `onFailure: "block"`, so a hook that fails or times out blocks the
// call. Both are in Claude Code 2.1.311's hook schema (read in its binary:
// `on_failure: ["continue","block"]`, and the exec form's `args`). The
// entries match derm's plugin (packages/derm-claude-plugin/hooks/hooks.json)
// in matcher, timeout and failure mode.

import { readFileSync, renameSync, writeFileSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

export const PRE_TIMEOUT = 120;
export const POST_TIMEOUT = 30;

function entry(node, hook, event, timeout, block) {
  const h = { type: "command", command: node, args: ["--no-warnings", hook, event], timeout };
  if (block) h.onFailure = "block";
  return { matcher: "*", hooks: [h] };
}

function isObject(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** True when a hook list already runs this hook script for this event. */
function hasDerm(list, hook, event) {
  return list.some(
    (m) =>
      isObject(m) &&
      Array.isArray(m.hooks) &&
      m.hooks.some((h) => isObject(h) && Array.isArray(h.args) && h.args.includes(hook) && h.args.at(-1) === event),
  );
}

/**
 * The settings with derm's PreToolUse and PostToolUse entries added. Every
 * other key and every other hook is kept as it was; a second run adds
 * nothing. Throws when the settings or their `hooks` are not objects, or an
 * event's value is not a list, rather than replace what another kit wrote.
 */
export function merge(settings, node, hook) {
  if (!path.isAbsolute(node) || !path.isAbsolute(hook)) throw new Error("the node and hook paths must be absolute");
  if (!isObject(settings)) throw new Error("the settings file does not hold a JSON object");
  const out = { ...settings };
  if (out.hooks !== undefined && !isObject(out.hooks)) throw new Error('"hooks" in the settings file is not an object');
  const hooks = { ...(out.hooks ?? {}) };
  for (const [event, arg, timeout, block] of [
    ["PreToolUse", "pre", PRE_TIMEOUT, true],
    ["PostToolUse", "post", POST_TIMEOUT, false],
  ]) {
    const list = hooks[event] ?? [];
    if (!Array.isArray(list)) throw new Error(`"hooks.${event}" in the settings file is not a list`);
    hooks[event] = hasDerm(list, hook, arg) ? list : [...list, entry(node, hook, arg, timeout, block)];
  }
  out.hooks = hooks;
  return out;
}

/** Reads the file (absent is `{}`), merges, and writes it back by rename. */
export function registerFile(file, node, hook) {
  let settings = {};
  let text;
  try {
    text = readFileSync(file, "utf8");
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
  }
  if (text !== undefined && text.trim() !== "") {
    try {
      settings = JSON.parse(text);
    } catch {
      throw new Error(`${file} is not JSON`);
    }
  }
  const merged = merge(settings, node, hook);
  const tmp = `${file}.derm-${process.pid}`;
  writeFileSync(tmp, `${JSON.stringify(merged, null, 2)}\n`, { mode: 0o644 });
  renameSync(tmp, file);
  return merged;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [file, node, hook] = process.argv.slice(2);
  if (!file || !node || !hook) {
    process.stderr.write("usage: node register-hooks.mjs <settings.json> <node> <derm-hook.mjs>\n");
    process.exit(2);
  }
  try {
    registerFile(file, node, hook);
  } catch (e) {
    process.stderr.write(`derm kit: ${e.message}\n`);
    process.exit(1);
  }
}
