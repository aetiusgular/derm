// The content switch (contracts/events.md section 5; rules case 85 as
// changed): `~/.derm/settings.json`'s `content`, which replaced
// DERM_LOG_CONTENT (lane S's request 3's rest, integration w5 continue).
// Read as derm-tap's reader reads it (crates/derm-tap/src/settings.rs): a
// regular file of this user's, one link, no group or other write, at most
// 64 KiB, `version` 1, `content.on` true with `retentionDays` 1 to 7. Any
// doubt reads as off. The emitter then sends prompt, reply and tool input
// text, and the daemon, which reads the same file, keeps it only in content
// files, never in a record.

import { constants, lstatSync, readFileSync } from "node:fs";
import path from "node:path";

const MAX_BYTES = 64 * 1024;

export type SettingsReader = (file: string) => string | undefined;

/** Reads the file under the owner and mode rules, or undefined. */
export function readSettingsFile(file: string): string | undefined {
  try {
    const st = lstatSync(file);
    if (!st.isFile() || st.nlink !== 1 || st.size > MAX_BYTES) return undefined;
    if (typeof process.getuid === "function" && st.uid !== process.getuid()) return undefined;
    if ((st.mode & 0o022) !== 0) return undefined;
    return readFileSync(file, { encoding: "utf8", flag: constants.O_RDONLY | constants.O_NOFOLLOW });
  } catch {
    return undefined;
  }
}

/** True when the user's settings turn content capture on. */
export function contentSwitchOn(home: string | undefined, read: SettingsReader = readSettingsFile): boolean {
  if (!home || !path.isAbsolute(home)) return false;
  const text = read(path.join(home, ".derm", "settings.json"));
  if (text === undefined) return false;
  try {
    const v = JSON.parse(text) as Record<string, unknown>;
    if (typeof v !== "object" || v === null || Array.isArray(v) || v.version !== 1) return false;
    const c = v.content as Record<string, unknown> | undefined;
    if (typeof c !== "object" || c === null || Array.isArray(c)) return false;
    const days = c.retentionDays;
    return c.on === true && typeof days === "number" && Number.isInteger(days) && days >= 1 && days <= 7;
  } catch {
    return false;
  }
}
