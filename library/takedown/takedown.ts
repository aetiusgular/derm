// A takedown (T4.4): a catalog entry's `status` becomes `deleted` and nothing
// else in its manifest changes, so its metadata stays readable, as the
// official registry keeps a deleted server and returns it with
// `include_deleted` (`library/mirror/registry.ts`, servers.go:43-50 at
// 9c4a96c). The exports leave a deleted entry out, except the registry list
// written with deleted servers included. Each takedown adds one line to
// library/TAKEDOWNS.md, the public log. The entry schema allows no field for
// a reason (`additionalProperties: false`), so the reason and the report
// live in the log.
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { REPO_ROOT } from "../validate/schemas.ts";
import { CATALOG_DIR, loadCatalog } from "../validate/index.ts";
import { getMeta } from "../validate/types.ts";

export const TAKEDOWN_LOG = join(REPO_ROOT, "library", "TAKEDOWNS.md");

export const LOG_HEADER = `# Takedowns

The public log of entries taken out of the derm library. A takedown sets the
entry's \`status\` to \`deleted\` and changes nothing else in it: its metadata
stays in the repository, the exports leave it out, and the registry list keeps
it in \`registry-include-deleted.json\`, as the official MCP registry returns a
deleted server with \`include_deleted\`.

Report abuse, malware, a trademark or a copyright claim with the "Report an
entry" issue form, or privately through GitHub's private vulnerability
reporting when the report itself would do harm. We answer within 7 days.

| Date (UTC) | Entry | Name | Status before | Reason | Report |
|---|---|---|---|---|---|
`;

const ISSUE_URL = /^https:\/\/github\.com\/aetiusgular\/(?:derm|tk)\/issues\/(\d{1,7})$/;

export type TakedownInput = {
  id: string;
  /** One line, shown in the public log. */
  reason: string;
  /** `#<n>`, this repository's issue URL, or `private`. */
  report: string;
  catalogDir?: string;
  logPath?: string;
  now?: () => Date;
};

export type TakedownResult = { manifest: string; logLine: string; diff: string[] };

function reportCell(report: string): string {
  if (report === "private") return "sent privately";
  const short = /^#(\d{1,7})$/.exec(report);
  if (short) return `[#${short[1]}](https://github.com/aetiusgular/derm/issues/${short[1]})`;
  const url = ISSUE_URL.exec(report);
  if (url) return `[#${url[1]}](${report})`;
  throw new Error("report: give #<issue number>, this repository's issue URL, or private");
}

export function takedown(i: TakedownInput): TakedownResult {
  const reason = i.reason.trim();
  if (!reason || reason.length > 200 || /[|\r\n\u0000-\u001f\u007f]/.test(reason)) {
    throw new Error("reason: one line of at most 200 characters, with no | and no control character");
  }
  const cell = reportCell(i.report.trim());
  const catalog = loadCatalog(i.catalogDir ?? CATALOG_DIR);
  const entry = catalog.entries.find((e) => e.id === i.id);
  if (!entry) throw new Error(`no catalog entry ${JSON.stringify(i.id)}`);
  const path = join(entry.dir, entry.file);
  const text = readFileSync(path, "utf8");
  if (JSON.stringify(JSON.parse(text), null, 2) + "\n" !== text) {
    throw new Error(`${path}: its formatting is not the library's (two-space JSON); refusing to rewrite it`);
  }
  const data = JSON.parse(text) as Record<string, unknown>;
  const meta = getMeta(entry.kind, data);
  if (!meta) throw new Error(`${entry.id}: no derm object in its manifest`);
  const before = meta.status;
  if (before === "deleted") throw new Error(`${entry.id} is already deleted`);
  meta.status = "deleted";
  writeFileSync(path, JSON.stringify(data, null, 2) + "\n");
  const name = typeof data["name"] === "string" ? data["name"] : entry.id;
  const day = (i.now ?? (() => new Date()))().toISOString().slice(0, 10);
  const logLine = `| ${day} | ${entry.id} | ${name} | ${before} | ${reason} | ${cell} |`;
  const logPath = i.logPath ?? TAKEDOWN_LOG;
  appendFileSync(logPath, `${logLine}\n`);
  return { manifest: path, logLine, diff: [`- "status": "${before}"`, `+ "status": "deleted"`] };
}
