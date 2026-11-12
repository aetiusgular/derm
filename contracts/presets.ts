// The harness preset table, assembled from one file per agent in
// crates/derm-cli/src/connect/presets/ (integration w2 split the old
// contracts/harness-presets.json so each wave 4 lane owns its agents' rows
// by file). index.json names the two lists and their order. The same rules
// as `assemble` in crates/derm-cli/src/connect/presets.rs: every listed id has
// a file whose `id` is its name, no id is listed twice, and every file is
// listed. The assembled object follows harness-presets.schema.json.
//
// Wave 5 (the wave 5 base): the sibling tables in presets/wave5/ (`tap`, lane
// S; `kit`, lane T; `executables`, lane W) are merged into the rows by
// `mergeWave5`, with the same refusals as presets.rs's `merge_wave5`.
//
// Wave 6 (the wave 6 base): presets/wave6/sandbox.json (lane 6A) is merged
// the same way, after wave 5's tables.

import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

export const PRESETS_DIR = fileURLToPath(new URL("../crates/derm-cli/src/connect/presets/", import.meta.url));

export type PresetTable = { $comment?: string; version: number; harnesses: Record<string, unknown>[]; planned: Record<string, unknown>[] };

/** Wave 5's sibling tables, in the order presets.rs merges them. */
export const WAVE5_FIELDS = ["tap", "kit", "executables"] as const;

/** Wave 6's sibling tables (presets/wave6/), merged after wave 5's. */
export const WAVE6_FIELDS = ["sandbox"] as const;

const folderOf = (field: string): string => ((WAVE6_FIELDS as readonly string[]).includes(field) ? "wave6" : "wave5");

/**
 * Merges each sibling table's values into the rows as its field. Refuses a
 * table whose `field` is not its name, an id the index does not name, a row
 * that already sets the field, and a value that is not the field's shape.
 */
export function mergeWave5(table: PresetTable, tables: { field: string; text: string }[]): void {
  for (const { field, text } of tables) {
    const folder = folderOf(field);
    const t = JSON.parse(text) as { field?: unknown; rows?: unknown };
    if (t.field !== field) throw new Error(`${folder}/${field}.json: its field is not ${field}`);
    if (typeof t.rows !== "object" || t.rows === null || Array.isArray(t.rows)) throw new Error(`${folder}/${field}.json: no rows object`);
    for (const [id, value] of Object.entries(t.rows as Record<string, unknown>)) {
      const shapeOk = field === "executables" ? Array.isArray(value) && value.every((v) => typeof v === "string") : value === null || (typeof value === "object" && !Array.isArray(value));
      if (!shapeOk) throw new Error(`${folder}/${field}.json: ${id}'s value is not a ${field}`);
      const row = [...table.harnesses, ...table.planned].find((r) => r.id === id);
      if (row === undefined) throw new Error(`${folder}/${field}.json names ${id}, which index.json does not`);
      if (Object.hasOwn(row, field)) throw new Error(`${id}.json sets ${field}, which ${folder}/${field}.json owns`);
      row[field] = value;
    }
  }
}

export function loadPresetTable(dir: string = PRESETS_DIR): PresetTable {
  const index = JSON.parse(readFileSync(join(dir, "index.json"), "utf8")) as { $comment?: string; version: number; harnesses: string[]; planned: string[] };
  const files = new Set(readdirSync(dir).filter((f) => f.endsWith(".json") && f !== "index.json").map((f) => f.slice(0, -".json".length)));
  const seen = new Set<string>();
  const list = (ids: string[]): Record<string, unknown>[] =>
    ids.map((id) => {
      if (seen.has(id)) throw new Error(`index.json: ${id} listed twice`);
      seen.add(id);
      if (!files.has(id)) throw new Error(`index.json names ${id}, which has no row file`);
      const row = JSON.parse(readFileSync(join(dir, `${id}.json`), "utf8")) as Record<string, unknown>;
      if (row.id !== id) throw new Error(`${id}.json: its id is not ${id}`);
      return row;
    });
  const table: PresetTable = { version: index.version, harnesses: list(index.harnesses), planned: list(index.planned) };
  if (index.$comment !== undefined) table.$comment = index.$comment;
  for (const f of files) if (!seen.has(f)) throw new Error(`${f}.json is in no list of index.json`);
  const wave5 = join(dir, "wave5");
  const present = existsSync(wave5) ? readdirSync(wave5).filter((f) => f.endsWith(".json")).sort() : [];
  const known = WAVE5_FIELDS.map((f) => `${f}.json`);
  for (const f of present) if (!known.includes(f)) throw new Error(`wave5/${f} is not a wave 5 table`);
  mergeWave5(
    table,
    WAVE5_FIELDS.filter((f) => present.includes(`${f}.json`)).map((field) => ({ field, text: readFileSync(join(wave5, `${field}.json`), "utf8") })),
  );
  const wave6 = join(dir, "wave6");
  const present6 = existsSync(wave6) ? readdirSync(wave6).filter((f) => f.endsWith(".json")).sort() : [];
  const known6 = WAVE6_FIELDS.map((f) => `${f}.json`);
  for (const f of present6) if (!known6.includes(f)) throw new Error(`wave6/${f} is not a wave 6 table`);
  mergeWave5(
    table,
    WAVE6_FIELDS.filter((f) => present6.includes(`${f}.json`)).map((field) => ({ field, text: readFileSync(join(wave6, `${field}.json`), "utf8") })),
  );
  return table;
}
