#!/usr/bin/env node
// Renders the Homebrew formula from a release's SHA256SUMS.
//
//   node packaging/homebrew/render.mjs <version> <SHA256SUMS> [out]
//
// <version> is the tag without its "v" (0.1.0). The SHA256SUMS must hold the
// macOS zip and the Linux musl tarball of that version; anything missing, a
// malformed line or a version with characters a URL or Ruby string should not
// carry is refused. Writes to [out] or prints.
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

export function parseSums(text) {
  const sums = new Map();
  for (const line of text.split("\n")) {
    if (line.trim() === "") continue;
    const m = /^([0-9a-f]{64}) [ *](\S+)$/.exec(line);
    if (!m) throw new Error(`malformed SHA256SUMS line: ${JSON.stringify(line)}`);
    if (sums.has(m[2])) throw new Error(`${m[2]} listed twice`);
    sums.set(m[2], m[1]);
  }
  return sums;
}

export function render(version, sumsText, template = readFileSync(join(here, "derm.rb.in"), "utf8")) {
  if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$/.test(version)) {
    throw new Error(`version ${JSON.stringify(version)} is not x.y.z or x.y.z-pre`);
  }
  const sums = parseSums(sumsText);
  const want = {
    MACOS_SHA256: `derm-${version}-macos.zip`,
    LINUX_SHA256: `derm-${version}-x86_64-unknown-linux-musl.tar.gz`,
  };
  let out = template.replaceAll("@VERSION@", version);
  for (const [key, file] of Object.entries(want)) {
    const sha = sums.get(file);
    if (!sha) throw new Error(`SHA256SUMS has no ${file}`);
    out = out.replaceAll(`@${key}@`, sha);
  }
  const left = /@[A-Z0-9_]+@/.exec(out);
  if (left) throw new Error(`placeholder ${left[0]} not filled`);
  return out;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [version, sumsPath, outPath] = process.argv.slice(2);
  if (!version || !sumsPath) {
    console.error("usage: render.mjs <version> <SHA256SUMS> [out]");
    process.exit(2);
  }
  try {
    const formula = render(version, readFileSync(sumsPath, "utf8"));
    if (outPath) writeFileSync(outPath, formula);
    else process.stdout.write(formula);
  } catch (e) {
    console.error(`render.mjs: ${e.message}`);
    process.exit(1);
  }
}
