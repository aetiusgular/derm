// The extension's own second layer, policies/derm.toml. Gemini compiles each
// argsPattern as a JavaScript RegExp and matches it against the call's
// arguments as JSON, so these checks run in JavaScript, the engine Gemini
// uses. Until 19 Nov 2026 they sat in src/policyToml.test.ts beside the
// policy printer, which became `derm connect gemini --rules --print`
// (crates/derm-cli/src/connect/rules.rs, gemini_toml_full).
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("the extension's own policies/derm.toml", () => {
  // Gemini matches argsPattern as a JavaScript regex against the call's
  // arguments as JSON. Both deny rules name derm's folder and, since the
  // rename, the old name's, which derm never reads (rename review R1).
  const file = readFileSync(new URL("./policies/derm.toml", import.meta.url), "utf8");
  const patterns = [...file.matchAll(/^argsPattern = '([^']*)'$/gm)].map((m) => new RegExp(m[1] ?? ""));

  it("denies writes and shell text that name .derm/ or .tk/", () => {
    expect(patterns).toHaveLength(2);
    const [write, shell] = patterns as [RegExp, RegExp];
    for (const p of ["/home/u/.derm/policy.json", "/home/u/.tk/policy.json"]) {
      expect(write.test(JSON.stringify({ file_path: p, content: "{}" }))).toBe(true);
      expect(shell.test(JSON.stringify({ command: `cat ${p}` }))).toBe(true);
    }
    expect(write.test(JSON.stringify({ file_path: "/home/u/proj/tk/notes.md" }))).toBe(false);
    // The .tk web domain is not the old folder: a hard deny would refuse it
    // (the rename re-review, F3).
    expect(write.test(JSON.stringify({ file_path: "/home/u/site.tk/index.html" }))).toBe(false);
    expect(shell.test(JSON.stringify({ command: "curl https://example.tk/api" }))).toBe(false);
  });

  // The rename re-review's F2: the daemon's own folder.
  it("denies the daemon's token", () => {
    const [write, shell] = patterns as [RegExp, RegExp];
    for (const p of ["/run/user/1000/derm/daemon.token", "/run/user/1000/tk/daemon.token"]) {
      expect(shell.test(JSON.stringify({ command: `cat ${p}` })), p).toBe(true);
      expect(write.test(JSON.stringify({ file_path: p })), p).toBe(true);
    }
    expect(shell.test(JSON.stringify({ command: "ls /run/user/1000/derm/" }))).toBe(false);
  });

  // Gemini 0.66.0 drops a rule whose argsPattern fails isSafeRegExp
  // (bundle chunk-HJ5KJXNZ.js:292070-292083, transcribed): the pattern must
  // compile, be at most 2,048 characters, and not match its nested-quantifier
  // check. Integration w4's first F2 fix used `(?:[^"\\]|\\.)*` and Gemini
  // dropped both rules (contract checks gemini-derm-second-layer and
  // gemini-derm-fail-open, run on 0.66.0).
  it("passes Gemini's own isSafeRegExp, or Gemini drops the rule", () => {
    const sources = [...file.matchAll(/^argsPattern = '([^']*)'$/gm)].map((m) => m[1] ?? "");
    expect(sources).toHaveLength(2);
    const isSafeRegExp = (pattern: string) => {
      try {
        new RegExp(pattern);
      } catch {
        return false;
      }
      if (pattern.length > 2048) return false;
      return !/\([^)]*[*+?{].*\)[*+?{]/.test(pattern);
    };
    for (const p of sources) expect(isSafeRegExp(p), p).toBe(true);
    expect(isSafeRegExp('"x":"(?:[^"\\\\]|\\\\.)*y')).toBe(false);
  });
});
