#!/usr/bin/env node
// Self-test for lane-scope.mjs: one throwaway commit per rule, in a scratch
// repository under the OS temp folder. Run: node scripts/lane-scope.test.mjs
// Exit 0 when every case gets the expected exit code and message.

import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const script = join(dirname(fileURLToPath(import.meta.url)), "lane-scope.mjs");
const repo = mkdtempSync(join(tmpdir(), "derm-scope-"));
const git = (...a) => execFileSync("git", a, { cwd: repo, encoding: "utf8" });
const write = (p, text) => {
  mkdirSync(dirname(join(repo, p)), { recursive: true });
  writeFileSync(join(repo, p), text);
};

const cargo = `[package]
name = "derm-cli"

[features]
default = []
# [lane-C]
fork-docker-mcp = []
# [lane-D]
# [lane-5bA]
# [lane-5bB]

[dependencies]
derm-core = { path = "../derm-core" }
# [lane-C]
# [lane-D]

[dev-dependencies]
# [lane-C]
# [lane-D]
`;

const coreCargo = `[package]
name = "derm-core"

[dependencies]
serde = "1"
# [lane-X]
# [lane-Z]
`;

git("init", "-q", "-b", "main");
git("config", "user.name", "scope test");
git("config", "user.email", "scope@test.invalid");
for (const [p, t] of Object.entries({
  "crates/derm-cli/Cargo.toml": cargo,
  "crates/derm-cli/src/main.rs": "fn main() {}\n",
  "crates/derm-cli/src/connect/mod.rs": "// c\n",
  "crates/derm-cli/src/run/mod.rs": "// d\n",
  "crates/derm-cli/src/hook/mod.rs": "// hook\n",
  "crates/derm-cli/src/hook/claude_format/mod.rs": "// a\n",
  "crates/derm-cli/src/gate/core.rs": "// gate\n",
  "crates/derm-cli/src/gate/serve/mod.rs": "// c\n",
  "crates/derm-cli/tests/hook_cases_5bA.rs": "// red\n",
  "crates/derm-cli/tests/support/replay.rs": "// replay\n",
  "crates/derm-sysmon/src/lib.rs": "// e\n",
  "crates/derm-sysmon/tests/contract.rs": "// red\n",
  "crates/derm-daemon/src/lib.rs": "// b\n",
  "crates/derm-daemon/src/computer_use/mod.rs": "// k\n",
  "packages/derm-pi/extensions/gate.ts": "// a\n",
  "packages/derm-pi/extensions/memory.ts": "// k\n",
  "library/src/validate.ts": "// e\n",
  "crates/derm-cli/src/connect/presets/droid.json": "{}\n",
  "crates/derm-cli/src/connect/presets/continue.json": "{}\n",
  "packages/derm-hooks-claude-compat/src/core/policy.ts": "// core\n",
  "contracts/policy.md": "# p\n",
  // Wave 5 (the wave 5 base): its seams and its fixture folders.
  "contracts/events.md": "# e\n",
  "contracts/fixtures/tap/records.json": "[]\n",
  "contracts/fixtures/installs/cases.json": "{}\n",
  "crates/derm-cli/src/run/boundary/mod.rs": "// t\n",
  "crates/derm-daemon/src/approver/mod.rs": "// v\n",
  "packages/derm-claude-plugin/src/core/policy.ts": "// core\n",
  "packages/derm-claude-plugin/src/core/installs/index.ts": "// x\n",
  "crates/derm-core/Cargo.toml": coreCargo,
  "package.json": "{}\n",
  "README.md": "# r\n",
})) write(p, t);
git("add", "-A");
git("commit", "-q", "-m", "base");
const base = git("rev-parse", "HEAD").trim();

const cases = [
  ["own file edited (A)", "A", () => write("packages/derm-pi/extensions/gate.ts", "// a2\n"), 0, "clean"],
  ["new file in own folder (B)", "B", () => write("crates/derm-daemon/src/socket.rs", "// s\n"), 0, "clean"],
  ["new .test.ts in own folder (E)", "E", () => write("library/src/x.test.ts", "//\n"), 0, "clean"],
  ["new .test.tsx refused (A)", "A", () => write("packages/derm-pi/extensions/x.test.tsx", "//\n"), 1, "vitest collects only"],
  ["new .test.mjs refused (F)", "F", () => write("packages/derm-claude-plugin/x.test.mjs", "//\n"), 1, "vitest collects only"],
  ["another lane's file (C edits run/)", "C", () => write("crates/derm-cli/src/run/mod.rs", "// x\n"), 1, "owned by lane D"],
  ["excepted file (A edits memory.ts)", "A", () => write("packages/derm-pi/extensions/memory.ts", "// x\n"), 1, "owned by lane K"],
  // Lane U's since the wave 5 base (it was lane K's in wave 2).
  ["excepted folder (B edits computer_use)", "B", () => write("crates/derm-daemon/src/computer_use/mod.rs", "// x\n"), 1, "owned by lane U"],
  ["new file outside every lane", "D", () => write("docs/x.md", "x\n"), 1, "owned by no lane"],
  ["no-lane file: contracts", "B", () => write("contracts/policy.md", "# changed\n"), 1, "no lane edits this"],
  ["no-lane file: root package.json", "E", () => write("package.json", "{\"x\":1}\n"), 1, "no lane edits this"],
  ["no-lane file: main.rs", "C", () => write("crates/derm-cli/src/main.rs", "fn main() { }\n"), 1, "no lane edits this"],
  ["deleted file of another lane", "A", () => unlinkSync(join(repo, "library/src/validate.ts")), 1, "owned by lane E"],
  // Wave 4 (integration w2): a lane's preset files are its own by name, and
  // `except` takes them out of lane Q's connect/ folder.
  ["preset file of lane L edited by L", "L", () => write("crates/derm-cli/src/connect/presets/droid.json", "{\"id\":\"droid\"}\n"), 0, "clean"],
  ["preset file of lane L edited by Q", "Q", () => write("crates/derm-cli/src/connect/presets/droid.json", "{\"id\":\"droid\"}\n"), 1, "owned by lane C, L"],
  ["lane Q's own preset file", "Q", () => write("crates/derm-cli/src/connect/presets/continue.json", "{\"id\":\"continue\"}\n"), 0, "clean"],
  ["synced core copy edited by its package's lane", "L", () => write("packages/derm-hooks-claude-compat/src/core/policy.ts", "// changed\n"), 1, "owned by no lane"],
  ["shared Cargo.toml, own section (C)", "C", () => write("crates/derm-cli/Cargo.toml", cargo.replace("# [lane-C]\n# [lane-D]\n\n[dev", "# [lane-C]\nregex = \"=1.11.1\"\n# [lane-D]\n\n[dev")), 0, "clean"],
  ["shared Cargo.toml, C drops its feature flag", "C", () => write("crates/derm-cli/Cargo.toml", cargo.replace("fork-docker-mcp = []\n", "")), 0, "clean"],
  ["shared Cargo.toml, D drops C's feature flag", "D", () => write("crates/derm-cli/Cargo.toml", cargo.replace("fork-docker-mcp = []\n", "")), 1, "lane C's section changed"],
  ["shared Cargo.toml, own dev section (D)", "D", () => write("crates/derm-cli/Cargo.toml", cargo.replace(/# \[lane-D\]\n$/, "# [lane-D]\ntempfile = \"=3.20.0\"\n")), 0, "clean"],
  ["shared Cargo.toml, other lane's section (C writes under D)", "C", () => write("crates/derm-cli/Cargo.toml", cargo.replace("# [lane-D]\n\n[dev", "# [lane-D]\nregex = \"=1.11.1\"\n\n[dev")), 1, "lane D's section changed"],
  ["shared Cargo.toml, outside sections", "D", () => write("crates/derm-cli/Cargo.toml", cargo.replace("derm-core =", "serde = \"1\"\nderm-core =")), 1, "changed outside"],
  ["shared Cargo.toml, marker removed", "C", () => write("crates/derm-cli/Cargo.toml", cargo.replace("# [lane-C]\n# [lane-D]\n\n[dev", "# [lane-D]\n\n[dev")), 1, "changed outside"],
  ["shared Cargo.toml, lane without a section (A)", "A", () => write("crates/derm-cli/Cargo.toml", cargo.replace("# [lane-C]\n# [lane-D]\n\n[dev", "# [lane-C]\nx = \"1\"\n# [lane-D]\n\n[dev")), 1, "has no section"],
  ["shared Cargo.toml, new section marker", "C", () => write("crates/derm-cli/Cargo.toml", cargo.replace("# [lane-C]\n# [lane-D]\n\n[dev", "# [lane-C]\n# [lane-E]\n# [lane-D]\n\n[dev")), 1, "changed outside"],
  // Wave 5 (the wave 5 base): the seams are whole folders, and a lane owns a
  // noLane path only by name.
  ["wave 5: lane T's run/boundary/", "T", () => write("crates/derm-cli/src/run/boundary/mod.rs", "// t2\n"), 0, "clean"],
  ["wave 5: run/ outside the seams is not T's", "T", () => write("crates/derm-cli/src/run/mod.rs", "// x\n"), 1, "owned by lane D, R"],
  ["wave 5: lane R no longer owns run/boundary/", "R", () => write("crates/derm-cli/src/run/boundary/mod.rs", "// x\n"), 1, "owned by lane T"],
  ["wave 5: lane V's approver/", "V", () => write("crates/derm-daemon/src/approver/mod.rs", "// v2\n"), 0, "clean"],
  ["wave 5: lane B no longer owns approver/", "B", () => write("crates/derm-daemon/src/approver/mod.rs", "// x\n"), 1, "owned by lane V"],
  ["wave 5: lane S's fixture folder in contracts/", "S", () => write("contracts/fixtures/tap/stream.json", "[]\n"), 0, "clean"],
  ["wave 5: the rest of contracts/ is still no lane's", "S", () => write("contracts/events.md", "# changed\n"), 1, "no lane edits this"],
  ["wave 5: lane X cannot edit lane S's fixtures", "X", () => write("contracts/fixtures/tap/records.json", "[1]\n"), 1, "no lane edits this"],
  ["wave 5: lane X's installs/ in the canonical core", "X", () => write("packages/derm-claude-plugin/src/core/installs/index.ts", "// x2\n"), 0, "clean"],
  ["wave 5: the core outside installs/ is not X's", "X", () => write("packages/derm-claude-plugin/src/core/policy.ts", "// x\n"), 1, "owned by lane F"],
  ["wave 5: lane F no longer owns core/installs/", "F", () => write("packages/derm-claude-plugin/src/core/installs/index.ts", "// f\n"), 1, "owned by lane X"],
  ["wave 5: derm-core's manifest, own section (X)", "X", () => write("crates/derm-core/Cargo.toml", coreCargo.replace("# [lane-X]\n", "# [lane-X]\nureq = \"=3.0.0\"\n")), 0, "clean"],
  ["wave 5: derm-core's manifest, another lane's section (Z writes under X)", "Z", () => write("crates/derm-core/Cargo.toml", coreCargo.replace("# [lane-X]\n", "# [lane-X]\nwindows = \"=0.61.0\"\n")), 1, "lane X's section changed"],
  // Wave 5b (the wave 5b base): lane names with digits, the gate's seams,
  // and the base's red tests, which no lane edits.
  ["wave 5b: lane 5bA's hook/claude_format/", "5bA", () => write("crates/derm-cli/src/hook/claude_format/mod.rs", "// a2\n"), 0, "clean"],
  ["wave 5b: hook/mod.rs is no lane's", "5bA", () => write("crates/derm-cli/src/hook/mod.rs", "// x\n"), 1, "owned by no lane"],
  ["wave 5b: lane 5bB cannot edit claude_format/", "5bB", () => write("crates/derm-cli/src/hook/claude_format/mod.rs", "// b\n"), 1, "owned by lane 5bA"],
  ["wave 5b: lane 5bC's gate/serve/", "5bC", () => write("crates/derm-cli/src/gate/serve/mod.rs", "// c2\n"), 0, "clean"],
  ["wave 5b: gate/ outside serve/ is no lane's", "5bC", () => write("crates/derm-cli/src/gate/core.rs", "// x\n"), 1, "owned by no lane"],
  ["wave 5b: the red tests are no lane's", "5bA", () => write("crates/derm-cli/tests/hook_cases_5bA.rs", "// x\n"), 1, "no lane edits this"],
  ["wave 5b: the replay harness is no lane's", "5bB", () => write("crates/derm-cli/tests/support/replay.rs", "// x\n"), 1, "no lane edits this"],
  ["wave 5b: lane 5bE's crate", "5bE", () => write("crates/derm-sysmon/src/lib.rs", "// e2\n"), 0, "clean"],
  ["wave 5b: lane 5bE's red test is not its own", "5bE", () => write("crates/derm-sysmon/tests/contract.rs", "// x\n"), 1, "owned by no lane"],
  ["wave 5b: shared Cargo.toml, own section (5bA)", "5bA", () => write("crates/derm-cli/Cargo.toml", cargo.replace("# [lane-5bA]\n", "# [lane-5bA]\nx = []\n")), 0, "clean"],
  ["wave 5b: shared Cargo.toml, 5bB writes under 5bA", "5bB", () => write("crates/derm-cli/Cargo.toml", cargo.replace("# [lane-5bA]\n", "# [lane-5bA]\nx = []\n")), 1, "lane 5bA's section changed"],
];

let failed = 0;
for (const [name, lane, change, code, text] of cases) {
  git("checkout", "-q", "-B", "case", base);
  change();
  git("add", "-A");
  git("commit", "-q", "-m", name);
  const r = spawnSync("node", [script, lane, "--base", base], { cwd: repo, encoding: "utf8" });
  const out = r.stdout + r.stderr;
  const ok = r.status === code && out.includes(text);
  if (!ok) failed++;
  console.log(`${ok ? "ok  " : "FAIL"} ${name}: exit ${r.status} (want ${code})${ok ? "" : `\n${out}`}`);
}

for (const [name, argv, code] of [
  // "O" is never a lane (section 7a skips it). "Z" was the bad letter until
  // the wave 5 base made lane Z.
  ["bad lane letter", ["O", "--base", base], 2],
  ["bad wave 5b lane", ["5bG", "--base", base], 2],
  ["bad base", ["A", "--base", "no-such-commit"], 2],
  ["stray argument", ["A", "--frob"], 2],
]) {
  const r = spawnSync("node", [script, ...argv], { cwd: repo, encoding: "utf8" });
  const ok = r.status === code;
  if (!ok) failed++;
  console.log(`${ok ? "ok  " : "FAIL"} ${name}: exit ${r.status} (want ${code})`);
}

rmSync(repo, { recursive: true, force: true });
const total = cases.length + 4;
console.log(`${total - failed} of ${total} as expected`);
process.exit(failed ? 1 : 0);
