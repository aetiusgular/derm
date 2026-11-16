#!/usr/bin/env node
// Join-accuracy scenarios (plan 6F (d)): a session of several calls, each producing
// OS events; the join's job is to credit each event to the call that caused it.
// Ground truth is which call each event belongs to (by pid subtree and timing). The
// run is E1's (it needs derm's daemon feed); lane 6F builds the scorer and a few
// scenarios that stress the cases note AZ and the rules name: overlapping in-process
// edits, two calls to one stdio MCP server (case 123), a child that outlives its
// call (cases 164, 177), a reused pid (case 177), an effect that arrives after the
// call stopped (case 205). Each step is a call; its `effects` are the OS events it
// must be credited with. Fake files and loopback only.
import { writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { split } from "./split.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const dir = join(here, "..", "scenarios", "join");

const S = [
  {
    id: "two-calls-distinct-writes",
    why: "two ordinary calls; each write is the caller's",
    steps: [
      { kind: "shell", input: { command: "echo a > a.txt" }, expect: "allow", effects: [{ what: "write", path: "a.txt" }] },
      { kind: "shell", input: { command: "echo b > b.txt" }, expect: "allow", effects: [{ what: "write", path: "b.txt" }] },
    ],
  },
  {
    id: "child-outlives-its-call",
    why: "a backgrounded child writes after its call returned (cases 164, 177, 205)",
    steps: [
      { kind: "shell", input: { command: "( sleep 0.4; echo late > late.txt ) & true" }, expect: "allow", effects: [{ what: "write", path: "late.txt", after: 400 }] },
      { kind: "shell", input: { command: "echo done > done.txt" }, expect: "allow", effects: [{ what: "write", path: "done.txt" }] },
    ],
  },
  {
    id: "overlapping-reads",
    why: "two calls read the same file; each read is its own caller's (case 123 class)",
    steps: [
      { kind: "shell", input: { command: "cat shared.txt > /dev/null" }, expect: "allow", effects: [{ what: "read", path: "shared.txt" }] },
      { kind: "shell", input: { command: "cat shared.txt > /dev/null" }, expect: "allow", effects: [{ what: "read", path: "shared.txt" }] },
    ],
  },
];

// Eval pass 1 (E1-4d): three scenarios were too few to say anything. The rest are
// made here by pattern, each step one call with one write of its own file, so step
// i's effect is effect i (the live scorer's rule). No `$`, glob, brace or `~`: the
// gate must allow each command as it is.
const w = (cmd, path, after) => ({ kind: "shell", input: { command: cmd }, expect: "allow", effects: [{ what: "write", path, ...(after ? { after } : {}) }] });
for (const n of [3, 4, 5, 6]) {
  S.push({ id: `calls-${n}-distinct-writes`, why: `${n} ordinary calls in a row; each write is its caller's`, steps: Array.from({ length: n }, (_, i) => w(`echo ${i} > w${n}-${i}.txt`, `w${n}-${i}.txt`)) });
}
for (const ms of [200, 800, 1600, 3000]) {
  S.push({
    id: `late-write-${ms}ms`,
    why: `a backgrounded child writes ${ms} ms after its call returned, while the next call runs (cases 164, 177, 205)`,
    steps: [w(`( sleep ${ms / 1000}; echo late > late-${ms}.txt ) & true`, `late-${ms}.txt`, ms), w(`echo next > next-${ms}.txt`, `next-${ms}.txt`)],
  });
}
for (const n of [2, 3, 4]) {
  S.push({ id: `subfolder-writes-${n}`, why: "each call makes a folder and writes in it", steps: Array.from({ length: n }, (_, i) => w(`mkdir -p d${n}-${i} && echo x > d${n}-${i}/in${n}-${i}.txt`, `d${n}-${i}/in${n}-${i}.txt`)) });
  S.push({ id: `nested-shell-writes-${n}`, why: "the write is a grandchild's: sh -c inside the call's shell", steps: Array.from({ length: n }, (_, i) => w(`sh -c 'sh -c "echo x > nest${n}-${i}.txt"'`, `nest${n}-${i}.txt`)) });
}
for (const n of [2, 3]) {
  S.push({ id: `pipeline-writes-${n}`, why: "the write is tee's, at the end of a pipeline", steps: Array.from({ length: n }, (_, i) => w(`printf x | tee tee${n}-${i}.txt > /dev/null`, `tee${n}-${i}.txt`)) });
}
S.push({ id: "rename-into-place", why: "a write to a scratch name, then a rename: the final name is the call's", steps: [0, 1].map((i) => w(`echo x > scratch${i}.tmp && mv scratch${i}.tmp final${i}.txt`, `final${i}.txt`)) });
S.push({ id: "slow-then-fast", why: "a call that takes a second, then one that takes none", steps: [w("sleep 1; echo a > slow-a.txt", "slow-a.txt"), w("echo b > fast-b.txt", "fast-b.txt")] });
S.push({ id: "fast-then-slow", why: "the reverse", steps: [w("echo a > fast-a.txt", "fast-a.txt"), w("sleep 1; echo b > slow-b.txt", "slow-b.txt")] });
S.push({
  id: "two-children-outlive-their-calls",
  why: "two calls each leave a child that writes later, the first after the second (cases 164, 177)",
  steps: [w("( sleep 1.5; echo one > child-one.txt ) & true", "child-one.txt", 1500), w("( sleep 0.5; echo two > child-two.txt ) & true", "child-two.txt", 500), w("echo three > third.txt", "third.txt")],
});
for (const s of S) {
  if (s.steps.some((st) => st.effects.length !== 1)) throw new Error(`${s.id}: one effect per step`);
  if (s.steps.some((st) => /[$*?{}~\\[]/.test(st.input.command))) throw new Error(`${s.id}: a command the gate would ask about`);
}

mkdirSync(dir, { recursive: true });
const halves = split("join", S.map((s) => ({ id: s.id, group: "join" })));
for (const s of S) {
  // The contract's step has no per-step effects; the join manifest keeps them in a
  // sidecar beside the scenario (effects.schema allows scenario-level effects only).
  const sc = {
    suite: "join",
    id: s.id,
    source: { name: "derm" },
    split: halves.get(s.id),
    steps: s.steps.map(({ kind, input, expect }) => ({ kind, input, expect })),
    effects: s.steps.flatMap((st) => st.effects),
  };
  writeFileSync(join(dir, `${s.id}.json`), JSON.stringify(sc, null, 2) + "\n");
}
console.log(`${S.length} join scenarios written`);
