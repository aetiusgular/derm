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
