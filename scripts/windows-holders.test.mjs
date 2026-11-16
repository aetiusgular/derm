#!/usr/bin/env node
// Self-test for windows-holders.mjs's rule. Run: node scripts/windows-holders.test.mjs
// Exit 0 when every case gets the expected problems.

import assert from "node:assert/strict";
import { problems } from "./windows-holders.mjs";

const files = ["a.test.ts", "b.test.ts"];
const fixtures = {
  "5bA": { cases: [{ id: "a_one", test: "a.test.ts :: one" }, { id: "a_two", test: "a.test.ts :: two" }] },
  "5bB": { cases: [] },
  manual: { cases: [{ test: "b.test.ts :: three", lane: "5bF", how: "ported by hand: x::y" }, { test: "b.test.ts :: four", lane: "5bF" }] },
};
const replays = { "5bA": new Set(["a_one"]), "5bB": new Set() };
const t = (file, name) => ({ file, name });

let n = 0;
const check = (label, tests, want) => {
  assert.deepEqual(problems({ files, tests, fixtures, replays }), want, label);
  n++;
};

check("held, replayed and ported", [t("a.test.ts", "one"), t("b.test.ts", "three")], []);
check("a test with no entry", [t("a.test.ts", "one"), t("b.test.ts", "three"), t("b.test.ts", "new")], ["no Rust holder: b.test.ts :: new"]);
check("a fixture case no Rust test replays", [t("a.test.ts", "two"), t("b.test.ts", "three")], [
  "5bA.json case a_two is not replayed in hook_cases_5bA.rs: a.test.ts :: two",
]);
check("a manual entry that says no port", [t("a.test.ts", "one"), t("b.test.ts", "four")], ["manual.json names no lane or no port: b.test.ts :: four"]);
check("a listed file with no tests", [t("a.test.ts", "one")], ["no tests listed in b.test.ts (moved or renamed? update scripts/windows-held.json)"]);
check("tests of other files are not judged", [t("a.test.ts", "one"), t("b.test.ts", "three"), t("c.test.ts", "x")], []);
console.log(`windows-holders self-test: ${n} of ${n} passed`);
