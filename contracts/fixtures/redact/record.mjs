// Records the hook core's redactor (packages/derm-claude-plugin/src/core/
// redact.ts) on the inputs redact.test.ts generates, so the Rust port
// (crates/derm-core/src/redact/hook.rs) is held to the TypeScript's output,
// not to a hand-written expectation (rules section 9, item 12).
//   node --experimental-strip-types contracts/fixtures/redact/record.mjs
// writes hook-cases.json beside this file. Recorded by the wave 5b base at
// e29ce27; run again only if redact.ts changes.

import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { REDACTED, redactText, redactValue } from "../../../packages/derm-claude-plugin/src/core/redact.ts";

const here = path.dirname(fileURLToPath(import.meta.url));

// redact.test.ts's generator, copied.
function rng(seed) {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const PIECES = [
  "token", "Token", "TOK", "en", "secret", "password", "api_key", "apikey", "private_key", "passwd",
  "max_tokens", "x", "A", "1", "42", ".", "-", "_", "=", ":", ": ", " ", "  ", "\t", "\n", "\r",
  '"', "'", "\\", '\\"', "\\'", "\\\n", "&", ";", ",", "}", "{", "[", "]", "[redacted", REDACTED,
  "[REDACTED x", "é", " ", " ", "ghp_", "abcdefghijklmnopqrstuvwxyz0123456789", "--", "=v",
];
function randomText(next) {
  const n = 1 + Math.floor(next() * 28);
  let s = "";
  for (let i = 0; i < n; i++) s += PIECES[Math.floor(next() * PIECES.length)];
  return s;
}
const PEM_PARTS = ["-----BEGIN ", "-----END ", "PRIVATE KEY-----", "RSA ", "EC ", "-----", "-", " ", "\n", "MIIB", "x", "PRIVATE KEY", "BEGIN", "END"];

function digest(cases) {
  const h = createHash("sha256");
  for (const [t, r] of cases) h.update(`${t}\u0000${r.text}\u0000${r.count}\n`, "utf8");
  return h.digest("hex");
}

const random = [];
for (let seed = 1; seed <= 30_000; seed++) {
  const t = randomText(rng(seed));
  random.push([t, redactText(t)]);
}
const pem = [];
let seed = 7;
const rand = (n) => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff), seed % n);
for (let i = 0; i < 30_000; i++) {
  let t = "";
  const n = 1 + rand(12);
  for (let j = 0; j < n; j++) t += PEM_PARTS[rand(PEM_PARTS.length)];
  pem.push([t, redactText(t)]);
}
const body = "abcdefghijklmnopqrstuvwx-_zABCDEFGHIJKLMNOP0123";
const named = [
  `{"api_token": "abc", "n": 1}`,
  `curl -H 'x' --password=hunter2 && ls`,
  "max_tokens=1000",
  `"secret": "a\\"b"`,
  `"secret": ""`,
  "TOKEN=abc",
  ...["proj", "svcacct", "admin"].map((k) => `key sk-${k}-${body} end`),
  "sk-proj-short", "task-proj-abcdefghijklmnopqrstuvwxyz", "sk-project-plan", "sk-admin-dashboard-settings-page", "the sk-proj-management-overview-v2 folder",
  "ok\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n",
  "a -----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY----- b -----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY----- c",
  `token ghp_${"a".repeat(36)} and gho_${"B".repeat(35)} and ghs_${"c".repeat(256)} and ghr_${"d".repeat(36)}_x`,
  `github_pat_${"a".repeat(22)} github_pat_${"b".repeat(21)}`,
  "AKIAABCDEFGHIJKLMNOP ASIA0123456789ABCDEF AKIAABCDEFGHIJKLMNOPQ xAKIAABCDEFGHIJKLMNOP",
  `sk-ant-${"a".repeat(20)}- sk-ant-${"a".repeat(19)} sk-ant-api03-${"Z".repeat(30)}--`,
  `xoxb-${"1".repeat(10)} xoxp-123-456-789abc- xoxz-${"1".repeat(12)}`,
].map((t) => [t, redactText(t)]);
const values = [
  { command: "echo hi", env: { API_TOKEN: "x", PLAIN: "token=abc" }, args: ["--password=p", { private_key: "" }], n: 3 },
  { url: "https://x?token=abc", headers: { Authorization: "Bearer ghp_" + "a".repeat(36) } },
].map((v) => {
  const r = redactValue(v);
  return { input: v, value: r.value, count: r.count };
});
const out = {
  source: "packages/derm-claude-plugin/src/core/redact.ts at e29ce27, recorded by contracts/fixtures/redact/record.mjs (wave 5b base, 10 Nov 2026)",
  marker: REDACTED,
  random: { count: random.length, sha256: digest(random), first: random.slice(0, 300).map(([t, r]) => ({ text: t, out: r.text, count: r.count })) },
  pem: { count: pem.length, sha256: digest(pem), first: pem.slice(0, 300).map(([t, r]) => ({ text: t, out: r.text, count: r.count })) },
  named: named.map(([t, r]) => ({ text: t, out: r.text, count: r.count })),
  values,
};
writeFileSync(path.join(here, "hook-cases.json"), `${JSON.stringify(out, null, 1)}\n`);
console.log(out.random.sha256, out.pem.sha256);
