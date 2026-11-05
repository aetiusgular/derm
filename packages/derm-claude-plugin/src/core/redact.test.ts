// The core's redaction (redact.ts). Integration w4 replaced the two pair
// expressions with a linear scan (lane P's request 1, review P-S2): these
// tests hold the scan to the old expressions' output on random input, and
// pin its time on the crafted input that made the old ones take seconds.

import { describe, expect, it } from "vitest";
import { REDACTED, TOKEN_SHAPES, redactText, redactValue } from "./redact.ts";

// The expressions redact.ts used until integration w4 (824ae83), kept here as
// the oracle. Run only on short input: they are quadratic and worse.
const KEY = String.raw`[A-Za-z0-9_.-]*(?:token|secret|password|passwd|apikey|api_key|private_key)[A-Za-z0-9_.-]*`;
const OLD_QUOTED = new RegExp(String.raw`(["']${KEY}["']\s*:\s*)(["'])((?:\\.|(?!\2)[^\\])*)\2`, "gi");
const OLD_BARE = new RegExp(String.raw`(\b${KEY}\s*[=:]\s*)(?!\[redacted)([^\s&;"',}]+)`, "gi");

function oldRedactText(text: string): { text: string; count: number } {
  let count = 0;
  let out = text.replace(OLD_QUOTED, (_m, head: string, q: string, value: string) => {
    if (value === "" || value === REDACTED) return `${head}${q}${value}${q}`;
    count++;
    return `${head}${q}${REDACTED}${q}`;
  });
  out = out.replace(OLD_BARE, (m, head: string, value: string) => {
    if (/^[0-9]+$/.test(value)) return m;
    count++;
    return `${head}${REDACTED}`;
  });
  for (const shape of [...TOKEN_SHAPES, OLD_PEM]) {
    out = out.replace(shape, () => {
      count++;
      return REDACTED;
    });
  }
  return { text: out, count };
}

// The PEM shape as one expression, before integration w4's review (W4-S2):
// many BEGIN lines with no END made it quadratic (256 KB took 1.5 s). Since
// the re-review (W4-R6) a key with no END line is redacted to the end of the
// text, as derm-pi's own scan does (`|$`), so tool output cut short by `head`
// does not print it; the oracle carries the same `|$`.
const OLD_PEM = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)/g;

// Integration w5 continue (W5C-S9): OpenAI's key prefixes.
describe("OpenAI keys", () => {
  it("redacts project, service account and admin keys, and leaves look-alikes", () => {
    // Built at run time, and without OpenAI's marker, so no scanner reads a
    // fixture as a live key.
    const body = "abcdefghijklmnopqrstuvwx-_zABCDEFGHIJKLMNOP0123";
    for (const k of ["proj", "svcacct", "admin"].map((kind) => `sk-${kind}-${body}`)) {
      expect(redactText(`key ${k} end`), k).toEqual({ text: `key ${REDACTED} end`, count: 1 });
    }
    for (const t of ["sk-proj-short", "task-proj-abcdefghijklmnopqrstuvwxyz", "sk-project-plan", "sk-admin-dashboard-settings-page", "the sk-proj-management-overview-v2 folder"]) {
      expect(redactText(t).count, t).toBe(0);
    }
  });
});

describe("the PEM scan (review W4-S2)", () => {
  const parts = ["-----BEGIN ", "-----END ", "PRIVATE KEY-----", "RSA ", "EC ", "-----", "-", " ", "\n", "MIIB", "x", "PRIVATE KEY", "BEGIN", "END"];
  it("gives the old expression's output on 30,000 random strings of PEM fragments", () => {
    let seed = 7;
    const rand = (n: number) => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff), seed % n);
    for (let i = 0; i < 30_000; i++) {
      let t = "";
      const n = 1 + rand(12);
      for (let j = 0; j < n; j++) t += parts[rand(parts.length)];
      expect(redactText(t), JSON.stringify(t)).toEqual(oldRedactText(t));
    }
  });
  it("redacts a key cut off before its END line, to the end of the text (W4-R6)", () => {
    const cut = "ok\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n";
    expect(redactText(cut)).toEqual({ text: `ok\n${REDACTED}`, count: 1 });
  });
  it("redacts a whole key and keeps the text around it", () => {
    const key = "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----";
    expect(redactText(`a ${key} b ${key} c`)).toEqual({ text: `a ${REDACTED} b ${REDACTED} c`, count: 2 });
  });
  for (const [name, text] of [
    ["BEGIN lines with no END", "-----BEGIN PRIVATE KEY-----\n".repeat(9_000)],
    ["BEGIN lines and END lines that never close a key", "-----BEGIN PRIVATE KEY-----\n-----END X-----\n".repeat(6_000)],
    ["BEGIN headers that never finish", "-----BEGIN RSA PRIVATE KEY".repeat(10_000)],
  ] as [string, string][]) {
    it(`redacts 256 KB of ${name} in under 100 ms`, () => {
      const big = text.repeat(Math.ceil(256_000 / text.length)).slice(0, 256_000);
      redactText(big.slice(0, 1_000));
      const t0 = performance.now();
      redactText(big);
      const ms = performance.now() - t0;
      expect(ms, `${ms.toFixed(1)} ms`).toBeLessThan(100);
    });
  }
});

// A small deterministic generator, so a failure names its seed.
function rng(seed: number): () => number {
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
  "[REDACTED x", "é", " ", " ", "ghp_", "abcdefghijklmnopqrstuvwxyz0123456789", "--", "=v",
];

function randomText(next: () => number): string {
  const n = 1 + Math.floor(next() * 28);
  let s = "";
  for (let i = 0; i < n; i++) s += PIECES[Math.floor(next() * PIECES.length)];
  return s;
}

describe("redactText", () => {
  it("gives the old expressions' output on 30,000 random strings", () => {
    for (let seed = 1; seed <= 30_000; seed++) {
      const text = randomText(rng(seed));
      const want = oldRedactText(text);
      const got = redactText(text);
      expect(got, `seed ${seed}: ${JSON.stringify(text)}`).toEqual(want);
    }
  });

  it("keeps the documented cases", () => {
    expect(redactText(`{"api_token": "abc", "n": 1}`).text).toBe(`{"api_token": "${REDACTED}", "n": 1}`);
    expect(redactText(`curl -H 'x' --password=hunter2 && ls`).text).toBe(`curl -H 'x' --password=${REDACTED} && ls`);
    expect(redactText("max_tokens=1000").text).toBe("max_tokens=1000");
    expect(redactText(`"secret": "a\\"b"`).text).toBe(`"secret": "${REDACTED}"`);
    expect(redactText(`"secret": ""`)).toEqual({ text: `"secret": ""`, count: 0 });
    // A redacted value is not counted again.
    const once = redactText("TOKEN=abc").text;
    expect(redactText(once)).toEqual({ text: once, count: 0 });
  });

  // Lane P measured the old expressions: "token." × 500 (3,000 characters)
  // took 1.1 s, × 700 took 3.1 s, and a hook with a timeout let the call run.
  // 64 KB of each crafted shape, under 100 ms (the request's pin).
  const crafted: [string, string][] = [
    ["a run of secret-like words", "token.".repeat(10_923)],
    ["a run followed by a separator", "token.".repeat(10_922) + "x=v"],
    ["a quoted run with no closing quote", '"' + "secret-".repeat(9_362)],
    ["many quoted keys with unclosed values", `"token":"\\`.repeat(6_553)],
    ["alternating quotes", `'token':"`.repeat(7_281)],
    ["separators with no value", "password= ".repeat(6_553)],
    ["spaces before no separator", "api_key" + " ".repeat(65_000)],
  ];
  for (const [name, text] of crafted) {
    it(`redacts 64 KB of ${name} in under 100 ms`, () => {
      expect(text.length).toBeGreaterThanOrEqual(64_000);
      redactText(text.slice(0, 1_000)); // warm up
      const t0 = performance.now();
      const got = redactText(text);
      const ms = performance.now() - t0;
      expect(ms, `${ms.toFixed(1)} ms`).toBeLessThan(100);
      expect(typeof got.text).toBe("string");
    });
  }

  it("redacts a JSON value holding 64 KB of crafted text in under 100 ms", () => {
    const value = { command: "token.".repeat(10_923), env: { API_TOKEN: "x" }, args: ["secret-".repeat(9_362)] };
    const t0 = performance.now();
    const got = redactValue(value);
    expect(performance.now() - t0).toBeLessThan(100);
    expect((got.value as { env: { API_TOKEN: string } }).env.API_TOKEN).toBe(REDACTED);
  });
});
