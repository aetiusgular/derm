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
  for (const shape of TOKEN_SHAPES) {
    out = out.replace(shape, () => {
      count++;
      return REDACTED;
    });
  }
  return { text: out, count };
}

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
