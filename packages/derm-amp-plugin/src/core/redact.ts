// Best-effort redaction of secret-like values (contracts/docker-args.md,
// section 2). It finds values whose key looks like a secret and a few
// well-known token shapes. It cannot find an arbitrary secret in text and is
// never presented as doing so. Canonical copy: packages/derm-claude-plugin/src/core/.

/** The fork's property-name pattern (dockerArgs.ts:38 at 159ef3e). */
export const SECRET_LIKE = /token|secret|password|passwd|apikey|api_key|private_key/i;

export const REDACTED = "[redacted by derm]";

/**
 * Token shapes with a fixed, documented prefix. Sources are listed in
 * plans/parallel/tk_lane_F.md, Research. Each is matched as a whole word-ish
 * run so ordinary text is left alone.
 */
export const TOKEN_SHAPES: readonly RegExp[] = [
  /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g, // GitHub classic and app tokens
  /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/g, // GitHub fine-grained personal access tokens
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, // AWS access key ids
  /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g, // Anthropic API keys
  /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g, // Slack tokens
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g, // PEM private keys (RFC 7468)
];

// Two pair forms are redacted, in this order:
//   "key": "value"   (JSON, also with single quotes; the value's quote closes it, `\` escapes)
//   key=value, key: value   (the value runs to whitespace, &, ;, a quote, `,` or `}`)
// where the key is a run of [A-Za-z0-9_.-] holding a secret-like word. Until
// integration w4 both were one regular expression each, with the key written
// `[A-Za-z0-9_.-]*(?:token|...)[A-Za-z0-9_.-]*`; on a long run holding many
// such words every word start retried the whole run, so the cost grew as
// len² × words ("token." × 700, 4,200 characters, took 3.1 s; lane P, P-S2).
// The key can only end where the run ends (the next character, a quote, `=`,
// `:` or a space, is outside the class), so the scan below takes each maximal
// run once, tests it for a secret-like word, and looks at what follows it:
// linear in the text. It gives the same output as the two expressions did
// (`redact.test.ts` holds it against them on random input).
const KEY_WORD = /token|secret|password|passwd|apikey|api_key|private_key/i;
const RUN = /[A-Za-z0-9_.-]+/g;
const QUOTED_SEP = /\s*:\s*/y;
const BARE_SEP = /\s*[=:]\s*/y;
const BARE_VALUE = /[^\s&;"',}]+/y;
const WORD_CHAR = /[A-Za-z0-9_]/;

function isQuote(c: string | undefined): c is '"' | "'" {
  return c === '"' || c === "'";
}

function stickyEnd(re: RegExp, text: string, at: number): number {
  re.lastIndex = at;
  return re.test(text) ? re.lastIndex : -1;
}

/** "key": "value" pairs: the value replaced, the rest kept. */
function redactQuoted(text: string): { text: string; count: number } {
  let count = 0;
  let out = "";
  let copied = 0;
  let pos = 0;
  RUN.lastIndex = 0;
  for (let m = RUN.exec(text); m !== null; m = RUN.exec(text)) {
    const s = m.index;
    const e = s + m[0].length;
    // The key's opening quote, not taken by an earlier pair.
    if (s - 1 < pos || !isQuote(text[s - 1]) || !isQuote(text[e]) || !KEY_WORD.test(m[0])) continue;
    const sepEnd = stickyEnd(QUOTED_SEP, text, e + 1);
    if (sepEnd < 0) continue;
    const q = text[sepEnd];
    if (!isQuote(q)) continue;
    // The value: escaped pairs and any character but the quote; `\` before a
    // line end ends it unclosed, as `\\.` without the s flag did.
    let i = sepEnd + 1;
    let closed = -1;
    while (i < text.length) {
      const c = text[i];
      if (c === "\\") {
        const n = text[i + 1];
        if (n === undefined || n === "\n" || n === "\r" || n === " " || n === " ") break;
        i += 2;
        continue;
      }
      if (c === q) {
        closed = i;
        break;
      }
      i++;
    }
    if (closed < 0) continue;
    const value = text.slice(sepEnd + 1, closed);
    if (value !== "" && value !== REDACTED) {
      out += text.slice(copied, sepEnd + 1) + REDACTED;
      copied = closed;
      count++;
    }
    pos = closed + 1;
    RUN.lastIndex = pos;
  }
  return { text: out + text.slice(copied), count };
}

/** key=value and key: value pairs: the value replaced, the rest kept. */
function redactBare(text: string): { text: string; count: number } {
  let count = 0;
  let out = "";
  let copied = 0;
  RUN.lastIndex = 0;
  for (let m = RUN.exec(text); m !== null; m = RUN.exec(text)) {
    const e = m.index + m[0].length;
    // `\b` before the key: the run needs a word character.
    if (!WORD_CHAR.test(m[0]) || !KEY_WORD.test(m[0])) continue;
    const sepEnd = stickyEnd(BARE_SEP, text, e);
    if (sepEnd < 0) continue;
    if (text.slice(sepEnd, sepEnd + 9).toLowerCase() === "[redacted") continue;
    const valueEnd = stickyEnd(BARE_VALUE, text, sepEnd);
    if (valueEnd < 0) continue;
    // `max_tokens=1000` is a count, not a secret.
    if (!/^[0-9]+$/.test(text.slice(sepEnd, valueEnd))) {
      out += text.slice(copied, sepEnd) + REDACTED;
      copied = valueEnd;
      count++;
    }
    RUN.lastIndex = valueEnd;
  }
  return { text: out + text.slice(copied), count };
}

export type Redaction = { text: string; count: number };

/** Redacts secret-like values in one string, in time linear in its length. */
export function redactText(text: string): Redaction {
  const quoted = redactQuoted(text);
  const bare = redactBare(quoted.text);
  let count = quoted.count + bare.count;
  let out = bare.text;
  for (const shape of TOKEN_SHAPES) {
    out = out.replace(shape, () => {
      count++;
      return REDACTED;
    });
  }
  return { text: out, count };
}

/**
 * Redacts every string inside a JSON value. An object key that is
 * secret-like has its string value replaced whole. Returns a new value.
 */
export function redactValue(value: unknown): { value: unknown; count: number } {
  let count = 0;
  const walk = (v: unknown, keyIsSecret: boolean): unknown => {
    if (typeof v === "string") {
      if (keyIsSecret && v !== "" && v !== REDACTED) {
        count++;
        return REDACTED;
      }
      const r = redactText(v);
      count += r.count;
      return r.text;
    }
    if (Array.isArray(v)) return v.map((x) => walk(x, keyIsSecret));
    if (typeof v === "object" && v !== null) {
      const out: Record<string, unknown> = {};
      for (const [k, x] of Object.entries(v)) out[k] = walk(x, SECRET_LIKE.test(k));
      return out;
    }
    return v;
  };
  const out = walk(value, false);
  return { value: out, count };
}
