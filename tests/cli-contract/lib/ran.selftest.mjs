// node tests/cli-contract/lib/ran.selftest.mjs
// BW5B-R4 (box test w5b retest, item 6): `native-hermes-allow` failed on its
// own predicate when the allowed call ran, because Hermes v0.22.5's terminal
// tool returns its output inside JSON with no newline. Played back against
// the reply recorded from the real Hermes.
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ranText } from "./ran.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const fx = JSON.parse(readFileSync(path.join(here, "..", "checks", "5bB", "fixtures", "hermes-terminal-0.22.5.json"), "utf8"));
const check = (what, got, want) => {
  if (got !== want) {
    console.error(`FAIL ${what}: ${got}, wanted ${want}`);
    process.exitCode = 1;
  } else console.log(`ok ${what}`);
};
check("hermes allowed reply ran", ranText(fx.allowed, "hermes-5bb-allowed"), true);
check("hermes denied reply did not run", ranText(fx.denied, "hermes-5bb-allowed"), false);
check("a marker only mentioned in an output line did not run", ranText(JSON.stringify({ output: "echo hermes-5bb-allowed-not" }), "hermes-5bb-allowed"), false);
check("a shell line with its newline ran", ranText("crush-5bb-allowed\n", "crush-5bb-allowed"), true);
check("an escaped newline ran", ranText("\"goose-5bb-allowed\\n\"", "goose-5bb-allowed"), true);
