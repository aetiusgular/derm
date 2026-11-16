// node tests/cli-contract/lib/pty.selftest.mjs: scriptArgs gives this OS's
// script(1) a line it runs on a terminal, with the line's exit status
// (MW6R4-2: the util-linux form refused on macOS).
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import assert from "node:assert/strict";
import { scriptArgs } from "./pty.mjs";

assert.deepEqual(scriptArgs("x", "linux"), ["-qec", "x", "/dev/null"]);
assert.deepEqual(scriptArgs("x", "darwin"), ["-q", "/dev/null", "/bin/sh", "-c", "x"]);

if (!existsSync("/usr/bin/script")) {
  console.log("pty selftest: shapes ok; no /usr/bin/script to run");
  process.exit(0);
}
const tty = spawnSync("/usr/bin/script", scriptArgs("test -t 0 && echo on-a-tty; exit 3"), { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
assert.match(tty.stdout ?? "", /on-a-tty/, `stdout ${JSON.stringify(tty.stdout)} stderr ${JSON.stringify(tty.stderr)}`);
assert.equal(tty.status, 3, `exit ${tty.status}`);
console.log("pty selftest: ok (" + process.platform + ")");
