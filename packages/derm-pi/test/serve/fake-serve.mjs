// A stand-in for `derm gate serve` (contracts/gate-serve.md), for the
// client's failure tests only: what it answers is set by FAKE_SERVE_MODE.
// The protocol itself is tested against the real binary in client.test.ts
// (`derm gate serve` from target/debug or DERM_BIN).
import { createInterface } from "node:readline";

const mode = process.env.FAKE_SERVE_MODE ?? "ok";
const rl = createInterface({ input: process.stdin });
let n = 0;
const say = (o) => process.stdout.write(`${JSON.stringify(o)}\n`);
rl.on("line", (line) => {
  n += 1;
  const r = JSON.parse(line);
  if (n === 1) {
    if (mode === "silent-hello") return;
    if (mode === "refuse-hello") return say({ id: r.id, ok: false, error: "no" });
    say({ id: r.id, ok: true, protocol: 1, policy: { loaded: true, problem: null } });
    if (mode === "exit-after-hello") setTimeout(() => process.exit(3), 10);
    return;
  }
  if (mode === "hang") return;
  if (mode === "garbage") return process.stdout.write("not json\n");
  if (mode === "wrong-id") return say({ id: 999, ok: true });
  if (mode === "die-on-request") {
    process.stderr.write("boom\n");
    process.exit(4);
  }
  if (r.op === "decide") return say({ id: r.id, ok: true, action: "allow", normalizedTool: r.call.tool, reason: "fake", updatedInput: null, redacted: 0, askTimeoutSeconds: 1 });
  say({ id: r.id, ok: true, echo: r });
});
