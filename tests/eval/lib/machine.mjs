// The host spec printed with every number (rules section 3; contracts/eval.md section 2).
import { readFileSync, existsSync } from "node:fs";
import os from "node:os";

export function machine(name = process.env.DERM_EVAL_MACHINE ?? "cloud") {
  let osName = `${os.type()} ${os.release()}`;
  if (existsSync("/etc/os-release")) {
    const m = /^PRETTY_NAME="?([^"\n]+)"?/m.exec(readFileSync("/etc/os-release", "utf8"));
    if (m) osName = m[1];
  }
  const cpus = os.cpus();
  return {
    name,
    os: osName,
    kernel: os.release(),
    cpu: `${cpus.length} x ${cpus[0]?.model ?? "unknown"}`,
    ram: `${Math.round(os.totalmem() / 2 ** 30)} GB`,
  };
}
