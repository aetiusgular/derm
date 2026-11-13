// Ground truth for effect visibility (plan 6F (f); contracts/eval.md section 3): a
// recorder derm does not own, so a claim that derm saw an effect can be checked
// against something independent. On Linux this is `strace -f` plus an
// `-a always,io_uring` audit rule; this module is the strace half, which the cloud
// can run. Note AZ (F6, AZ-10): strace -f sees ordinary syscalls but misses
// io_uring entirely (0 of 20 io_uring opens in the box run), and costs 4x to 9x on a
// file-heavy workload; the audit `io_uring` rule (added on the box by E1 / step 0)
// catches io_uring opens and connects that strace cannot. Every truth run reports
// its own cost beside the numbers. Never a second syscall audit rule set: audit's
// first match takes the event, so it would steal derm's records or see nothing
// (box run, section 8.11).
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";

export function hasStrace() {
  return spawnSync("strace", ["-V"], { encoding: "utf8" }).status === 0;
}

// Run argv under strace -f, following children, tracing the syscalls an effect can
// come through. Returns observed effects: { what, path|host, pid } and the cost.
const SYSCALLS = "openat,open,connect,execve,clone,clone3,unlinkat,renameat,renameat2";

export function record(argv, { env, cwd, timeoutMs = 60_000 } = {}) {
  const t0 = process.hrtime.bigint();
  const r = spawnSync("strace", ["-f", "-y", "-e", `trace=${SYSCALLS}`, "-s", "200", ...argv], {
    env,
    cwd,
    encoding: "utf8",
    timeout: timeoutMs,
    maxBuffer: 128 * 1024 * 1024,
  });
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  const effects = parse(r.stderr ?? "");
  return { effects, costMs: ms, exit: r.status, stdout: r.stdout ?? "" };
}

// strace -f lines: `[pid N] openat(AT_FDCWD, "path", flags) = fd`,
// `connect(fd, {sa_family=AF_INET, ...}, ...) = ...`, `execve("prog", ...) = 0`,
// `clone(...) = childpid`. One effect per successful call.
export function parse(text) {
  const out = [];
  for (const raw of text.split("\n")) {
    const pidM = /^\[pid\s+(\d+)\]\s*/.exec(raw);
    const pid = pidM ? Number(pidM[1]) : null;
    const line = raw.replace(/^\[pid\s+\d+\]\s*/, "");
    let m;
    if ((m = /^openat?\([^,]*,\s*"((?:[^"\\]|\\.)*)"[^=]*=\s*(-?\d+)/.exec(line)) || (m = /^open\("((?:[^"\\]|\\.)*)"[^=]*=\s*(-?\d+)/.exec(line))) {
      if (Number(m[2]) >= 0) {
        const write = /O_WRONLY|O_RDWR|O_CREAT|O_APPEND/.test(line);
        out.push({ what: write ? "write" : "read", path: unescape(m[1]), pid });
      }
    } else if (/^connect\(/.test(line) && /sa_family=AF_INET6?/.test(line)) {
      // strace spells the address inet_addr("1.2.3.4") / inet_pton(..., "::1") /
      // sin6_addr=..."::1"; -y may decorate the fd. Take the first quoted IP.
      m = /inet_addr\("([^"]+)"\)|inet_pton\([^,]+,\s*"([^"]+)"\)|sin6?_addr=[^,]*?"([^"]+)"/.exec(line);
      out.push({ what: "connect", host: m ? m[1] ?? m[2] ?? m[3] : "inet", pid });
    } else if ((m = /^execve\("((?:[^"\\]|\\.)*)"/.exec(line)) && /=\s*0\s*$/.test(line)) {
      out.push({ what: "exec", path: unescape(m[1]), pid });
    } else if ((m = /^clone3?\(.*\)\s*=\s*(\d+)/.exec(line))) {
      out.push({ what: "fork", pid, child: Number(m[1]) });
    }
  }
  return out;
}

function unescape(s) {
  return s.replace(/\\(.)/g, (_, c) => ({ n: "\n", t: "\t", "\\": "\\", '"': '"' }[c] ?? c));
}

// Whether an observed set covers a scenario's declared hidden effects. A declared
// effect is covered if some observed effect of the same `what` matches its target
// (path suffix, host substring). Returns the per-declared-effect coverage.
export function cover(declared, observed) {
  return declared.map((d) => {
    const hit = observed.find((o) => {
      if (o.what !== d.what) return false;
      if (d.path) return o.path?.endsWith(d.path.replace(/^~\//, "")) || o.path?.includes(d.path.replace(/^~\//, ""));
      if (d.host) return o.host?.includes(d.host);
      return true;
    });
    return { ...d, seenByTruth: !!hit };
  });
}

// The audit io_uring rule the box run needs (note AZ AZ-10), as text for the runner
// to install (root) and for the doc. Never run from this module.
export const IO_URING_RULE = [
  "-a always,io_uring -S openat -k derm_eval_uring",
  "-a always,io_uring -S openat2 -k derm_eval_uring",
  "-a always,io_uring -S connect -k derm_eval_uring",
];

export const CAVEAT =
  "strace -f misses io_uring entirely (note AZ, F6: 0 of 20 io_uring opens on the box) and costs 4x to 9x on a file-heavy workload; the `-a always,io_uring` audit rule (E1, on the box) catches io_uring openat/openat2/connect that strace cannot, and io_uring reads and writes stay invisible to audit on kernel 7.0 (AZ-10).";

void existsSync;
