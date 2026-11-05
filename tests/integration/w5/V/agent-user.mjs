#!/usr/bin/env node
// S2 part c end to end (wave 5 lane V): a chat with no boundary runs as the
// agents' user, the gate inside it reaches the person's daemon only through
// the chat's bridge, and the agent cannot reach the person's token, files,
// `sudo` or the approver.
//
// It changes the machine it runs on: it makes two users (an owner and an
// agents' user), runs packaging/linux/agent-user/install.sh, starts a daemon
// as the owner, and undoes all of it at the end (uninstall.sh, userdel). So
// it runs only as root, only on Linux, and is meant for a throwaway machine:
// a cloud workspace or a container. Never on the box or the Mac: there the
// box test w5 runs install.sh by hand, on Tony's yes.
//
//   sudo node tests/integration/w5/V/agent-user.mjs --bin <dir with derm and derm-daemon> [--core <hook core>] [--json]
//
// Needs the lane V request patches applied (V-1 passes the chat's context to
// run/user/, V-3 makes the gate trust its owner's files); without them the
// first checks fail and say which.

import { execFileSync, spawn, spawnSync } from "node:child_process";
import { chmodSync, cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const args = process.argv.slice(2);
const opt = (name, dflt) => {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] ? args[i + 1] : dflt;
};
const JSON_OUT = args.includes("--json");
const BIN = resolve(opt("--bin", join(ROOT, "target", "release")));
// The hook core the gate inside runs (V-3's checks live there).
const CORE = resolve(opt("--core", join(ROOT, "packages/derm-claude-plugin/src/core")));

if (process.platform !== "linux" || process.getuid() !== 0) {
  console.error("agent-user.mjs: needs root on Linux, on a throwaway machine (it makes and removes users)");
  process.exit(2);
}
for (const b of ["derm", "derm-daemon"]) {
  if (!existsSync(join(BIN, b))) {
    console.error(`missing ${join(BIN, b)}: cargo build --release first, or pass --bin`);
    process.exit(2);
  }
}

const OWNER = "dermv-owner";
const OWNER_UID = 1600;
const AGENT = "dermv-agent";
const OWNER_HOME = `/home/${OWNER}`;
const AGENT_HOME = `/var/lib/${AGENT}`;
const RUNTIME = `/run/user/${OWNER_UID}`;
const LIB = "/usr/local/lib/dermv"; // root's: derm, the daemon, the hook core
const PROJECT = "/srv/dermv-project";
const results = [];
const check = (name, ok, detail) => {
  results.push({ name, ok: Boolean(ok), detail });
  if (!JSON_OUT) console.log(`${ok ? "pass" : "FAIL"}  ${name}${detail ? `  (${detail})` : ""}`);
};
const sh = (cmd, a, o = {}) => spawnSync(cmd, a, { encoding: "utf8", ...o });
const asOwner = (a, o = {}) =>
  sh("runuser", ["-u", OWNER, "--", "env", "-i", `HOME=${OWNER_HOME}`, `USER=${OWNER}`, `XDG_RUNTIME_DIR=${RUNTIME}`,
    `PATH=${LIB}/bin:/usr/bin:/bin`, ...a], o);
const asAgent = (a) => sh("runuser", ["-u", AGENT, "--", ...a]);

// The agents' user's `pi`: records who it is and what it can reach, then
// runs the gate's own client from the hook core, as a hook would.
const AGENT_PI = `#!/bin/sh
out="$PWD/report.json"
try() { "$@" >/dev/null 2>&1 && echo readable || echo denied; }
tok=$(try cat ${RUNTIME}/derm/daemon.token)
rt=$(try ls ${RUNTIME})
oh=$(try ls ${OWNER_HOME})
sudo -n true >/dev/null 2>&1; s1=$?
sudo -n -u ${OWNER} true >/dev/null 2>&1; s2=$?
clean=true
for c in /proc/[0-9]*/cmdline; do
  if tr '\\0' ' ' < "$c" 2>/dev/null | grep -q -e "$DERM_CHAT_TOKEN" -e /run/derm-agent; then clean=false; fi
done
hook=$(node ${LIB}/hook.mjs 2>&1 | tail -1)
printf '{"uid":%s,"home":"%s","which":"%s","daemonToken":"%s","runtime":"%s","ownerHome":"%s","sudo":%s,"sudoOwner":%s,"groups":"%s","argvClean":%s,"hook":%s}\\n' \\
  "$(id -u)" "$HOME" "$(command -v pi)" "$tok" "$rt" "$oh" "$s1" "$s2" "$(id -nG)" "$clean" "\${hook:-null}" > "$out"
`;

// The gate's client, from the hook core (V-3's checks run for real).
const HOOK = `
import net from "node:net";
import { exchange } from "${LIB}/core/daemon.ts";
import { loadPolicy } from "${LIB}/core/policy.ts";
const out = {};
const loaded = loadPolicy(process.env.DERM_POLICY);
out.policyProblem = loaded.problem ?? null;
out.rules = loaded.policy.rules.length;
const ev = { id: "dermv-e2e-1", at: 0, chatId: "", harness: "pi", source: "adapter", kind: "tool.decision", summary: "bash ask", detail: {} };
const r1 = await exchange([{ op: "event", event: ev }], { client: "dermv", replyTimeoutMs: 3000, cwd: process.cwd() });
out.event = r1.replies ? r1.replies[0] : r1;
const r2 = await exchange([{ op: "approve", request: { id: "dermv-ask-1", chat: "", harness: "pi", tool: "bash", summary: "echo", timeoutSeconds: 3 } }], { client: "dermv", replyTimeoutMs: 6000, cwd: process.cwd() });
out.approve = r2.replies ? r2.replies[0] : r2;
const r3 = await exchange([{ op: "approver" }], { client: "dermv", replyTimeoutMs: 3000, cwd: process.cwd() });
out.approver = r3.replies ? r3.replies[0] : r3;
out.direct = await new Promise((res) => {
  const s = net.createConnection({ path: "${RUNTIME}/derm/daemon.sock" });
  s.on("connect", () => { s.destroy(); res("connected"); });
  s.on("error", () => res("unreachable"));
});
out.forged = await new Promise((res) => {
  const s = net.createConnection({ path: process.env.DERM_DAEMON_SOCKET });
  let got = "";
  s.on("connect", () => s.write(JSON.stringify({ op: "hello", token: "f".repeat(64), client: "x" }) + "\\n"));
  s.on("data", (d) => { got += d; });
  s.on("close", () => res(got ? "answered: " + got.slice(0, 80) : "closed"));
  s.on("error", () => res("error"));
  setTimeout(() => { s.destroy(); res(got ? "answered" : "closed"); }, 2000);
});
console.log(JSON.stringify(out));
`;

let daemon;
function cleanup() {
  if (daemon) daemon.kill("SIGTERM");
  sh(join(ROOT, "packaging/linux/agent-user/uninstall.sh"), ["--owner", OWNER, "--agent", AGENT]);
  sh("pkill", ["-KILL", "-u", OWNER]);
  sh("userdel", ["--remove", OWNER]);
  for (const p of [LIB, PROJECT, RUNTIME]) rmSync(p, { recursive: true, force: true });
  if (madeNode) rmSync("/usr/local/bin/node", { force: true });
}
// The agents' user runs the gate with node; put one on its PATH when the
// system has none there (removed at the end).
let madeNode = false;

try {
  cleanup();
  if (!existsSync("/usr/local/bin/node") && !existsSync("/usr/bin/node")) {
    execFileSync("ln", ["-s", process.execPath, "/usr/local/bin/node"]);
    madeNode = true;
  }
  // The owner: a person's account, home 0750 as Ubuntu makes it.
  execFileSync("useradd", ["--create-home", "--uid", String(OWNER_UID), "--shell", "/bin/bash", OWNER]);
  chmodSync(OWNER_HOME, 0o750);
  const inst = sh(join(ROOT, "packaging/linux/agent-user/install.sh"), ["--owner", OWNER, "--agent", AGENT, "--yes"]);
  check("install.sh sets up the agents' user", inst.status === 0, inst.status === 0 ? "" : inst.stderr.trim().slice(0, 300));
  const agentUid = Number(sh("id", ["-u", AGENT]).stdout.trim());

  // derm and the hook core where both users can run and read them; the
  // stand-in harness in the agents' user's own folder, as its own install.
  mkdirSync(`${LIB}/bin`, { recursive: true, mode: 0o755 });
  cpSync(join(BIN, "derm"), `${LIB}/bin/derm`);
  cpSync(join(BIN, "derm-daemon"), `${LIB}/bin/derm-daemon`);
  cpSync(CORE, `${LIB}/core`, { recursive: true });
  writeFileSync(`${LIB}/hook.mjs`, HOOK);
  sh("chmod", ["-R", "a+rX", LIB]);
  // The owner's own `pi` (derm run resolves it first) and the agent's.
  writeFileSync(`${LIB}/bin/pi`, "#!/bin/sh\necho the owner's pi must not run\nexit 9\n");
  chmodSync(`${LIB}/bin/pi`, 0o755);
  mkdirSync(`${AGENT_HOME}/.local/bin`, { recursive: true });
  writeFileSync(`${AGENT_HOME}/.local/bin/pi`, AGENT_PI);
  chmodSync(`${AGENT_HOME}/.local/bin/pi`, 0o755);
  sh("chown", ["-R", `${AGENT}:${AGENT}`, `${AGENT_HOME}/.local`]);

  // A folder both can write, outside the owner's home: the agents' group.
  mkdirSync(PROJECT, { recursive: true });
  sh("chown", [`${OWNER}:${AGENT}`, PROJECT]);
  chmodSync(PROJECT, 0o2770);

  // The owner's policy and runtime folder, then the daemon as the owner.
  mkdirSync(`${OWNER_HOME}/.derm`, { recursive: true, mode: 0o700 });
  writeFileSync(`${OWNER_HOME}/.derm/policy.json`, JSON.stringify({ version: 1, rules: [{ tool: "bash", action: "ask" }] }));
  chmodSync(`${OWNER_HOME}/.derm/policy.json`, 0o600);
  sh("chown", ["-R", `${OWNER}:${OWNER}`, `${OWNER_HOME}/.derm`]);
  mkdirSync(RUNTIME, { recursive: true, mode: 0o700 });
  sh("chown", [`${OWNER}:${OWNER}`, RUNTIME]);
  chmodSync(RUNTIME, 0o700);
  daemon = spawn("runuser", ["-u", OWNER, "--", "env", "-i", `HOME=${OWNER_HOME}`, `XDG_RUNTIME_DIR=${RUNTIME}`,
    "PATH=/usr/bin:/bin", `${LIB}/bin/derm-daemon`, "--foreground"], { stdio: "ignore" });
  for (let i = 0; i < 100 && !existsSync(`${RUNTIME}/derm/daemon.token`); i++) await new Promise((r) => setTimeout(r, 100));
  check("the daemon runs as the owner", existsSync(`${RUNTIME}/derm/daemon.token`));

  // The chat.
  const run = asOwner([`${LIB}/bin/derm`, "run", "pi", "--boundary", "none"], { cwd: PROJECT, timeout: 60_000 });
  check("derm run pi --boundary none exits 0", run.status === 0, `exit ${run.status}: ${(run.stderr || "").trim().slice(-400)}`);
  const report = existsSync(`${PROJECT}/report.json`) ? JSON.parse(readFileSync(`${PROJECT}/report.json`, "utf8")) : {};
  check("the harness ran as the agents' user, from its own install", report.uid === agentUid && report.which === `${AGENT_HOME}/.local/bin/pi`, JSON.stringify({ uid: report.uid, which: report.which }));
  check("HOME is the agents' user's, not the owner's", report.home === AGENT_HOME, report.home);
  check("the agent cannot read daemon.token", report.daemonToken === "denied", report.daemonToken);
  check("the agent cannot enter the owner's runtime folder or home", report.runtime === "denied" && report.ownerHome === "denied", `${report.runtime}, ${report.ownerHome}`);
  check("the agent cannot sudo, as root or as the owner", report.sudo !== 0 && report.sudoOwner !== 0, `${report.sudo}, ${report.sudoOwner}`);
  check("the agent is in no group but its own", report.groups === AGENT, report.groups);
  check("no chat token or bridge path in any argv the agent can see", report.argvClean === true, String(report.argvClean));
  const hook = report.hook ?? {};
  check("the gate reads the owner's policy copy (V-3)", hook.policyProblem === null && hook.rules === 1, JSON.stringify(hook.policyProblem));
  check("the gate's event reaches the daemon through the bridge", hook.event?.ok === true, JSON.stringify(hook.event));
  check("an ask with no approver is no at once", hook.approve?.answer === "no" && hook.approve?.by === "none", JSON.stringify(hook.approve));
  check("the chat's token cannot become an approver", typeof hook.approver?.error === "string" && hook.approver.error.includes("daemon scope"), JSON.stringify(hook.approver));
  check("the daemon's own socket is out of the agent's reach", hook.direct === "unreachable", hook.direct);
  check("a forged hello with another token never reaches the daemon", hook.forged === "closed", hook.forged);

  // What the daemon recorded.
  const rep = asOwner([`${LIB}/bin/derm`, "watch", "tail", "--since", "0", "--json"], { timeout: 5000 });
  const events = (rep.stdout || "").split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return {}; } });
  const start = events.find((e) => (e.event ?? e).kind === "run.start");
  const sd = (start?.event ?? start)?.detail ?? {};
  check("run.start names the agents' user", sd.agentUser?.user === AGENT && sd.agentUser?.uid === agentUid && sd.agentUser?.how === "sudo" && sd.runsAs === AGENT, JSON.stringify({ agentUser: sd.agentUser, runsAs: sd.runsAs }));
  check("the adapter event is in the chat's feed", events.some((e) => (e.event ?? e).id === "dermv-e2e-1"));
  const left = sh("ls", ["-A", `/run/derm-agent/${OWNER_UID}`]).stdout.trim();
  check("the chat's bridge is gone after the run", left === "", left);
} finally {
  cleanup();
  // Another owner's entry may stay in the shared file; this owner's must go.
  const anchor = existsSync("/etc/derm/agent-users.json") ? readFileSync("/etc/derm/agent-users.json", "utf8") : "";
  const gone = sh("id", [AGENT]).status !== 0 && !anchor.includes(`"ownerUid": ${OWNER_UID}`) && !existsSync(`/etc/sudoers.d/derm-agent-${OWNER}`);
  check("uninstall.sh leaves nothing behind", gone);
  const failed = results.filter((r) => !r.ok).length;
  if (JSON_OUT) console.log(JSON.stringify({ passed: results.length - failed, failed, results }, null, 2));
  else console.log(`${results.length - failed} of ${results.length} passed`);
  process.exitCode = failed ? 1 : 0;
}

