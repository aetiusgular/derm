// Lane T, phase 4 (Tony's O1 decision): derm's sbx kit for Claude Code, as
// far as a machine with no KVM can take it.
//
//   sbx-kit-claude-gate
//     1. `derm run claude-code --boundary sbx` with a fake sbx: derm builds
//        the kit and passes it to `sbx create` with --kit; the fake keeps a
//        copy (derm removes its own right after the create).
//     2. The kit's files/home/ is laid into /home/agent, as sbx does
//        (SPEC-v2 5.8), and its setup.install runs as root, as sbx runs it
//        (SPEC-v2 5.6): `sh /home/agent/.derm-kit/install.sh`.
//     3. The real Claude Code starts as the `agent` user, in the claude
//        kit's full access (`--dangerously-skip-permissions`, its
//        entrypoint) with DERM_FULL_ACCESS=1 (the kit's environment),
//        against the fake Messages server. The gate it runs is the one the
//        install registered in /etc/claude-code/managed-settings.json; no
//        plugin and no flag of derm's is on its command line.
//     Pass: a denied Bash is blocked with derm's rule, an asked Write is
//     denied with the full-access note and writes nothing, an allowed Read
//     runs.
//
// It needs root, makes a user named `agent`, and writes /etc/claude-code,
// /opt/derm-kit and /home/agent, so it runs only when DERM_KIT_ROOT_TEST=1
// is set, as root, in a throwaway machine (a cloud workspace, a container).
// It puts back an /etc/claude-code it found, removes what it made, and
// removes the user only if it made it. Never on your Mac or the box.
//
//   cargo build -p derm-cli
//   DERM_KIT_ROOT_TEST=1 DERM_BIN=<target>/debug/derm node tests/cli-contract/run.mjs \
//     --claude /tmp/cli/node_modules/.bin/claude --only sbx-kit-claude-gate

import { spawnSync } from "node:child_process";
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { startFakeMessages, textBlock, toolUse, lastUserText } from "../../lib/fakeMessages.mjs";
import { ClaudeSession } from "../../lib/claudeDriver.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../..");
const AGENT = "agent";

function dermBin() {
  for (const p of [process.env.DERM_BIN, path.join(ROOT, "target/release/derm"), path.join(ROOT, "target/debug/derm")]) {
    if (p && existsSync(p)) return p;
  }
  return null;
}

function sh(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { encoding: "utf8", ...opts });
  return { code: r.status, out: r.stdout ?? "", err: r.stderr ?? "" };
}

/** Tool results in the request that follows a tool_use, by tool_use_id. */
function toolResult(fake, id) {
  for (const r of [...fake.requests].reverse()) {
    for (const m of r.body?.messages ?? []) {
      for (const c of Array.isArray(m.content) ? m.content : []) {
        if (c?.type === "tool_result" && c.tool_use_id === id) {
          return typeof c.content === "string" ? c.content : JSON.stringify(c.content);
        }
      }
    }
  }
  return null;
}

function scripted(plan, used) {
  return (body) => {
    const last = (body?.messages ?? []).at(-1);
    if (last?.role === "user" && Array.isArray(last.content) && last.content.some((c) => c?.type === "tool_result")) return [textBlock("done")];
    const said = lastUserText(body);
    const p = Object.keys(plan).find((k) => new RegExp(`(^|\\s)${k}(\\s|$)`).test(said));
    if (!p) return [textBlock("ok")];
    const block = toolUse(plan[p].name, plan[p].input);
    used[p] = block.id;
    return [block];
  };
}

/** Step 1: the kit derm builds for a claude-code chat under sbx. */
function kitFromDerm(root) {
  const home = path.join(root, "host-home");
  const work = path.join(root, "host-work");
  const bin = path.join(root, "host-bin");
  const out = path.join(root, "kit");
  for (const d of [home, work, bin]) mkdirSync(d, { recursive: true });
  mkdirSync(path.join(home, ".derm"), { mode: 0o700 });
  const policy = {
    version: 1,
    rules: [
      { tool: "bash", action: "deny" },
      { tool: "write", action: "ask" },
      { tool: "read", action: "allow" },
    ],
  };
  writeFileSync(path.join(home, ".derm", "policy.json"), JSON.stringify(policy), { mode: 0o600 });
  const sbx = path.join(bin, "sbx");
  writeFileSync(
    sbx,
    [
      "#!/bin/sh",
      `echo "$*" >> '${path.join(root, "sbx-calls")}'`,
      'if [ "$1" = create ]; then',
      "  prev=",
      '  for a in "$@"; do',
      `    if [ "$prev" = --kit ]; then cp -R "$a" '${out}'; fi`,
      '    prev=$a',
      "  done",
      "fi",
      "exit 0",
    ].join("\n"),
  );
  chmodSync(sbx, 0o755);
  const PATH = [bin, path.dirname(process.execPath), "/usr/bin", "/bin"].join(":");
  const r = sh(dermBin(), ["run", "claude-code", "--boundary", "sbx", "--no-daemon", "--", "-p", "hi"], {
    cwd: work,
    env: { PATH, HOME: home, LANG: "C" },
    timeout: 60000,
  });
  const calls = existsSync(path.join(root, "sbx-calls")) ? readFileSync(path.join(root, "sbx-calls"), "utf8") : "";
  return { r, calls, out, policy };
}

export const checks = [
  {
    id: "sbx-kit-claude-gate",
    title: "derm's sbx kit: derm run builds it, its install registers the gate in managed settings, and the real Claude Code in full access runs it",
    harness: "claude",
    async run({ claudePath, version }) {
      if (process.env.DERM_KIT_ROOT_TEST !== "1") return { status: "skip", finding: "set DERM_KIT_ROOT_TEST=1 in a throwaway machine, as root (it makes a user and writes /etc/claude-code)" };
      if (typeof process.getuid !== "function" || process.getuid() !== 0) return { status: "skip", finding: "needs root" };
      if (!dermBin()) return { status: "skip", finding: "no derm binary (DERM_BIN, target/release, target/debug)" };
      for (const t of ["/usr/sbin/useradd", "/usr/sbin/userdel", "/usr/bin/setpriv"]) {
        if (!existsSync(t)) return { status: "skip", finding: `no ${t}` };
      }
      const base = existsSync("/var/tmp") ? "/var/tmp" : "/tmp";
      const root = mkdtempSync(path.join(base, "derm-kit-root-"));
      chmodSync(root, 0o755);
      const made = { user: false, etc: null, opt: false };
      const findings = [];
      let fake;
      let s;
      try {
        // 1. derm builds the kit.
        const k = kitFromDerm(root);
        const create = k.calls.split("\n").find((l) => l.startsWith("create ")) ?? "";
        if (!/ --kit \S*derm-sbx-kit-\S+ /.test(create) || !existsSync(path.join(k.out, "spec.yaml"))) {
          return { status: "fail", finding: `no kit on the create: ${JSON.stringify(create)}; derm: exit ${k.r.code} ${JSON.stringify(k.r.err.slice(-300))}` };
        }
        if (!/runs with derm's gate/.test(k.r.err)) findings.push("the start line did not say the gate is in the VM");
        const left = readdirSync(base).filter((n) => n.startsWith("derm-sbx-kit-"));
        if (left.length > 0) findings.push(`derm left its kit folder: ${left.join(", ")}`);

        // 2. The VM's side: the agent user, the kit's files, its install.
        if (sh("/usr/bin/getent", ["passwd", AGENT]).code !== 0) {
          const u = sh("/usr/sbin/useradd", ["-m", "-U", "-s", "/bin/sh", AGENT]);
          if (u.code !== 0) return { status: "fail", finding: `useradd: ${u.err}` };
          made.user = true;
        }
        if (existsSync("/etc/claude-code")) {
          made.etc = `/etc/claude-code.derm-kit-test-${process.pid}`;
          renameSync("/etc/claude-code", made.etc);
        }
        made.opt = !existsSync("/opt/derm-kit");
        cpSync(path.join(k.out, "files", "home"), "/home/agent", { recursive: true });
        sh("/usr/bin/chown", ["-R", `${AGENT}:${AGENT}`, "/home/agent/.derm-kit"]);
        const PATH = [path.dirname(process.execPath), "/usr/local/bin", "/usr/bin", "/bin"].join(":");
        const inst = sh("/bin/sh", ["/home/agent/.derm-kit/install.sh"], { env: { PATH, LANG: "C" }, timeout: 60000 });
        if (inst.code !== 0) return { status: "fail", finding: `install.sh exit ${inst.code}: ${inst.err.slice(-400)}` };
        const managed = JSON.parse(readFileSync("/etc/claude-code/managed-settings.json", "utf8"));
        const pre = managed.hooks?.PreToolUse?.[0]?.hooks?.[0];
        if (pre?.onFailure !== "block" || pre?.args?.at(-1) !== "pre") findings.push(`managed PreToolUse: ${JSON.stringify(pre)}`);
        const st = statSync("/home/agent/.derm/policy.json");
        const agentUid = Number(sh("/usr/bin/id", ["-u", AGENT]).out.trim());
        if (st.uid !== agentUid || (st.mode & 0o022) !== 0) findings.push("the policy in the VM is not the agent's own, or is writable by others");
        if (statSync("/opt/derm-kit/src/hook.ts").uid !== 0) findings.push("the gate's code is not root's");
        // W5C-S2: the marker the hook's VM route needs, root's alone, and the
        // installed hook's own check holds on it.
        const marker = statSync("/opt/derm-kit/sbx-vm");
        if (marker.uid !== 0 || (marker.mode & 0o022) !== 0) findings.push("the VM marker is not root's alone");
        const held = sh(process.execPath, ["--input-type=module", "-e", 'const m = await import("/opt/derm-kit/src/core/daemon.ts"); process.exit(m.vmMarker() === undefined ? 0 : 1);']);
        if (held.code !== 0) findings.push(`the installed hook does not take the VM marker: ${held.err.slice(-200)}`);
        if (existsSync("/home/agent/.derm-kit")) findings.push("the install left its staging folder");

        // 3. The real Claude Code, as the agent user, in full access.
        const wrapper = path.join(root, "claude-as-agent");
        writeFileSync(wrapper, `#!/bin/sh\nexec /usr/bin/setpriv --reuid=${AGENT} --regid=${AGENT} --init-groups '${claudePath}' "$@"\n`);
        chmodSync(wrapper, 0o755);
        const dirs = { root: path.join(root, "agent-root"), home: "/home/agent", work: path.join(root, "agent-work") };
        for (const d of [dirs.root, dirs.work]) {
          mkdirSync(d, { recursive: true });
          sh("/usr/bin/chown", [`${AGENT}:${AGENT}`, d]);
        }
        mkdirSync(path.join(dirs.root, "claude-config"), { recursive: true });
        sh("/usr/bin/chown", [`${AGENT}:${AGENT}`, path.join(dirs.root, "claude-config")]);
        writeFileSync(path.join(dirs.work, "note.txt"), "plain note\n");
        sh("/usr/bin/chown", [`${AGENT}:${AGENT}`, path.join(dirs.work, "note.txt")]);
        const used = {};
        fake = await startFakeMessages({
          script: scripted(
            {
              "deny-bash": { name: "Bash", input: { command: "echo hi", description: "say hi" } },
              "ask-write": { name: "Write", input: { file_path: path.join(dirs.work, "new.txt"), content: "x\n" } },
              "allow-read": { name: "Read", input: { file_path: path.join(dirs.work, "note.txt") } },
            },
            used,
          ),
        });
        s = new ClaudeSession({
          claudePath: wrapper,
          dirs,
          baseUrl: fake.baseUrl,
          settings: { env: { ENABLE_TOOL_SEARCH: "false" } },
          args: ["--dangerously-skip-permissions"],
          env: { DERM_FULL_ACCESS: "1", IS_SANDBOX: "1" },
        });
        await s.send("deny-bash");
        await s.send("ask-write");
        await s.send("allow-read");
        const deny = toolResult(fake, used["deny-bash"]) ?? "";
        const ask = toolResult(fake, used["ask-write"]) ?? "";
        const allow = toolResult(fake, used["allow-read"]) ?? "";
        if (!deny.includes("derm: rule bash")) findings.push(`Bash not denied by derm: ${JSON.stringify(deny.slice(0, 200))}`);
        if (existsSync(path.join(dirs.work, "new.txt")) || !/full access/.test(ask)) findings.push(`Write not denied as full access: ${JSON.stringify(ask.slice(0, 200))}`);
        if (!allow.includes("plain note")) findings.push(`Read did not run: ${JSON.stringify(allow.slice(0, 200))}`);
        if (findings.length > 0) return { status: "fail", finding: `${findings.join("; ")}; stderr ${JSON.stringify(s.stderr.slice(-300))}` };
        return {
          status: "pass",
          finding: `derm built the kit; its install registered the gate (root's /opt/derm-kit, managed settings, the agent's own policy); Claude Code ${(version ?? "").match(/\d+\.\d+\.\d+/)?.[0] ?? "?"} as ${AGENT} in full access: Bash denied by derm's rule, an asked Write denied, an allowed Read ran`,
        };
      } catch (e) {
        return { status: "fail", finding: `${e.message}; ${findings.join("; ")}` };
      } finally {
        if (s) await s.close();
        if (fake) await fake.close();
        rmSync("/etc/claude-code", { recursive: true, force: true });
        if (made.etc) renameSync(made.etc, "/etc/claude-code");
        if (made.opt) rmSync("/opt/derm-kit", { recursive: true, force: true });
        // The VM marker never stays on this machine, whoever made the folder
        // (re-review W5R-7): with it, a hook here would take the VM route.
        else rmSync("/opt/derm-kit/sbx-vm", { force: true });
        rmSync("/home/agent/.derm", { recursive: true, force: true });
        rmSync("/home/agent/.derm-kit", { recursive: true, force: true });
        if (made.user) sh("/usr/sbin/userdel", ["-r", AGENT]);
        rmSync(root, { recursive: true, force: true });
      }
    },
  },
];
