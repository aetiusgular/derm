// The agent-account installer's parts that need no root (accounts build,
// lane L2): names, labels, the contract's reader, the table it renders, the
// unit, and the dry runs. The parts that need root (real users, the loaded
// table, real sockets) are tests/root-e2e.sh, run as root on a throwaway
// machine; CI's runners are not used for that.
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir, userInfo } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const dir = new URL("./", import.meta.url).pathname;
const helper = join(dir, "accounts.py");
const py = (...args: string[]) => spawnSync("python3", ["-I", helper, ...args], { encoding: "utf8" });

// The reader as a library, to feed it files and shapes.
function shape(data: unknown): string | null {
  const out = execFileSync(
    "python3",
    [
      "-I",
      "-c",
      "import importlib.util,json,sys\n" +
        "s=importlib.util.spec_from_file_location('a',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)\n" +
        "print(json.dumps(m.anchor_shape_problem(json.loads(sys.argv[2]))))",
      helper,
      JSON.stringify(data),
    ],
    { encoding: "utf8" },
  );
  return JSON.parse(out) as string | null;
}

const account = (slug: string, uid: number, extra: Record<string, unknown> = {}) => ({
  name: `derm-${slug}`,
  uid,
  subscription: "Claude Max",
  home: `/var/lib/derm/agents/${slug}`,
  ...extra,
});

describe.skipIf(process.platform !== "linux")("agent accounts (Linux)", () => {
  it("takes slugs of a-z, 0-9 and - up to 15, the same on every system", () => {
    for (const ok of ["a", "max-1", "0", "-", "abcdefghijklmno", "agentx", "my-agent"]) expect(py("valid-slug", ok).status, ok).toBe(0);
    for (const bad of ["", "A", "x_y", "../a", "a b", "a.b", "abcdefghijklmnop", "é"]) {
      expect(py("valid-slug", bad).status, bad).toBe(1);
    }
    expect(py("valid-slug", "abcdefghijklmnop").stderr).toContain("20 characters");
    // derm-agent is wave 5's agents' user, derm-agents the group; a slug
    // starting agent- would make derm-agent-<x>, wave 5's sudoers file name.
    for (const reserved of ["agent", "agents", "agent-tonyg"]) {
      const r = py("valid-slug", reserved);
      expect(r.status, reserved).toBe(1);
      expect(r.stderr).toContain("reserved");
    }
  });

  it("takes a label shown as typed and refuses one that would not be", () => {
    for (const ok of ["Claude Max, personal", "ChatGPT Plus (work) ✓", "x".repeat(120)]) expect(py("valid-label", ok).status).toBe(0);
    for (const bad of ["", "a\nb", "a\u001b[31mb", "a‮b", "a​b", "x".repeat(121)]) expect(py("valid-label", bad).status).toBe(1);
  });

  it("reads the contract exactly as plans/parallel_build_accounts.md section 2 writes it", () => {
    const good = { version: 1, group: "derm-agents", accounts: [account("max1", 996), account("t2", 995)] };
    expect(shape(good)).toBeNull();
    expect(shape({ ...good, accounts: [] })).toBeNull();
    expect(shape({ ...good, owner: "x" })).toContain("exactly version, group and accounts");
    expect(shape({ ...good, version: true })).toContain("version");
    expect(shape({ ...good, version: 2 })).toContain("version");
    expect(shape({ ...good, group: "docker" })).toContain("group");
    expect(shape({ ...good, accounts: [account("a", 996, { shell: "/bin/sh" })] })).toContain("exactly name, uid");
    expect(shape({ ...good, accounts: [{ ...account("a", 996), home: "/home/a" }] })).toContain("home");
    expect(shape({ ...good, accounts: [{ ...account("a", 996), name: "root" }] })).toContain("derm-");
    expect(shape({ ...good, accounts: [account("a", 0)] })).toContain("uid");
    expect(shape({ ...good, accounts: [account("a", 996), account("b", 996)] })).toContain("twice");
    expect(shape({ ...good, accounts: [account("a", 996, { subscription: "a‮b" })] })).toContain("label");
  });

  it("refuses an accounts file root did not write, and says why", () => {
    const d = mkdtempSync(join(tmpdir(), "derm-l2-"));
    const f = join(d, "agents.json");
    writeFileSync(f, JSON.stringify({ version: 1, group: "derm-agents", accounts: [] }));
    const r = spawnSync(
      "python3",
      [
        "-I",
        "-c",
        "import importlib.util,sys\n" +
          "s=importlib.util.spec_from_file_location('a',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)\n" +
          "try:\n m.read_anchor(sys.argv[2]); print('read')\nexcept m.Refused as e: print(e)",
        helper,
        f,
      ],
      { encoding: "utf8" },
    );
    if (userInfo().uid === 0) expect(r.stdout).toContain("read");
    else expect(r.stdout).toContain("is not root's");
  });

  it("renders one table, uids sorted and once, every account by group and by uid", () => {
    const r = py("render", "--gid", "995", "--uid", "997", "--uid", "996", "--uid", "997");
    expect(r.status).toBe(0);
    const t = r.stdout;
    expect(t).toContain("elements = { 996, 997 }");
    expect(t).toContain("meta skgid 995 jump agents");
    expect(t).toContain("meta skuid @uids jump agents");
    expect(t).toContain("type filter hook output priority filter; policy accept;");
    // Loopback addresses only, DNS refused there too, the rest rejected.
    const chain = t.slice(t.indexOf("chain agents {"));
    const rules = chain.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#") && l !== "}" && !l.startsWith("chain"));
    expect(rules).toEqual([
      "meta l4proto { tcp, udp } th dport 53 counter reject with icmpx admin-prohibited",
      'oif "lo" ip daddr 127.0.0.0/8 accept',
      'oif "lo" ip6 daddr ::1 accept',
      "counter reject with icmpx admin-prohibited",
    ]);
    // Replaced whole in one transaction: add, delete, define.
    expect(t).toMatch(/^table inet derm_agents\ndelete table inet derm_agents\ntable inet derm_agents \{$/m);
    expect(py("render", "--gid", "995").status).toBe(1);
  });

  it("ties the unit to nftables.service, whose stop and reload flush the ruleset", () => {
    const unit = readFileSync(join(dir, "derm-agents-nft.service"), "utf8");
    for (const line of [
      "After=nftables.service",
      "PartOf=nftables.service",
      "ReloadPropagatedFrom=nftables.service",
      "Before=network-pre.target shutdown.target",
      "ExecStart=/usr/sbin/nft -f /etc/derm/agents.nft",
      "ExecStartPost=/usr/bin/python3 -I /usr/local/lib/derm/agents.py marker",
      "WantedBy=sysinit.target",
    ]) {
      expect(unit.split("\n")).toContain(line);
    }
  });

  const me = userInfo();
  // The owner must be a person's account (uid 1000 or more): CI's runner is.
  it.skipIf(me.uid < 1000)("prints every step and changes nothing in a dry run", () => {
    const owner = me.username;
    const r = spawnSync(join(dir, "install.sh"), ["--account", "max1", "--subscription", "Claude Max", "--owner", owner, "--dry-run"], {
      encoding: "utf8",
    });
    expect(r.status, r.stderr).toBe(0);
    for (const step of ["1. /usr/local/lib/derm/agents.py", "2. the group derm-agents", "3. the user derm-max1", "4. /etc/derm/agents.json", "5. /etc/derm/agents.nft", "6. /etc/systemd/system/derm-agents-nft.service", "7. /etc/tmpfiles.d/derm-accounts-", "8. /etc/sudoers.d/derm-max1"]) {
      expect(r.stdout).toContain(step);
    }
    expect(r.stdout).toContain(`${owner} ALL=(derm-max1) NOPASSWD:SETENV: ALL`);
    const u = spawnSync(join(dir, "uninstall.sh"), ["--account", "max1", "--dry-run"], { encoding: "utf8" });
    expect(u.status, u.stderr).toBe(0);
    expect(u.stdout).toContain("the user derm-max1");
  });

  it("refuses bad input before it asks or changes anything", () => {
    const r = spawnSync(join(dir, "install.sh"), ["--account", "../x", "--subscription", "x", "--owner", "nobody", "--dry-run"], { encoding: "utf8" });
    expect(r.status).toBe(1);
    expect(r.stdout).not.toContain("==");
    const u = spawnSync(join(dir, "uninstall.sh"), ["--account", "A", "--dry-run"], { encoding: "utf8" });
    expect(u.status).toBe(1);
  });
});
