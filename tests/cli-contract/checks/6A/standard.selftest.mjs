// node tests/cli-contract/checks/6A/standard.selftest.mjs
// Box test w6 retest, BW6R-2: the Standard tier's Claude Code checks take
// derm's refusal (BW6-1) as their pass where this host kills Claude Code's
// sandboxed commands, read the way `contracts_w6.rs` reads it, for the PATH
// the check gives derm. Each case is the facts of one host.
import { hostKillsClaudeCommands } from "./standard.mjs";

const host = (o) => ({
  platform: o.platform ?? "linux",
  exists: (p) => (o.files ?? []).includes(p),
  read: (p) => {
    if (p in (o.reads ?? {})) return o.reads[p];
    throw new Error("ENOENT");
  },
  real: (p) => (o.real ?? {})[p] ?? p,
});
const PROFILE = "/etc/apparmor.d/bwrap-userns-restrict";
const SYSCTL = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";
const COPY = "/usr/local/libexec/derm-srt";
const cases = [
  ["Ubuntu's profile with /usr/bin/bwrap first (the box, stock)", "/b:/usr/bin", { files: [PROFILE, "/usr/bin/bwrap"] }, true],
  ["Ubuntu's profile with srt's copy first (the box, DERM_BWRAP_DIR)", `${COPY}:/usr/bin`, { files: [PROFILE, `${COPY}/bwrap`, "/usr/bin/bwrap"] }, false],
  ["a link to /usr/bin/bwrap first counts as it", "/l:/usr/bin", { files: [PROFILE, "/l/bwrap"], real: { "/l/bwrap": "/usr/bin/bwrap" } }, true],
  ["Ubuntu's profile and no bwrap at all", "/usr/bin", { files: [PROFILE] }, true],
  ["no profile, the userns sysctl at 1 (CI's Ubuntu runner)", "/usr/bin", { files: ["/usr/bin/bwrap"], reads: { [SYSCTL]: "1\n" } }, true],
  ["no profile, the sysctl at 0", "/usr/bin", { files: ["/usr/bin/bwrap"], reads: { [SYSCTL]: "0\n" } }, false],
  ["no profile, no sysctl (a cloud container)", "/usr/bin", { files: ["/usr/bin/bwrap"] }, false],
  ["macOS", "/usr/bin", { platform: "darwin", files: [PROFILE] }, false],
];
for (const [what, PATH, facts, want] of cases) {
  const got = hostKillsClaudeCommands(PATH, host(facts));
  if (got !== want) {
    console.error(`FAIL ${what}: ${got}, wanted ${want}`);
    process.exitCode = 1;
  } else console.log(`ok ${what}`);
}
