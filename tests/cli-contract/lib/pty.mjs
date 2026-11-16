// A shell line on a pseudo-terminal through script(1), for the checks that
// type a yes where derm reads it from the terminal only (case 89).
//
// util-linux script takes the line with -c (`script -qec <line> /dev/null`,
// script(1) from util-linux). macOS's BSD script has no -c: its synopsis is
// `script [-aeFkqr] [-t time] [file [command ...]]`, and its -e is "accepted
// for compatibility with util-linux script. The child command exit status is
// always the exit status of script" (script(1) on macOS 26.5.1, read). Run on
// the Mac, the util-linux form failed with "illegal option -- c" (Mac test w6
// retest 4, MW6R4-2), so the line goes to /bin/sh -c there.
//
// On macOS the child's stdin must not be a node pipe: node's pipes there are
// socketpairs, and BSD script fails at once with "tcgetattr/ioctl: Operation
// not supported on socket" (run). Spawn it with stdin "ignore" (/dev/null).
// A typed answer on stdin is not reliable on macOS either: at stdin's end BSD
// script writes the terminal's EOF, which raced the answer in a run ("got="
// came back empty). So only lines that read nothing use this on macOS; the
// checks that type a yes still run on Linux only.

/** script(1)'s arguments that run `line` under /bin/sh on a pty. */
export function scriptArgs(line, platform = process.platform) {
  if (platform === "darwin" || platform === "freebsd" || platform === "openbsd" || platform === "netbsd") {
    return ["-q", "/dev/null", "/bin/sh", "-c", line];
  }
  return ["-qec", line, "/dev/null"];
}
