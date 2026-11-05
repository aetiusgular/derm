# Lane Z's requests for integration (wave 5, phase 4)

Patches to files lane Z does not own (six; Z-6 was added after the
first Windows CI run). They make the whole workspace build
and pass `cargo clippy --workspace --all-targets -- -D warnings` for
`x86_64-pc-windows-gnu` (and `-msvc` by `cargo check`), and leave Linux as
it was: `cargo test --workspace` 986 passed, 0 failed; clippy and
`cargo fmt --all --check` clean (lane Z's workspace, 5 Nov 2026). Apply in
order (Z-1 to Z-6) on `lane/Z-windows`; each was checked with `git apply --check` on the
lane's head, and the six together give exactly the tree that was tested (`lane/Z-windows-probe`).

| Patch | Files | What |
|---|---|---|
| Z-1-platform-seam | `derm-core/src/platform/mod.rs` | `platform::peer` and a `platform::Pidfd` type on Windows too (an `OwnedFd` on Unix, a process handle on Windows). |
| Z-2-derm-tap | `derm-tap` | Unix-only calls (`PermissionsExt`, `symlink`) behind `cfg(unix)`; Windows twins of the privacy tests (the platform's private file; a junction instead of a symlink). |
| Z-3-derm-daemon | `derm-daemon` | `pidfd` as `platform::Pidfd`; `uid` as `UserId` by value in computer use; Unix-native tests gated `cfg(unix)` with Windows twins where the thing they check exists on Windows. |
| Z-4-derm-audit-linux | `derm-audit-linux` | The client's token-file checks through the platform (owner and private on Windows); the fake daemon through the seam; a Windows twin of the token test. |
| Z-6-derm-core-token-home | `derm-core/src/token.rs`, `runtime.rs` | `token::mint` from BCryptGenRandom on Windows (it opened `/dev/urandom`: os error 3 on the Windows runner, failing every test that mints); `runtime::home_dir` reads `USERPROFILE` on Windows, so the socket path (the pipe's pointer file) is `%USERPROFILE%\.derm\run\derm\daemon.sock`. |
| Z-5-derm-cli | `derm-cli` | `run` through `platform::exec` on Windows; `run/user` (the box user) Unix-only with Windows stubs that run in place; gate, connect, doctor, watch and probe Unix-only calls behind `cfg(unix)`; Unix-native tests gated. |

No test was deleted, skipped or weakened: a test gated `cfg(unix)` checks a
Unix thing (a mode bit, a signal, `/bin/sh`, a Unix socket) and still runs on
Linux and macOS; where Windows has the same property a twin runs there.

## Requests in words (not patches)

1. `HOME` on Windows: Z-6 fixes the socket path (`runtime.rs`; the daemon's
   `tests::socket_path_ends_with_derm_daemon_sock` failed on the runner).
   Still reading `HOME` only: `policy.rs:1142`,
   `derm-daemon/src/daemon.rs:253`, `connect/mod.rs:105`,
   `watch/status.rs:88`. Ask: `runtime::home_dir` there too.
2. `/dev/urandom` on Windows: Z-6 fixes `token::mint` (the runner failed
   `token::tests::minted_tokens_are_well_formed_and_distinct` with os error
   3; Wine had passed it, resolving the Unix path to the Linux file). Still
   opening it: `connect/log.rs:39`.
3. `Source::Sysmon` in the event contract (`contracts/events.md` section 5),
   written by the daemon only as `Tap` and `Derm` are; `derm-audit-windows`
   takes its source from the caller until then.
4. The daemon wires `derm-audit-windows` (`reader::read_after` polled,
   `Feed::register` on `run.start`, `unregister` on `run.end`), keeping the
   last record id across restarts.
5. The JS hook core's daemon client (`packages/*/src/core/daemon.ts`, ten
   copies): on `win32`, read the pointer file at the socket path (private,
   one line `\\.\pipe\derm-<64 hex>`), connect to that pipe, and refuse to
   send a token unless the pipe's server is the user's (`GetNamedPipeServerProcessId`
   is not in Node; the check needs a small native step or `derm` itself as
   the go-between).
6. `connect/gate.rs` `plain_path` refuses every Windows path (no `C:\`);
   decide the Windows form before the gate is used on Windows.
7. `derm status` on Windows names the gaps: no S2 without a boundary,
   Sysmon's FileCreate is not every write, event 3 off unless the config
   turns it on, a process started with another parent is outside the chat.
8. The Windows CI job runs `cargo test --workspace --no-fail-fast`, so the
   first failing test binary does not hide the others' results.
9. Lane T: `%USERPROFILE%\.derm` denied to srt's sandbox account, as in
   the phase 1 request 5.
10. Unix-shaped test inputs that fail on the Windows runner (5 Nov, probe
    run 42059209319), outside lane Z's folders, not gated: `derm-cli`
    `connect::tests` and `rules_tests` (CRLF in fixtures vs LF written;
    `/tmp` and `sh` in inputs), `run::preflight` (`/usr/local/bin` PATH),
    `doctor` gate tests (`node` scripts), `connect::gateway` (`sh`),
    `watch::conn` (a relative-path test that is absolute on Windows);
    `derm-daemon` `activity` and `collector` (launchd and plist tests),
    `daemon::tests` and `computer_use` (minting, fixed by Z-6). Each needs a
    Windows twin or a Windows form of its input, decided by the owner.
