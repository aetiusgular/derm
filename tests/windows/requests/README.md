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
10. Unix-shaped tests that fail on the Windows runner, outside lane Z's
    folders, not gated. With Z-1 to Z-6 applied (probe `9e785d8`, run on
    5 Nov 17:3x UTC) these 29 are the only Windows failures: 747 passed,
    29 failed, in two targets (`derm-cli --bin derm` 21, `derm-daemon
    --lib` 8); every other target passes, `derm-core` 59 of 59.
    - `derm-cli` `connect::tests` (8: `a_cli_on_path_counts_as_installed`,
      `check_names_lists_the_pairs_in_the_user_project_and_policy_files`,
      `claude_code_matches_claude_mcp_add_json`,
      `codex_matches_codex_mcp_add_and_keeps_comments`,
      `copilot_matches_copilot_mcp_add`, `gemini_matches_gemini_mcp_add`,
      `pi_matches_pi_mcp_add`, `qwen_matches_qwen_mcp_add`) and
      `connect::rules_tests` (3: `codex_rules_end_to_end_with_codex_home`,
      `gemini_gets_its_deny_rules_in_a_file_of_its_own`,
      `qwen_home_moves_the_file_and_a_bad_policy_writes_nothing`): CRLF
      fixtures against LF written, `/tmp` and `sh` in inputs, `HOME`.
    - `connect::gateway::docker_mcp::tests::allows_the_listed_shapes`
      (`file:///Users/...` is not a plain path on Windows; request 6) and
      `connect::gateway::host::tests::search_path_keeps_the_inherited_path_first`
      (`:` as the PATH separator and Unix folders).
    - `doctor::tests` (3: the gate tests run `node` scripts by Unix path).
    - `run::preflight::tests::the_companions_path_drops_relative_and_writable_entries`
      (`/usr/local/bin` PATH).
    - `run::tap::tests::case_113_a_base_url_set_elsewhere_refuses_the_start_and_names_where`
      (the test joins `.claude/settings.json` with `/`, the message prints
      `\`; the refusal itself works).
    - `run::end_to_end::both_process_readers_find_a_marked_process_and_lose_it_when_it_ends`
      (`sh -c` and `ps`).
    - `tests::each_subcommand_reaches_its_module` (`derm connect: HOME is
      not set`; request 1).
    - `watch::conn::tests::a_relative_socket_flag_is_refused`
      (`/tmp/x/daemon.sock` is relative on Windows).
    - `derm-daemon` `activity::collector` (2), `activity::commands` (1),
      `collector::app` (3), `collector::tests` (1): launchd, plist, app
      bundle and root shell, all macOS things.
    - `activity::retention::tests::scan_and_apply_touch_only_our_names_and_never_follow_links`:
      the links are made only under `cfg(unix)`, so on Windows the day
      folder empties and is deleted too (2, not 1). Needs a Windows link
      (a junction) or the count under `cfg`.
    Each needs a Windows twin or a Windows form of its input, decided by the
    owner. Run 2 (`2235a9f`) also failed `daemon::tests` and
    `computer_use` (minting): fixed by Z-6.
