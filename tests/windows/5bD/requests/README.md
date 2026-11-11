# Lane 5bD's requests for integration

Each request names the files it changes outside lane 5bD's folders, why, and how it was checked. Apply them in order at the phase merge.

## 5bD-1: `derm run` calls the Windows srt form (`5bD-1-run-wiring.patch`)

`git apply tests/windows/5bD/requests/5bD-1-run-wiring.patch` from the repository root, on lane 5bD's head. It:

- `run/mod.rs`: after the srt preflight and before the dry run's print, calls `boundary::windows_srt::wire` when `cfg!(windows)` and the boundary is srt. It rewrites the plan into srt's Windows form, takes the machine's srt lock and writes the chat's files; the returned session frees the lock and removes the files when `run_io` returns, on every way out.
- `run/preflight.rs`: on Windows `srt_with` asks for no tool on PATH. srt 0.0.82 runs ripgrep on Linux only (`src/sandbox/sandbox-manager.ts:1895`), and bubblewrap and socat are Linux's.
- `run/boundary/probe.rs`: on Windows the probe pins the srt-win backend and loopback binding off, as a chat does, and runs `-c "exit 0"`: srt runs a `-c` string through `cmd.exe /d /s /c`, which has no `true`. srt's install line on Windows names its once-per-machine `windows-install` (README "Windows (alpha)", "Setup") and no ripgrep.
- `run/boundary/windows_srt/mod.rs`: `WIRED` becomes true, so `refusal()` refuses srt on Windows only while another chat holds the lock (case 230).
- Two Windows tests change with the behaviour, as the wave 5b plan's call 1 changes it: `ww5_8_srt_is_refused_on_windows_for_the_true_reason` becomes `ww5_8_srt_on_windows_needs_no_rg_and_reads_the_windows_path` (WW5-8's two failures, "needs rg" and "a relative PATH entry", stay guarded), and `fpw_s7_on_windows_the_probe_names_the_refusal_not_an_install` becomes `fpw_s7_on_windows_the_probe_gives_windows_own_install_line` (FPW-S7 was an install line for a boundary derm refused; derm now starts it). A move of a test with its behaviour, not a weakened failing test.

Checked: applied on lane 5bD's head `2a7c4f2` in a worktree; `cargo fmt --all --check`, `cargo clippy -p derm-cli --all-targets -D warnings` and `cargo test -p derm-cli` (596, 0 failed) on Linux; the patched tree pushed once as `lane/5bD-srt-windows-trial` for CI's Windows job (result in `plans/parallel/tk_lane_5bD.md`), then deleted.

## 5bD-2: the gate inside srt on Windows reads `DERM_CHAT_FILE` (gate code, lane 5bA's or integration's)

`derm enter` sets `DERM_CHAT_FILE` to `chat.json` in the chat's folder (`{"version":1,"chat","policy","policyProblem","daemon":{"http"}}`), which `derm run` wrote as the user and the sandbox account may only read. Inside srt on Windows the gate's own lookups fail: `%USERPROFILE%` is the sandbox account's, so the policy file and the daemon's pipe pointer are not found, and the pipe is no route a sandboxed process should have (contract section 2, item 4). Asked, in `crates/derm-cli/src/gate/`:

1. When `DERM_BOUNDARY` is `srt` on Windows, the policy is the one in `DERM_CHAT_FILE`, and the daemon is reached over HTTP at its `daemon.http` (the `/derm/v1/event` and `/derm/v1/approve` routes `post_vm` already speaks), through srt's proxy, whose variables srt sets (`http_proxy`; srt 0.0.82 deletes `NO_PROXY` on Windows, `windows-sandbox-utils.ts:4392-4403`). `DERM_POLICY` and the pipe pointer are not read there.
2. The file is taken only when, judged on its open handle: it is a regular file, no reparse point, at most 64 KiB, this account cannot open it for writing or `WRITE_DAC` (an agent-made file can be; `enter/win.rs`'s `writable_here` is the check), and its `chat` equals `DERM_CHAT_ID`. Otherwise every call asks, and the reason says so. A project can set `DERM_CHAT_FILE` (Claude Code passes a project's `env` to hooks, note BC finding BC-3), but it cannot make a file the sandbox account may read and not write.
3. Without this request, a gate inside srt on Windows finds no policy and no daemon: every call asks, and an ask with no daemon is a deny. Nothing is opened; the chat is unusable rather than ungated.

Not built here (outside 5bD's folders; `gate/` is integration's after the base). The variable and the file's shape are this lane's reading of the contract; see 5bD-3.

## 5bD-3: `contracts/srt-windows.md`, as built

The contract's sections 2 and 3 as lane 5bD built them (contracts are no lane's):

- Section 2, item 3: `derm run` writes the token file, not `derm enter`: `token` beside the handoff, read-only to the sandbox account for the chat's life, so the agent cannot replace it. `derm enter` sets `DERM_CHAT_TOKEN`, `DERM_CHAT_TOKEN_FILE` and `DERM_CHAT_FILE`.
- Section 2, item 4: the gate reads the policy and the route from `chat.json` beside the handoff (`DERM_CHAT_FILE`), not from the handoff, which is gone once read; request 5bD-2.
- Section 2, item 2: revoked "once read" is done by `derm enter` deleting the handoff (the sandbox account gets read and delete on that file alone, SDDL `FRSD`); where the delete fails, `derm run` removes it at stop.
- Section 2, item 5: the state copy is `%USERPROFILE%\.derm-srt\state\<harness>`, emptied at start and stop; the sign-in host stays shut under srt on Windows (no renewal inside), as for a keychain store on macOS (cases 186, 190).
- Section 2, item 6: `--check` prints `{"ok","chat","harness","program","args","cwd","variables","tokenFile","chatFile","daemon","policyProblem","expires","skipped"}`, and on Windows `writableHere` in place of a refusal, since the user who runs `--check` owns the file.
- Section 3: the variable names a handoff may not set are srt's whole overlay and its account's profile (`enter/handoff.rs` `RESERVED`), not only `PATH`, `PATHEXT`, `ComSpec`, `SystemRoot` and the proxy set.

## 5bD-4: rules section 4, cases (proposed)

- 230 and 231 as the wave 5b plan proposes, with 231's detection read as "deleted by `derm enter` once read".
- **A handoff or chat file the agent wrote.** A file the sandbox account can write or re-permission is refused by `derm enter` and (5bD-2) by the gate, whatever variable names it. Tests: `enter::win::tests::a_file_we_may_only_read_is_not_writable_here`, `a_file_of_ours_is_writable_here_and_its_bytes_read`.
- **A path cmd.exe would read as more than a path.** srt runs its `-c` string through `cmd.exe /d /s /c`, which expands `%` inside quotes; derm's and the handoff's paths with `"`, `%`, `!`, a control character or a trailing `\` are refused before srt starts. Test: `windows_srt::tests::a_path_cmd_would_read_as_more_than_a_path_is_refused`.

Applied by integration w5b at the phase merge (5bD-1; 5bD-3 written into `contracts/srt-windows.md`). 5bD-2 is open for the close; 5bD-4 goes into rules section 4 at the close.
