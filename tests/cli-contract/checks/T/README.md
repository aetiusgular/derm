# Contract checks, wave 5 lane T

Lane T's checks against the real CLIs under `/tmp/cli` (`plans/parallel_build_tk.md` section 7c). `run.mjs` loads every `.mjs` file in this folder; each exports `checks`, an array of `{ id, title, harness, run }`, as `checks/R/` does. Lanes add files, not lines.

`boundary.mjs`: `derm run` with no `--boundary` (cases 118 and 129), against the real Pi 1.4.0 and the real srt 0.0.81, with sbx faked (sbx needs KVM and a Docker sign-in; the box test and the Mac test run the real one).

```
cargo build -p derm-cli
npm install --prefix /tmp/cli @earendil-works/pi-coding-agent@1.4.0 @anthropic-ai/sandbox-runtime@0.0.81
apt-get install bubblewrap socat ripgrep            # srt's Linux tools, in /usr/bin
DERM_BIN=<target>/debug/derm SRT_BIN=/tmp/cli/node_modules/.bin/srt \
  node tests/cli-contract/run.mjs --cli pi=/tmp/cli/node_modules/.bin/pi \
  --only boundary-default-srt,boundary-srt-confines,boundary-sbx-signed-out,boundary-sbx-chosen,boundary-none-stops,boundary-pre-answer,boundary-terminal
```

`boundary-sbx-chosen` reports `info` until integration applies request T-2 (one `sbx run` with `--kit`), and `pass` after (create with the kit as the workload, attach, remove). `boundary-terminal` needs `/usr/bin/python3` for its pty.

`requests/`: lane T's requests for integration as patches against `integration/w5` at `6e147ee` (the lane does not own those files). Each applies alone and in order (`git apply tests/cli-contract/checks/T/requests/T-*.patch`):

- `T-1-contract-default-and-blocked.patch`: `contracts/wave5-records.schema.json`, `contracts/events.md`, `contracts/contracts.test.ts`: `answeredBy: "default"` (derm picked sbx or srt with no question) and `ioUring: "blocked"` (srt's seccomp helper refuses io_uring).
- `T-2-sbx-create-rule-attach-remove.patch`: `crates/derm-cli/src/run/plan.rs` (the sandbox name, SB2) and `run/mod.rs` (`boundary::sbx::start` before the harness, the removal before `run.stop`, `sandboxRemoved` in `run.stop`; SB1, SB3, case 117), with the end-to-end sbx test extended to the four steps.
- `T-3-io-uring-mark.patch`: `run/mod.rs`, `run.start`'s `ioUring` (case 128), with assertions in the `none` and `srt` end-to-end tests.
