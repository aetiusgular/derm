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

`boundary-sbx-chosen` passes since request T-2 was applied (`2dcc6a2`) (create with the kit as the workload, attach, remove). `boundary-terminal` needs `/usr/bin/python3` for its pty.

Phase 4 (Tony's O1 decision): `boundary-default-srt` also runs Pi with derm-pi registered in the throwaway HOME and a signed-in fake sbx, and passes only when derm picks srt first and never calls sbx.

`kitInstall.mjs`, `sbx-kit-claude-gate`: derm's sbx kit for Claude Code end to end, as far as a machine with no KVM goes. `derm run claude-code --boundary sbx` builds the kit (a fake sbx keeps a copy from the create); its `files/home/` is laid into `/home/agent` and its `install.sh` runs as root, as sbx would; then the real Claude Code runs as `agent` in the claude kit's full access, against the fake Messages server, with only the gate the install put in `/etc/claude-code/managed-settings.json`. It creates a user and writes `/etc/claude-code`, `/opt/derm-kit` and `/home/agent`, so it runs only as root with `DERM_KIT_ROOT_TEST=1`, in a throwaway machine, and undoes what it did:

```
npm install --prefix /tmp/cli --ignore-scripts @anthropic-ai/claude-code@2.1.311
node /tmp/cli/node_modules/@anthropic-ai/claude-code/install.cjs
DERM_KIT_ROOT_TEST=1 DERM_BIN=<target>/debug/derm \
  node tests/cli-contract/run.mjs --claude /tmp/cli/node_modules/.bin/claude --only sbx-kit-claude-gate
```

`requests/`: lane T's requests for integration as patches (the lane does not own those files). T-1 to T-3 were written against `integration/w5` at `6e147ee` and applied at the phase 3 merge (`2dcc6a2`); they are kept as the record. Phase 4's T-5 is against `6d49e3e`:

- `T-1-contract-default-and-blocked.patch`: `contracts/wave5-records.schema.json`, `contracts/events.md`, `contracts/contracts.test.ts`: `answeredBy: "default"` (derm picked sbx or srt with no question) and `ioUring: "blocked"` (srt's seccomp helper refuses io_uring).
- `T-2-sbx-create-rule-attach-remove.patch`: `crates/derm-cli/src/run/plan.rs` (the sandbox name, SB2) and `run/mod.rs` (`boundary::sbx::start` before the harness, the removal before `run.stop`, `sandboxRemoved` in `run.stop`; SB1, SB3, case 117), with the end-to-end sbx test extended to the four steps.
- `T-3-io-uring-mark.patch`: `run/mod.rs`, `run.start`'s `ioUring` (case 128), with assertions in the `none` and `srt` end-to-end tests.
- `T-5-sbx-forms-from-kit-json.patch` (phase 4): `contracts/harness-presets.schema.json` (`$defs.kit.fullAccess`), `crates/derm-cli/src/connect/presets/wave5/kit.json` (each kit's `fullAccess`), `run/harness.rs` (the sbx form from the kit table; `PI_KIT` goes; Hermes, OpenClaw, Amp, Crush and Grok gain one), `run/plan.rs` (the kit's words in the chat's full access under sbx, so `DERM_FULL_ACCESS=1` reaches the VM) and `run/boundary/probe.rs` (one line, `h.sbx()`). Applies alone on `6d49e3e` and on lane T's head.
