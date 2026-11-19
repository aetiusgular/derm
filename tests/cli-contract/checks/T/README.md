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

`kitInstall.mjs`, `sbx-kit-claude-gate`: derm's sbx kit for Claude Code end to end, as far as a machine with no KVM goes. `derm run claude-code --boundary sbx` builds the kit (a fake sbx keeps a copy from the create); its `derm-kit/` is laid into `/opt/derm-kit-src` and its `install.sh` runs as root, as sbx would; then the real Claude Code runs as `agent` in the claude kit's full access, against the fake Messages server, with only the gate the install put in `/etc/claude-code/managed-settings.json` (`/usr/local/bin/derm hook claude-code pre`, the derm under test). It creates a user and writes `/etc/claude-code`, `/opt/derm-kit`, `/usr/local/bin/derm` and `/home/agent`, so it runs only as root with `DERM_KIT_ROOT_TEST=1`, in a throwaway machine, and undoes what it did:

```
npm install --prefix /tmp/cli --ignore-scripts @anthropic-ai/claude-code@2.1.311
node /tmp/cli/node_modules/@anthropic-ai/claude-code/install.cjs
DERM_KIT_ROOT_TEST=1 DERM_BIN=<target>/debug/derm \
  node tests/cli-contract/run.mjs --claude /tmp/cli/node_modules/.bin/claude --only sbx-kit-claude-gate
```

Lane T's requests for integration (T-1 to T-3, and T-5 in phase 4) were patches in `requests/`. They were applied as `2dcc6a2` (phase 3 merge) and `6f26dca` (T-5); the patch files were removed on 19 Nov 2026 and those commits are the record.
