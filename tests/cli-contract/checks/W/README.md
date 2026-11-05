# Contract checks, wave 5 lane W

Lane W's checks against the real CLIs under `/tmp/cli` (`plans/parallel_build_tk.md` section 7c). `run.mjs` loads every `.mjs` file in this folder; each exports `checks`, an array of `{ id, title, harness, run }`. Lanes add files, not lines.

`presets.mjs`: `derm setup`'s workspace-write preset (the default, and the policy derm's sbx kit copies into the VM) against the real Claude Code 2.1.311 with the derm plugin, the fake Messages server and a fake daemon.

- `w-preset-vm`: the VM's shape, `DERM_FULL_ACCESS=1`: `echo` runs; `git push`, `docker run --privileged` and `derm setup` are denied with derm's reason and never run; no approver or prompt is asked.
- `w-preset-host`: the host's shape: `git status` runs, `git push` asks the daemon's approver (whose no denies it), `docker run --privileged` is denied with no question.

```
npm install --prefix /tmp/cli @anthropic-ai/claude-code@2.1.311
node tests/cli-contract/run.mjs --claude /tmp/cli/node_modules/.bin/claude --only w-preset-vm,w-preset-host
```

Both report `info` until integration applies request W-1: before it the preset's command rules fail the matcher's schema, so every call asks (a deny under full access), ordinary work included. With W-1 applied both pass (run 5 Nov 2026 in a scratch worktree of the lane head).

`preset-cases.json`: 24 calls and what each preset answers, read by request W-2's tests in all three matchers.

`requests/`: lane W's requests for integration as patches (the lane does not own those files):

- `W-1-command-rules.patch`: `contracts/policy.md` section 7 built in the three matchers (`command.ts` in the hook core and derm-pi, `crates/derm-core/src/command.rs`), `contracts/policy.schema.json`, fixture rules and cases 85 to 106, `fixtures/policy/invalid.json`, `sync-core.mjs`'s copies in the ten packages, and the writers of an agent's own rules (`connect/rules.rs`, the Gemini printout) leaving command rules to the gate. Applies alone on `integration/w5` at `6d49e3e` (`git apply --index`).
- `W-2-preset-tests.patch`: three test files, one per matcher, that read `crates/derm-cli/src/setup/presets/` and `preset-cases.json`. Applies after W-1 and the lane's squash.
