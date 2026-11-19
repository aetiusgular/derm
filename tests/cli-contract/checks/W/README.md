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

Lane W's requests for integration were patches in `requests/`, applied as `1dff932` (W-1, command rules), `2f23a46` (W-2, the preset tests) and `503ea56` (W-3, since moot: the sbx kit carries no TypeScript). The patch files were removed on 19 Nov 2026 and those commits are the record.
