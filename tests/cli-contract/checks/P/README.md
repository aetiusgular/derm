# Lane P's contract checks (wave 4)

Scaffolded by integration w2 for lane P (plugins: Amp, Cline) (`plans/parallel_build_tk.md`, section 7a). `run.mjs` imports every `.mjs` file here; lanes add files, not lines. Each exports `checks`, an array of `{ id, title, harness, run }`; `run({ binPath, version, codexPath, claudePath })` returns `{ status: "pass" | "fail" | "info" | "skip", finding }`.

- `clineGate.mjs`: derm's Cline plugin and approval-file responder against the real Cline CLI, with the fake chat-completions server (`../../lib/fakeChat.mjs`, provider `openai-compatible`) and a fake derm daemon. Every run uses a scratch HOME and `--data-dir`, so Cline's local backend serves it and no hub daemon is left (`cline-derm-no-hub` checks). Run with `--cli cline=<path to node_modules/cline/bin/cline>` (`npm install cline@<version>` under `/tmp/cli/cline`; the npm `.bin` link was not made on 3 Nov, so name the package's own `bin/cline`). `cline-responder-core` imports `@cline/core` from beside that path.
- Amp has no check here: it needs an account (call 8). Its package is tested against fixtures (`packages/derm-amp-plugin`).

The agents' hook contracts and fixtures: `contracts/hook-dialects.md`, `contracts/fixtures/hook-dialects/<agent>/`.
