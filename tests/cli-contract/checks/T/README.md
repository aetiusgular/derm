# Contract checks, wave 5 lane T

Lane T's checks against the real CLIs under `/tmp/cli` with the fake model servers (`plans/parallel_build_tk.md` section 7c). `run.mjs` loads every `.mjs` file in this folder; each exports `checks`, an array of `{ id, title, harness, run }`, as `checks/R/` does. Lanes add files, not lines. Folder made by the wave 5 base; empty until lane T.
