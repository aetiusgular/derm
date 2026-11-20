# derm setup's policy presets (wave 5, lane W)

Read-only, workspace-write and strict, each with default rules for the CLIs
agents use most (`plans/toolkit_universal_plan.md` lane W). Each rule set names
the CLI version it was read at.

`workspace-write.json` is the default: `derm init` and `derm setup` write it
when you have no policy. What it means for each of derm's eight permissions is
in `docs/permissions.md`.
