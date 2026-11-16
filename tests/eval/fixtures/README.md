# tests/eval/fixtures

Recorded from the real tools (rules section 9, item 12), 2026-11-13T00:29:14Z, cloud (Ubuntu 24.04.5, kernel 6.18.44):

- `moatbench-claude-code-verbose.txt`: stderr of `openmoat bench --hook 'DERM_POLICY=/opt/e1/policy/workspace-write.json /opt/e1/bin/derm hook claude-code pre' --host claude-code --format json --verbose`, OpenMoat 0.19.0's release binary (tarball sha256 `d24761fb...4ab90ad`), derm 0.1.3 built from `base/w6` at `d56cd9d`; its first line is this header. Every payload MoatBench sent and every reply derm gave.
- `moatbench-claude-code-derm.json`: that run's stdout (the scorecard).
- `moatbench-claude-code-calibration.json`: `openmoat bench --hook "cat >/dev/null; echo '{{{derm-eval-calibration'; exit 1" --host claude-code --format json` (the calibration hook of `lib/moatbench.mjs`), the same binary.

`eval.test.ts` holds `lib/moatbench.mjs`'s reading of a scorecard and `lib/probe.mjs`'s Claude Code payloads and reply reading to these.
