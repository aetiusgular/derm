# Terminal-Bench through Harbor, and HSB (plan 6F (g), (e); E1)

Lane 6F builds the configuration and the runner glue; the task runs are **E1 on the box** (they need Docker and a local model the Harbor bridge can reach). Nothing runs in the cloud: no Docker daemon here (note AZ, X3).

## Pins (note AZ section 1, re-checked 12 Nov)
- Harbor 0.25.0 = tag `fdba28f` (terminal-bench 0.2.18 on PyPI). `models/.../config.py:40-45`: network modes `no-network`, `public`, `allowlist`. The Codex agent is Responses-only and takes `OPENAI_BASE_URL` (`agents/installed/codex.py:143-153`). A custom agent loads by module path: `--agent module.path:ClassName` (`jobs.py:633` is the deprecated `--agent-import-path`).
- HarnessSecurity-Bench `d4510a9`. A runner ships per mechanism (`scripts/<id>/<id>_run_agent.py`, 9 mechanisms); **no repository licence** (`UPSTREAM_LICENSE` covers 2 tasks). Tony asks the authors before use (note AZ, F5; rules section 5, item 2). One Docker container per harness per trial. HSB pins Claude Code 2.1.252, Codex 0.151.0, Copilot 1.0.82, Gemini 0.57.0, gptme, Qwen; **Pi is not one**. Codex or Qwen against the box's OpenAI-compatible endpoint fits.

## The precondition (note AZ, X2; AZ-12)
The box's model server must listen on an address Docker's bridge reaches. llama-swap listens on `127.0.0.1` only, so a container gets HTTP 000 from `host-gateway:8080` (note AZ section 8.11). Before any Harbor or HSB arm, **Tony points the box's llama-swap at an address the bridge reaches** (e.g. `0.0.0.0`), and the agent reaches it through `host-gateway`. Host networking (`network_mode: host`) would sit outside Harbor's egress policy, so it is not a gated arm (note AZ, F8). Also: srt 0.0.82 does not start on the box's stock Ubuntu 26.04 without the AppArmor sysctl change (AZ-12); E1's srt arm needs Tony's root change, undone after, as `tk_integration_w5_bw510.md` did.

## What E1 does
1. Point llama-swap at the bridge address (Tony); confirm `curl host-gateway:<port>/v1/models` from a throwaway container answers.
2. Terminal-Bench subset (6F (g)): a fixed subset of Terminal-Bench tasks on the box's local model through Harbor, with derm off, the Standard tier (6A) and srt. Report the pass rate's change, reviews per task, wall time, per-call latency. derm wraps the harness through `derm run`; a custom Harbor agent (`--agent`) starts `derm run -- <harness>` so the gate and feed are in the path.
3. HSB (6F (e)): after Tony's licence answer, HSB's released tasks and oracles, paired on/off trials, on Codex or Qwen against the box endpoint; at least 3 trials per task, with intervals (plan section 3).

## OpenAgentSafety (6F (h); F9)
357 tasks on an OpenHands fork derm does not gate (note AZ, F9: README calls the codebase legacy; ~30 GB of services, two LLMs). Left to E1 by Tony; it stands beside ActPlane's published number (74% of unsafe behaviours prevented on 361; arXiv 2606.25189) only if E1 runs it, with and without derm.
