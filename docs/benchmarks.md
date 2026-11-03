# Benchmarks: deferred tools on a local 27B model

Measured 28 Oct 2026. Raw data: [`tests/measure/results/`](../tests/measure/results/). Method and scripts: [`tests/measure/`](../tests/measure/README.md).

## The question

Agents can load MCP tools up front ("direct") or defer them behind a search tool and load a tool's definition only when the model asks for it ("deferred"). Deferred saves prompt space. Does a local model still find and call the right tool when it has to search first?

## Setup

- Model: Qwen3.8 27B, `Qwen3.8-27B-UD-Q4_K_M.gguf`, through llama.cpp `f5027fb21` and llama-swap `1027b9b`, 131,072-token context, one slot, q8_0 KV cache, MTP speculative decoding.
- Machine: AMD Ryzen 5 3600, RTX 3090 24 GB, 15 GB RAM, Ubuntu 26.04.1, kernel 7.0.0 ([`host.txt`](../tests/measure/results/host.txt)).
- Agents: Pi 1.4.0 with derm's gate (deferred against direct); Claude Code 2.1.311 with derm's plugin, with `ENABLE_TOOL_SEARCH` unset, `auto` and `false`.
- Tasks: 20 ([`tasks.json`](../tests/measure/tasks.json)): 16 need the MCP tools (6 need two calls in a row, 1 crosses two servers), 4 controls need only built-in tools. Every entity is made up. The servers are recordings of Context7, Exa, Hugging Face and Shopify Dev MCP, replayed by a stub that hides each answer's token behind the right call with the right arguments: a pass means the model reached the right tool and carried its answer through.
- Each task three times per condition, 300 runs.

## Results

| Condition | Pass | MCP tasks | Tools declared, first request | Tool bytes, first request | Prompt tokens, first request | Seconds, median |
|---|---|---|---|---|---|---|
| Pi, deferred | 60/60 (100%) | 48/48 | 5 | 3,488 | 1,932 | 17.5 |
| Pi, direct | 59/60 (98%) | 47/48 | 17 | 44,070 | 11,563 | 14.4 |
| Claude Code, unset | 60/60 (100%) | 48/48 | 12 | 29,512 | 11,999 | 41.0 |
| Claude Code, `auto` | 59/60 (98%) | 47/48 | 32 | 87,040 | 26,655 | 40.4 |
| Claude Code, `false` | 58/60 (97%) | 46/48 | 32 | 87,040 | 26,452 | 39.0 |

The full table, per task, is [`summary.md`](../tests/measure/results/summary.md); every run is a line in `pi-results.jsonl` and `cc-results.jsonl`, every model request in `requests.jsonl`.

## What it shows

- On this model, deferring the tools cost no accuracy: Pi deferred passed every run, and so did Claude Code with tool search unset.
- Deferred cut the first request's prompt about sixfold in Pi (1,932 tokens against 11,563).
- It did not make Pi faster here: 17.5 s median against 14.4 s. Loading a tool rewrites the tool block at the head of the prompt, and a one-slot llama.cpp then reads the whole prompt again (0.8 full re-reads per run). Measure prompt processing, not only the context window, before choosing.
- Claude Code needs a change to its requests to run against llama.cpp at all: it sends a `role: "system"` message inside `messages`, which Qwen3.8's template refuses. The measurement's proxy moved those messages into the top-level system prompt (`proxy.mjs --fold-system`).

## What it does not show

- Only the 13 tools reachable without a sign-in: Vercel's and Granola's servers refuse to start without one and are not in the set.
- One model, one machine, one quantisation, three runs per task. The one Pi failure (`t10`) was the model finding a real PyPI package with the made-up name and answering from its real docs.
- No hosted model, and no task longer than two tool calls.
