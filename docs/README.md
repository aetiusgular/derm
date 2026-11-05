# derm documentation

derm is a skin for AI agents: a gate, a boundary and an audit around any coding agent. The gate allows, asks or denies each tool call from one policy file. The boundary is `derm run`, which starts an agent under a sandbox. The audit is `derm-daemon`, which keeps one log of what every agent did and answers the gate's questions.

- Install: [Linux](install/linux.md), [macOS](install/macos.md), [Windows (status: not installable yet)](install/windows.md), [the agent adapters](install/agents.md), [`derm setup`: policy presets, settings, shims](install/setup.md).
- The commands: [`derm connect`](verbs/connect.md), [`derm run`](verbs/run.md), [`derm watch` and `derm status`](verbs/watch.md), [`derm cu`](verbs/cu.md), [`derm-daemon`](verbs/daemon.md), [the library's commands](verbs/library.md). `derm acp` and `derm doctor` print "not implemented": they come with the coverage wave.
- [Privacy](privacy.md): what talks to the network, and what does not.
- [Benchmarks](benchmarks.md): Qwen3.8 27B with deferred tools against direct, through Pi and Claude Code, with the raw data.
- [Release notes](release-notes.md).
- [`llms.txt`](llms.txt): this set, for an agent.

The policy file and what the gate matches are specified in [`contracts/policy.md`](../contracts/policy.md); the daemon's socket in [`contracts/daemon-protocol.md`](../contracts/daemon-protocol.md); which agents are covered, and how, in the [README's coverage table](../README.md#harness-coverage).
