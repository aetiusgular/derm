"""Harbor agent: Harbor's own Codex agent, started through `derm run`.

Plan 6F (g), eval pass 1's E1-4c. Harbor 0.25.0 (tag fdba28f) loads it by
module path:

    harbor run --agent derm_codex:DermCodex --ak derm_arm=gate \
        --ak derm_bundle=/abs/path/to/bundle ...

Arms (`derm_arm`):
  off       Harbor's Codex agent, untouched. The control.
  gate      `derm run codex --boundary none`: derm's gate (its Codex plugin),
            the daemon's record and Codex's own telemetry to the daemon.
  standard  the same with `--tier standard`: Codex's own sandbox written
            from derm's policy.

Everything else is Harbor's Codex agent (agents/installed/codex.py): the
install, config.toml, the model connection, the trajectory. This class adds
derm to the task's container after Codex is installed, and rewrites the one
`codex exec` line Harbor runs (codex.py:2069-2083) so it starts through
`derm run`. Harbor passes `--dangerously-bypass-approvals-and-sandbox`, so
derm reads the chat as full access and denies what its policy would ask;
each such deny is a "review" in the score.

The bundle is built by `node tests/eval/lib/terminal-bench.mjs bundle`:
static derm binaries, a local Codex marketplace holding derm's plugin, the
trust entries for its two hooks, and the policy. Nothing is fetched from the
network for derm inside the container.
"""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any, ClassVar, override

from harbor.agents.installed.codex import Codex, CodexOptions
from harbor.environments.base import BaseEnvironment

ARMS = ("off", "gate", "standard")
REMOTE = "/installed-agent/derm"
EXEC_MARK = "codex exec "


def wrap_exec(command: str, arm: str, logs: str, tap: bool = False) -> str:
    """The `codex exec` line Harbor runs, started through `derm run`.

    Pure text, so it is tested without Harbor or Docker. `off` and any line
    that is not Harbor's exec line come back unchanged.
    """
    if arm == "off" or EXEC_MARK not in command or "--json" not in command:
        return command
    if arm not in ARMS:
        raise ValueError(f"derm_arm must be one of {ARMS}, not {arm!r}")
    if command.count(EXEC_MARK) != 1:
        raise ValueError("expected exactly one `codex exec` in Harbor's command")
    run = ["derm", "run", "codex", "--boundary", "none", "--chat", '"$DERM_TB_CHAT"']
    if not tap:
        run.append("--no-tap")
    if arm == "standard":
        run += ["--tier", "standard"]
    run += ["--", "exec "]
    wrapped = command.replace(EXEC_MARK, " ".join(run), 1)
    q = shlex.quote
    b, lg = q(REMOTE), q(logs)
    before = "\n".join(
        [
            "export PATH=/usr/local/bin:$PATH",
            "if [ -s ~/.nvm/nvm.sh ]; then . ~/.nvm/nvm.sh; fi",
            f"mkdir -p {lg} ~/.derm && chmod 700 ~/.derm",
            f"install -m 0600 {b}/policy.json ~/.derm/policy.json",
            # derm's Codex plugin from a local marketplace, then its two hooks
            # trusted by hash: Codex skips an untrusted plugin hook silently.
            f"codex plugin marketplace add {b}/mkt --json > {lg}/derm-setup.log 2>&1",
            f"codex plugin add derm@derm --json >> {lg}/derm-setup.log 2>&1",
            f'grep -q "derm@derm:hooks" "$CODEX_HOME/config.toml" 2>/dev/null || cat {b}/trust.toml >> "$CODEX_HOME/config.toml"',
            f"if ! derm watch report >/dev/null 2>&1; then (derm-daemon --foreground >> {lg}/derm-daemon.log 2>&1 &); fi",
            "i=0; while [ $i -lt 40 ] && ! derm watch report >/dev/null 2>&1; do sleep 0.25; i=$((i+1)); done",
            f"derm watch report >/dev/null 2>&1 || echo 'derm-daemon did not start' >> {lg}/derm-setup.log",
            'export DERM_TB_CHAT="tb-$(date +%s)-$$"',
            f'printf "%s\\n" "$DERM_TB_CHAT" > {lg}/derm-chat.txt',
            f"derm --version >> {lg}/derm-setup.log 2>&1",
        ]
    )
    after = "\n".join(
        [
            "derm_rc=$?",
            "sleep 6",  # Codex's log export interval, then the daemon's write
            f'derm watch report --chat "$DERM_TB_CHAT" --json > {lg}/derm-report.json 2>> {lg}/derm-setup.log',
            f'(derm watch tail --since 1d --chat "$DERM_TB_CHAT" --json > {lg}/derm-events.jsonl 2>/dev/null & t=$!; sleep 4; kill $t 2>/dev/null)',
            "exit $derm_rc",
        ]
    )
    return f"{before}\n{wrapped}\n{after}"


class DermCodexOptions(CodexOptions):
    """Harbor checks an agent's kwargs against its options model
    (agents/installed/base.py:370). These three carry no CLI flag."""

    derm_arm: str = "gate"
    derm_bundle: str | None = None
    derm_tap: bool = False


class DermCodex(Codex):
    """Harbor's Codex agent with derm in the path."""

    options_model: ClassVar[type[CodexOptions] | None] = DermCodexOptions

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        opts = self.options
        derm_arm = getattr(opts, "derm_arm", "gate")
        derm_bundle = getattr(opts, "derm_bundle", None)
        if derm_arm not in ARMS:
            raise ValueError(f"derm_arm must be one of {ARMS}, not {derm_arm!r}")
        self._derm_arm = derm_arm
        self._derm_tap = bool(getattr(opts, "derm_tap", False))
        self._derm_bundle = Path(derm_bundle) if derm_bundle else None
        if derm_arm != "off":
            if self._derm_bundle is None:
                raise ValueError("derm_bundle is required unless derm_arm=off")
            for part in ("bin/derm", "bin/derm-daemon", "mkt", "trust.toml", "policy.json"):
                if not (self._derm_bundle / part).exists():
                    raise ValueError(f"derm bundle has no {part}: {self._derm_bundle}")

    @staticmethod
    @override
    def name() -> str:
        return "derm-codex"

    @override
    async def install(self, environment: BaseEnvironment) -> None:
        await super().install(environment)
        if self._derm_arm == "off":
            return
        assert self._derm_bundle is not None
        await environment.upload_dir(self._derm_bundle, REMOTE)
        await self.exec_as_root(
            environment,
            command=(
                f"install -m 0755 {REMOTE}/bin/derm /usr/local/bin/derm && "
                f"install -m 0755 {REMOTE}/bin/derm-daemon /usr/local/bin/derm-daemon && "
                f"chmod -R a+rX {REMOTE} && derm --version"
            ),
        )

    @override
    async def exec_as_agent(
        self,
        environment: BaseEnvironment,
        command: str,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        timeout_sec: int | None = None,
    ) -> Any:
        command = wrap_exec(
            command,
            self._derm_arm,
            self.environment_logs_dir.as_posix(),
            self._derm_tap,
        )
        return await super().exec_as_agent(
            environment, command, env=env, cwd=cwd, timeout_sec=timeout_sec
        )
