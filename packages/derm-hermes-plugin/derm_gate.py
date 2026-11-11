"""derm's gate for Hermes Agent (T2.4, wave 2 lane I; wave 5b lane 5bB).

Hermes calls ``pre_tool_call`` before every tool call and ``transform_tool_result``
after it. Both hand the call to ``derm hook hermes <pre|post>``, derm's one gate in
Rust, run by its absolute path, so the rules here are the same as in every other
harness. Until wave 5b this ran ``bin/derm-decide.mjs`` with the ``node`` found on
PATH; a project or a shell file that put another ``node`` first chose the gate
(the BC-3 class, rules case 227), so derm is never looked up on PATH here.

Where derm is (case 227; contracts/hook-dialects.md 9.1): the absolute path in
``derm-path`` beside this file, which ``derm connect hermes --gate`` writes, else
derm's install folders (``~/.local/bin/derm``, then ``/usr/bin/derm``). Each is
used only when it is a regular file of yours or root's that no one else may write,
in a folder no one else may write, as case 109's rule says; ``derm-path`` itself is
held to the same rule. Anything else blocks every call and says why.

Hermes facts (NousResearch/hermes-agent v0.22.5, bf0203a7; ``main`` at 2b7a6ce and
78abaaf, unchanged in these files; plans/parallel/tk_lane_I.md, tk_lane_5bB.md):

- A pre_tool_call return of ``{"action": "block", "message"}`` vetoes the call and the
  message becomes the tool result; ``{"action": "approve", "message"}`` sends it to
  Hermes's human gate; ``{"action": "modify", "args"}`` is merged over the args
  (hermes_cli/plugins.py).
- A callback that raises, or runs past ``plugins.hook_callback_timeout`` (30 s by
  default), blocks the call (plugins_dispatch.py: policy hooks fail closed).
- Under ``--yolo``, ``/yolo``, an unattended turn, or ``approvals.mode: off``, Hermes's
  human gate approves everything at once (tools/approval.py). An ``approve`` there
  would let a derm ask through, so derm blocks instead (rules case 83).

Everything that goes wrong here blocks: no derm it can trust, a timeout, output that
is not the answer this module expects.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Any, Callable, Optional

HERE = Path(__file__).resolve().parent
#: The absolute path of derm, written beside this file by ``derm connect hermes --gate``.
DERM_PATH_FILE = "derm-path"
#: Below Hermes's default 30 s callback timeout; derm caps an ask at 20 s.
DECIDE_TIMEOUT_SECONDS = 25.0

Runner = Callable[[dict[str, Any]], dict[str, Any]]


def _block(reason: str) -> dict[str, str]:
    text = " ".join(str(reason).split()) or "blocked"
    return {"action": "block", "message": f"derm: {text}"}


def _private(st: os.stat_result) -> bool:
    """Owned by you or root, and no group or other write bit."""
    return st.st_uid in (os.getuid(), 0) and st.st_mode & 0o022 == 0


def trusted_file(path: Path) -> Optional[str]:
    """None when ``path`` is a regular file of yours or root's that no one else may
    write, in a folder no one else may write (links followed, as the agent's exec
    follows them); else why not."""
    if not path.is_absolute():
        return f"{path} is not an absolute path"
    try:
        real = path.resolve(strict=True)
        st = os.stat(real)
        folder = os.stat(real.parent)
    except OSError as exc:
        return f"{path} cannot be read ({exc.strerror or exc})"
    if not stat.S_ISREG(st.st_mode):
        return f"{path} is not a regular file"
    if not _private(st):
        return f"someone other than you may write {path}"
    if not _private(folder):
        return f"someone other than you may write the folder of {path}"
    return None


def find_derm(plugin_dir: Path = HERE, home: Optional[Path] = None) -> str:
    """derm's absolute path (case 227). Raises with the reason when none can be trusted."""
    if os.name == "nt":
        # Python's standard library cannot read a file's access list, so the check
        # above cannot be made on Windows (I; open for lane 5bF).
        raise RuntimeError("derm's Hermes gate cannot check derm's path on Windows yet")
    named = plugin_dir / DERM_PATH_FILE
    if os.path.lexists(named):
        why = trusted_file(named)
        if why is not None:
            raise RuntimeError(f"{DERM_PATH_FILE} not used: {why}")
        try:
            text = named.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeDecodeError) as exc:
            raise RuntimeError(f"{DERM_PATH_FILE} cannot be read ({exc})") from exc
        derm = Path(text)
        why = trusted_file(derm)
        if why is not None:
            raise RuntimeError(f"the derm {DERM_PATH_FILE} names is not used: {why}")
        return str(derm)
    home = home if home is not None else Path(os.path.expanduser("~"))
    tried = []
    for derm in (home / ".local" / "bin" / "derm", Path("/usr/bin/derm")):
        if not os.path.lexists(derm):
            continue
        why = trusted_file(derm)
        if why is None:
            return str(derm)
        tried.append(why)
    found = f" ({'; '.join(tried)})" if tried else ""
    raise RuntimeError(f"no derm found that only you can change{found}; run `derm connect hermes --gate`")


def derm_runner(payload: dict[str, Any], *, derm: Optional[str] = None, timeout: float = DECIDE_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Runs ``derm hook hermes <event>`` once. Raises on anything but one JSON object."""
    exe = derm or find_derm()
    event = "post" if payload.get("event") == "post" else "pre"
    proc = subprocess.run(
        [exe, "hook", "hermes", event],
        input=json.dumps(payload, default=str),
        capture_output=True,
        text=True,
        timeout=timeout,
        env=os.environ.copy(),
        cwd=os.getcwd(),
        check=False,
    )
    out = json.loads(proc.stdout.strip().splitlines()[-1]) if proc.stdout.strip() else None
    if not isinstance(out, dict):
        raise RuntimeError(f"derm hook gave no answer (exit {proc.returncode})")
    return out


def hermes_auto_approves() -> bool:
    """True when Hermes's own human gate would approve at once, or when that cannot be told."""
    try:
        from tools.approval import _yolo_active  # type: ignore[import-not-found]
        from tools.approval_context import _get_approval_mode  # type: ignore[import-not-found]
    except Exception:
        return True
    try:
        return bool(_yolo_active()) or _get_approval_mode() == "off"
    except Exception:
        return True


class Gate:
    def __init__(self, runner: Runner = derm_runner, auto_approves: Callable[[], bool] = hermes_auto_approves) -> None:
        self.runner = runner
        self.auto_approves = auto_approves

    def pre_tool_call(self, tool_name: str = "", args: Optional[dict[str, Any]] = None, session_id: str = "", tool_call_id: str = "", **_: Any) -> Optional[dict[str, Any]]:
        try:
            answer = self.runner({"event": "pre", "tool_name": tool_name, "args": args if isinstance(args, dict) else {}, "session_id": session_id, "tool_call_id": tool_call_id})
        except subprocess.TimeoutExpired:
            return _block("the gate timed out, so the call is refused")
        except Exception as exc:  # the gate could not decide: refuse
            return _block(f"the gate failed, so the call is refused ({exc})")
        decision = answer.get("decision")
        reason = answer.get("reason") if isinstance(answer.get("reason"), str) else ""
        if decision is None and answer.get("action") == "block":
            # derm's own refusal before any dialect ran (an event it does not take).
            message = answer.get("message") if isinstance(answer.get("message"), str) else ""
            return _block(message.removeprefix("derm: ") or "the gate refused the call")
        if decision == "deny":
            return _block(reason)
        if decision == "ask":
            if self.auto_approves():
                return _block(f"{reason}; Hermes approves everything in this mode (yolo, unattended or approvals off), so derm refuses its ask")
            return {"action": "approve", "message": f"derm asks: {reason}", "rule_key": f"derm:{tool_name}"}
        if decision == "allow":
            new_args = answer.get("args")
            if isinstance(new_args, dict):
                return {"action": "modify", "args": new_args}
            return None
        return _block(f"the gate gave no decision ({decision!r})")

    def transform_tool_result(self, tool_name: str = "", args: Optional[dict[str, Any]] = None, result: Any = None, session_id: str = "", tool_call_id: str = "", status: str = "", **_: Any) -> Optional[str]:
        try:
            answer = self.runner({"event": "post", "tool_name": tool_name, "args": args if isinstance(args, dict) else {}, "result": result, "session_id": session_id, "tool_call_id": tool_call_id, "status": status})
        except Exception:
            return None  # after the call nothing is gained by failing
        redacted = answer.get("result")
        return redacted if isinstance(redacted, str) and answer.get("redacted") else None
