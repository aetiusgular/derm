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
import sys
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


#: macOS's ``admin`` group: Homebrew's installer gives its prefix folders, never a
#: file, ``g+rwx`` with it for an admin (Homebrew/install install.sh at 7986efa,
#: lines 182-192, 843-852). derm connect, the plugins' launcher and the in-process
#: clients read the same rule (MW5B-2, FP1-S8; case 112).
MACOS_ADMIN_GID = 80

#: The permissions macOS's ``ls -le`` prints that let their holder change a file or
#: a folder (Apple file_cmds-479, ls/print.c:243-262).
ACL_WRITE_PERMS = ("write", "append", "delete", "add_file", "add_subdirectory", "delete_child", "writeattr", "writeextattr", "writesecurity", "chown")


def acl_grants_write(ls: str) -> bool:
    """Whether ``ls -lden``'s output for one path holds an access list entry that
    lets anyone write (MW5B-1): each line after the first is
    `` <n>: <uuid>[ inherited] <allow|deny> <perm,...>`` (file_cmds-479,
    ls/print.c:322-385). An entry that is not a deny and names a write-class
    permission is open, whoever it names; a line that cannot be placed is open."""
    lines = ls.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    for line in lines[1:]:
        w = line.split()
        if not w or not w[0].endswith(":"):
            return True
        i = 2
        kind = w[i] if len(w) > i else None
        if kind == "inherited":
            i += 1
            kind = w[i] if len(w) > i else None
        if kind is None:
            return True
        if kind == "deny":
            continue
        perms = w[i + 1] if len(w) > i + 1 else None
        if perms is not None and any(p in ACL_WRITE_PERMS for p in perms.split(",")):
            return True
    return False


def parse_groups(text: str) -> Optional[list[int]]:
    """``/usr/bin/id -G``'s groups, or None when a word is not a number."""
    words = text.split()
    if not words or not all(w.isascii() and w.isdigit() for w in words):
        return None
    return [int(w) for w in words]


def group_write_trusted(gid: int, is_dir: bool, macos: bool, groups: Callable[[], Optional[list[int]]]) -> bool:
    """A group write bit lets in no one you do not already trust: only on a macOS
    folder whose group is ``admin``, when you are in it."""
    if not (macos and is_dir and gid == MACOS_ADMIN_GID):
        return False
    g = groups()
    return g is not None and MACOS_ADMIN_GID in g


def _macos_groups() -> Optional[list[int]]:
    try:
        r = subprocess.run(["/usr/bin/id", "-G"], env={}, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    return parse_groups(r.stdout) if r.returncode == 0 else None


def _macos_acl_open(path: Path) -> bool:
    try:
        r = subprocess.run(["/bin/ls", "-lden", "--", str(path)], env={}, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return True
    return r.returncode != 0 or acl_grants_write(r.stdout)


def _private(st: os.stat_result, path: Optional[Path] = None) -> bool:
    """Owned by you or root, no other write bit, no group write bit unless on a
    macOS folder of the admin group you are in, and on macOS no access list entry
    that lets anyone write (FP1-S1: the rule the other three readers apply)."""
    macos = sys.platform == "darwin"
    if st.st_uid not in (os.getuid(), 0) or st.st_mode & 0o002:
        return False
    if st.st_mode & 0o020 and not group_write_trusted(st.st_gid, stat.S_ISDIR(st.st_mode), macos, _macos_groups):
        return False
    if macos and path is not None and _macos_acl_open(path):
        return False
    return True


def trusted_file(path: Path, derm: bool = False) -> Optional[str]:
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
    if derm and real.name != "derm":
        # FP1-S2: a link may lead anywhere; only a file named derm runs.
        return f"{path} is not named derm"
    if not _private(st, real):
        return f"someone other than you may write {path}"
    if not _private(folder, real.parent):
        return f"someone other than you may write the folder of {path}"
    return None


def install_candidates(home: Path, macos: bool) -> list:
    """Where derm's own installs put it, in the order the plugins' launcher,
    the in-process clients and derm connect try them (one list, case 112;
    FP2-S9: Hermes had ~/.local/bin and /usr/bin only)."""
    brew = ["/opt/homebrew/bin/derm", "/usr/local/bin/derm"] if macos else ["/home/linuxbrew/.linuxbrew/bin/derm", "/usr/local/bin/derm"]
    return [home / ".local" / "bin" / "derm"] + [Path(b) for b in brew] + [Path("/usr/bin/derm")]


def find_derm(plugin_dir: Path = HERE, home: Optional[Path] = None, candidates: Optional[list] = None) -> str:
    """derm's absolute path (case 227). Raises with the reason when none can be trusted.

    Without a derm-path file the first derm that is there decides: one that is
    there and refused stops the search with its reason, as the plugins'
    launcher and the in-process clients stop (MW5B-5, BW5B-R3). ``candidates``
    replaces the install folders' list in tests.
    """
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
        why = trusted_file(derm, derm=True)
        if why is not None:
            raise RuntimeError(f"the derm {DERM_PATH_FILE} names is not used: {why}")
        return str(derm)
    home = home if home is not None else Path(os.path.expanduser("~"))
    if candidates is None:
        candidates = install_candidates(home, sys.platform == "darwin")
    for derm in candidates:
        if not os.path.lexists(derm):
            continue
        why = trusted_file(derm, derm=True)
        if why is None:
            return str(derm)
        raise RuntimeError(
            f"no derm found that only you can change: {derm} is there and not used ({why}); "
            "derm stops at the first derm it finds rather than run another, so fix that one or "
            "remove it, or run `derm connect hermes --gate`"
        )
    raise RuntimeError("no derm found that only you can change; run `derm connect hermes --gate`")


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
