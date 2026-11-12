"""Unit tests for derm_gate.py. Run: python3 -m unittest discover -s packages/derm-hermes-plugin/tests

The runner is faked except in the tests that start the real ``derm hook hermes``
(``RealDerm``): the binary in ``DERM_TEST_BIN``, else ``target/debug/derm`` of this
repository when it was built (``cargo build -p derm-cli``).
"""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("derm_gate", HERE.parent / "derm_gate.py")
derm_gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(derm_gate)


def fixed(answer):
    return lambda payload: answer


class GateMapping(unittest.TestCase):
    def test_allow_is_none(self):
        self.assertIsNone(derm_gate.Gate(fixed({"decision": "allow", "reason": "rule terminal"}), lambda: False).pre_tool_call("terminal", {"command": "ls"}))

    def test_allow_with_rewritten_args_is_modify(self):
        out = derm_gate.Gate(fixed({"decision": "allow", "reason": "r", "args": {"q": "x", "api_key": "[redacted by derm]"}}), lambda: False).pre_tool_call("mcp__exa__search", {"q": "x", "api_key": "k"})
        self.assertEqual(out, {"action": "modify", "args": {"q": "x", "api_key": "[redacted by derm]"}})

    def test_deny_is_block_with_message(self):
        self.assertEqual(derm_gate.Gate(fixed({"decision": "deny", "reason": "rule terminal"}), lambda: False).pre_tool_call("terminal", {}), {"action": "block", "message": "derm: rule terminal"})

    def test_ask_escalates_to_hermes_gate(self):
        out = derm_gate.Gate(fixed({"decision": "ask", "reason": "no rule"}), lambda: False).pre_tool_call("write_file", {})
        self.assertEqual(out["action"], "approve")
        self.assertIn("no rule", out["message"])

    def test_ask_under_yolo_blocks(self):
        out = derm_gate.Gate(fixed({"decision": "ask", "reason": "no rule"}), lambda: True).pre_tool_call("write_file", {})
        self.assertEqual(out["action"], "block")
        self.assertIn("approves everything", out["message"])

    def test_auto_approve_check_outside_hermes_says_true(self):
        # No `tools` package here: the check cannot be made, so it says true and an ask blocks.
        self.assertTrue(derm_gate.hermes_auto_approves())

    def test_every_failure_blocks(self):
        def boom(payload):
            raise RuntimeError("x")

        def slow(payload):
            raise subprocess.TimeoutExpired("node", 25)

        for runner in (boom, slow, fixed({}), fixed({"decision": "maybe"})):
            self.assertEqual(derm_gate.Gate(runner, lambda: False).pre_tool_call("terminal", {"command": "ls"})["action"], "block")

    def test_result_is_replaced_only_when_redacted(self):
        g = derm_gate.Gate(fixed({"result": "TOKEN=[redacted by derm]", "redacted": 1}), lambda: False)
        self.assertEqual(g.transform_tool_result("terminal", {}, "TOKEN=ghp_x"), "TOKEN=[redacted by derm]")
        self.assertIsNone(derm_gate.Gate(fixed({"redacted": 0}), lambda: False).transform_tool_result("terminal", {}, "ok"))

        def boom(payload):
            raise RuntimeError("x")

        self.assertIsNone(derm_gate.Gate(boom, lambda: False).transform_tool_result("terminal", {}, "ok"))

    def test_no_trusted_derm_blocks(self):
        # Case 227: derm is never looked up on PATH; with none it can trust, every call blocks.
        empty = tempfile.mkdtemp()
        try:
            def runner(payload):
                return derm_gate.derm_runner(payload, derm=derm_gate.find_derm(Path(empty), Path(empty)))

            out = derm_gate.Gate(runner, lambda: False).pre_tool_call("terminal", {"command": "ls"})
        finally:
            shutil.rmtree(empty, ignore_errors=True)
        self.assertEqual(out["action"], "block")
        self.assertIn("no derm found", out["message"])

    def test_a_refusal_before_any_dialect_still_blocks_with_its_reason(self):
        out = derm_gate.Gate(fixed({"action": "block", "message": "derm: unknown event"}), lambda: False).pre_tool_call("terminal", {})
        self.assertEqual(out, {"action": "block", "message": "derm: unknown event"})


class FindDerm(unittest.TestCase):
    """Case 227: the derm-path file, then the install folders, each a file only you can change."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        os.chmod(self.dir, 0o700)
        self.plugin = self.dir / "plugin"
        self.home = self.dir / "home"
        self.bin = self.dir / "bin"
        for d in (self.plugin, self.home, self.bin):
            d.mkdir(mode=0o700)
        self.derm = self.bin / "derm"
        self.derm.write_text("#!/bin/sh\n")
        os.chmod(self.derm, 0o755)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_the_derm_path_file_names_derm(self):
        f = self.plugin / "derm-path"
        f.write_text(f"{self.derm}\n")
        os.chmod(f, 0o600)
        self.assertEqual(derm_gate.find_derm(self.plugin, self.home), str(self.derm))

    def test_a_derm_others_may_write_is_refused(self):
        f = self.plugin / "derm-path"
        f.write_text(str(self.derm))
        os.chmod(f, 0o600)
        os.chmod(self.derm, 0o775)
        with self.assertRaises(RuntimeError) as e:
            derm_gate.find_derm(self.plugin, self.home)
        self.assertIn("someone other than you", str(e.exception))
        os.chmod(self.derm, 0o755)
        os.chmod(self.bin, 0o777)
        with self.assertRaises(RuntimeError) as e:
            derm_gate.find_derm(self.plugin, self.home)
        self.assertIn("folder of", str(e.exception))

    def test_a_derm_path_file_others_may_write_is_refused(self):
        f = self.plugin / "derm-path"
        f.write_text(str(self.derm))
        os.chmod(f, 0o666)
        with self.assertRaises(RuntimeError) as e:
            derm_gate.find_derm(self.plugin, self.home)
        self.assertIn("derm-path not used", str(e.exception))

    def test_a_derm_path_that_leads_to_another_program_is_refused(self):
        # The fix pass's review, FP1-S2: only a file named derm runs.
        other = self.bin / "sh"
        other.write_text("#!/bin/sh\n")
        os.chmod(other, 0o755)
        f = self.plugin / "derm-path"
        f.write_text(str(other))
        os.chmod(f, 0o600)
        with self.assertRaises(RuntimeError) as e:
            derm_gate.find_derm(self.plugin, self.home)
        self.assertIn("not named derm", str(e.exception))

    def test_a_relative_path_is_refused(self):
        f = self.plugin / "derm-path"
        f.write_text("derm")
        os.chmod(f, 0o600)
        with self.assertRaises(RuntimeError) as e:
            derm_gate.find_derm(self.plugin, self.home)
        self.assertIn("not an absolute path", str(e.exception))

    def test_the_user_install_folder_is_used_without_a_derm_path_file(self):
        local = self.home / ".local" / "bin"
        local.mkdir(parents=True, mode=0o700)
        (local / "derm").write_text("#!/bin/sh\n")
        os.chmod(local / "derm", 0o755)
        self.assertEqual(derm_gate.find_derm(self.plugin, self.home), str(local / "derm"))

    def test_a_refused_user_derm_stops_the_search_and_is_named(self):
        # MW5B-5, BW5B-R3: the first derm that is there decides; one that is
        # there and refused is named, never passed over for the system's.
        local = self.home / ".local" / "bin"
        local.mkdir(parents=True, mode=0o700)
        (local / "derm").write_text("#!/bin/sh\n")
        os.chmod(local / "derm", 0o757)
        with self.assertRaises(RuntimeError) as e:
            derm_gate.find_derm(self.plugin, self.home, candidates=[self.home / ".local" / "bin" / "derm", self.derm])
        self.assertIn(str(local / "derm"), str(e.exception))
        self.assertIn("stops at the first derm", str(e.exception))
        os.chmod(local / "derm", 0o755)
        self.assertEqual(derm_gate.find_derm(self.plugin, self.home, candidates=[self.home / ".local" / "bin" / "derm", self.derm]), str(local / "derm"))
        (local / "derm").unlink()
        self.assertEqual(derm_gate.find_derm(self.plugin, self.home, candidates=[self.home / ".local" / "bin" / "derm", self.derm]), str(self.derm))

    def test_the_install_folders_are_the_launchers(self):
        # FP2-S9: the same list, in the same order, as the launcher and the clients.
        h = Path("/h")
        self.assertEqual(
            [str(p) for p in derm_gate.install_candidates(h, False)],
            ["/h/.local/bin/derm", "/home/linuxbrew/.linuxbrew/bin/derm", "/usr/local/bin/derm", "/usr/bin/derm"],
        )
        self.assertEqual(
            [str(p) for p in derm_gate.install_candidates(h, True)],
            ["/h/.local/bin/derm", "/opt/homebrew/bin/derm", "/usr/local/bin/derm", "/usr/bin/derm"],
        )

    def test_path_is_never_searched(self):
        old = os.environ.get("PATH", "")
        os.environ["PATH"] = str(self.bin)
        try:
            if Path("/usr/bin/derm").exists():
                self.skipTest("/usr/bin/derm is installed here")
            with self.assertRaises(RuntimeError):
                derm_gate.find_derm(self.plugin, self.home)
        finally:
            os.environ["PATH"] = old


def _built_derm():
    given = os.environ.get("DERM_TEST_BIN")
    if given:
        return given
    built = HERE.parent.parent.parent / "target" / "debug" / "derm"
    return str(built) if built.is_file() else None


@unittest.skipIf(_built_derm() is None, "no derm binary built (cargo build -p derm-cli, or DERM_TEST_BIN)")
class RealDerm(unittest.TestCase):
    """derm hook hermes with a real policy file, no daemon."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.policy = os.path.join(self.dir, "policy.json")
        with open(self.policy, "w") as f:
            json.dump({"version": 1, "askTimeoutSeconds": 1, "servers": ["exa"], "rules": [
                {"tool": "terminal", "action": "allow"},
                {"tool": "exa/*", "action": "deny"},
                {"tool": "write_file", "action": "ask"},
            ]}, f)
        os.chmod(self.policy, 0o600)
        self.env = {"DERM_POLICY": self.policy, "DERM_DAEMON_SOCKET": os.path.join(self.dir, "absent.sock")}
        self.saved = {k: os.environ.get(k) for k in self.env}
        os.environ.update(self.env)
        derm = _built_derm()
        self.gate = derm_gate.Gate(lambda payload: derm_gate.derm_runner(payload, derm=derm), lambda: False)

    def tearDown(self):
        for k, v in self.saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_allowed_terminal_command(self):
        self.assertIsNone(self.gate.pre_tool_call("terminal", {"command": "ls -la"}, session_id="s", tool_call_id="c1"))

    def test_mcp_tool_denied_by_server_rule(self):
        out = self.gate.pre_tool_call("mcp__exa__web_search", {"query": "x"})
        # derm-core names the action after the rule (contracts/hook-dialects.md 9.3, rule 2).
        self.assertEqual(out, {"action": "block", "message": "derm: rule exa/* deny"})

    def test_reject_list(self):
        out = self.gate.pre_tool_call("terminal", {"command": "git -c core.sshCommand=x fetch"})
        self.assertEqual(out["action"], "block")
        self.assertIn("reject list: core.sshcommand", out["message"])

    def test_ask_with_no_approver_escalates(self):
        out = self.gate.pre_tool_call("write_file", {"path": "a", "content": "b"})
        self.assertEqual(out["action"], "approve")

    def test_hermes_control_file_asks(self):
        out = self.gate.pre_tool_call("terminal", {"command": "echo plugins.disabled derm >> /home/u/.hermes/config.yaml"})
        self.assertEqual(out["action"], "approve")
        self.assertIn("control file (.hermes/)", out["message"])

    def test_result_redaction(self):
        out = self.gate.transform_tool_result("terminal", {"command": "env"}, "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789AB\nok")
        self.assertIsNotNone(out)
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz0123456789AB", out)


class Register(unittest.TestCase):
    def test_register_wires_the_two_hooks(self):
        pkg_spec = importlib.util.spec_from_file_location("hermes_plugins.derm", HERE.parent / "__init__.py", submodule_search_locations=[str(HERE.parent)])
        mod = importlib.util.module_from_spec(pkg_spec)
        sys.modules["hermes_plugins.derm"] = mod
        pkg_spec.loader.exec_module(mod)
        seen = []

        class Ctx:
            def register_hook(self, name, cb):
                seen.append((name, cb))

        mod.register(Ctx())
        self.assertEqual([n for n, _ in seen], ["pre_tool_call", "transform_tool_result"])


if __name__ == "__main__":
    unittest.main()


class WhoElseMayWrite(unittest.TestCase):
    """FP1-S1: the fourth reader of derm's rule (derm connect, the launcher and
    the in-process clients are the others) reads macOS's access lists and
    Homebrew's admin group the same way (MW5B-1, MW5B-2)."""

    U = "ABCDEFAB-CDEF-ABCD-EFAB-CDEFABCDEF12"
    HEAD = "-rwxr-xr-x@ 1 501 20 6840512 Nov 11 16:00 /Users/u/.local/bin/derm\n"

    def test_an_access_list_line_is_read_as_the_other_readers_read_it(self):
        u = self.U
        cases = [
            (f" 0: {u} allow write", True),
            (" 0: group:everyone allow write", True),
            (f" 0: {u} inherited allow add_file,search,file_inherit", True),
            (f" 0: {u} allow read,execute,readattr,readextattr,readsecurity", False),
            (f" 0: {u} deny delete", False),
            (f" 0: {u} deny write,append,delete,chown", False),
            (f" 0: {u} unknown write", True),
            (f" 0: {u} allow ", False),
            (f" 0: {u}", True),
            (f" 0: {u} inherited", True),
            ("garbage", True),
        ]
        cases += [(f" 0: {u} allow {p}", True) for p in derm_gate.ACL_WRITE_PERMS]
        self.assertFalse(derm_gate.acl_grants_write(self.HEAD))
        for line, want in cases:
            self.assertEqual(derm_gate.acl_grants_write(f"{self.HEAD}{line}\n"), want, line)
        self.assertEqual(len(derm_gate.ACL_WRITE_PERMS), 10)
        # A blank line inside the list cannot be placed: open, as in Rust and TS.
        self.assertTrue(derm_gate.acl_grants_write(f"{self.HEAD}\n 0: {self.U} deny delete\n"))

    def test_the_admin_group_is_trusted_only_on_a_macos_folder_for_a_member(self):
        t = derm_gate.group_write_trusted
        self.assertTrue(t(80, True, True, lambda: [20, 80]))
        self.assertFalse(t(80, False, True, lambda: [20, 80]))
        self.assertFalse(t(80, True, True, lambda: [20]))
        self.assertFalse(t(80, True, True, lambda: None))
        self.assertFalse(t(20, True, True, lambda: [20, 80]))
        self.assertFalse(t(80, True, False, lambda: [20, 80]))
        self.assertEqual(derm_gate.parse_groups("20 12 80\n"), [20, 12, 80])
        self.assertIsNone(derm_gate.parse_groups("20 x"))
        self.assertIsNone(derm_gate.parse_groups(""))
