#!/usr/bin/env python3
# derm's agent accounts on Linux (plans/parallel_build_accounts.md, lane L2;
# note CB sections 2.1 and 5). One helper for install.sh, uninstall.sh and
# derm: it validates names, keeps /etc/derm/agents.json, writes the nftables
# table, and checks what is installed. Run it with `python3 -I`.
#
#   accounts.py check [--probe] [--json]       anyone; --probe as an agent account
#   accounts.py render                         the table for the installed accounts
#   accounts.py valid-slug <slug> | valid-label <label>
#   accounts.py upsert|remove ...              install.sh and uninstall.sh only (root)
#
# The check needs no privilege. `nft list` does: nfnetlink refuses every
# message from a socket without CAP_NET_ADMIN (Linux 6.18
# net/netfilter/nfnetlink.c:661), and nft 1.0.9 run as a plain user prints
# "Operation not permitted (you must be root)". So the check reads what root
# wrote (agents.json, agents.nft, the unit, the load marker), renders the
# table again and compares it byte for byte, and --probe, run as an agent
# account, sends real packets and expects the kernel to refuse them.

import errno
import grp
import hashlib
import json
import os
import pwd
import re
import socket
import stat
import sys
import time
import unicodedata

ANCHOR = "/etc/derm/agents.json"
RULES = "/etc/derm/agents.nft"
UNIT = "/etc/systemd/system/derm-agents-nft.service"
MARKER = "/run/derm/agents-nft.loaded"
HELPER = "/usr/local/lib/derm/agents.py"
GROUP = "derm-agents"
PREFIX = "derm-agent-"
HOMES = "/var/lib/derm/agents"
TABLE = "derm_agents"
# The contract allows 24 (plans/parallel_build_accounts.md section 2), but
# useradd refuses a login name over 32 characters (shadow 4.13 on Ubuntu
# 24.04, run: 33 characters gave "invalid user name"), and "derm-agent-" is
# 11 of them. Readers may accept 24; the installer makes nothing over 21.
SLUG_RE = re.compile(r"[a-z0-9-]{1,24}")
SLUG_MAX = 21
LABEL_MAX = 120
# TEST-NET-1 and the documentation prefix (RFC 5737, RFC 3849): nothing
# answers there, so a probe that is let through reaches no one.
PROBE_V4 = ("192.0.2.1", 9)
PROBE_V6 = ("2001:db8::1", 9)
# systemd-resolved's stub. The probe needs no resolver listening: with the
# table the kernel refuses the send before any socket on 127.0.0.53 is looked up.
PROBE_DNS = ("127.0.0.53", 53)


class Refused(Exception):
    pass


def slug_problem(slug):
    if not SLUG_RE.fullmatch(slug or ""):
        return "a slug is 1 to 24 of a-z, 0-9 and -"
    if len(slug) > SLUG_MAX:
        return f"a slug is at most {SLUG_MAX} characters here: useradd takes 32 and {PREFIX!r} is 11"
    return None


def label_problem(label):
    if not label:
        return "the subscription label is empty"
    if len(label) > LABEL_MAX:
        return f"the subscription label is over {LABEL_MAX} characters"
    for ch in label:
        # Control characters and format characters (bidi overrides, zero
        # width) would change how the label looks when it is shown back.
        if unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp", "Cs", "Co", "Cn"):
            return f"the subscription label holds U+{ord(ch):04X}, which is not shown as itself"
    return None


def account_name(slug):
    return PREFIX + slug


def home_of(slug):
    return f"{HOMES}/{slug}"


def trusted_regular(path, what):
    """lstat checks for a file root wrote: regular, not a link, root's, not group or world writable."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise Refused(f"{what} {path} is missing")
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise Refused(f"{what} {path} is not a regular file")
    if st.st_uid != 0:
        raise Refused(f"{what} {path} is not root's (owner uid {st.st_uid})")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise Refused(f"{what} {path} is writable by others (mode {stat.S_IMODE(st.st_mode):o})")
    return st


def read_anchor(path=ANCHOR):
    """The contract's reader: None when there is no file, else the parsed data, else Refused."""
    if not os.path.lexists(path):
        return None
    trusted_regular(path, "the accounts file")
    with open(path, "rb") as f:
        raw = f.read(1 << 20)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise Refused(f"the accounts file {path} does not parse: {e}")
    shape_problem = anchor_shape_problem(data)
    if shape_problem:
        raise Refused(f"the accounts file {path}: {shape_problem}")
    return data


def anchor_shape_problem(data):
    if not isinstance(data, dict) or set(data) != {"version", "group", "accounts"}:
        return "the top level is not exactly version, group and accounts"
    if data["version"] != 1 or isinstance(data["version"], bool):
        return "version is not 1"
    if data["group"] != GROUP:
        return f"group is not {GROUP}"
    if not isinstance(data["accounts"], list):
        return "accounts is not a list"
    seen = set()
    for a in data["accounts"]:
        if not isinstance(a, dict) or set(a) != {"name", "uid", "subscription", "home"}:
            return "an account is not exactly name, uid, subscription and home"
        name = a["name"]
        if not isinstance(name, str) or not name.startswith(PREFIX) or not SLUG_RE.fullmatch(name[len(PREFIX):]):
            return f"account name {name!r} is not {PREFIX}<slug>"
        slug = name[len(PREFIX):]
        if not isinstance(a["uid"], int) or isinstance(a["uid"], bool) or a["uid"] <= 0:
            return f"{name}: uid is not a positive number"
        if not isinstance(a["subscription"], str) or label_problem(a["subscription"]):
            return f"{name}: the subscription label is not plain text"
        if a["home"] != home_of(slug):
            return f"{name}: home is not {home_of(slug)}"
        if name in seen or a["uid"] in seen:
            return f"{name}: listed twice"
        seen.add(name)
        seen.add(a["uid"])
    return None


def write_anchor(data, path=ANCHOR):
    problem = anchor_shape_problem(data)
    if problem:
        raise Refused(f"refusing to write {path}: {problem}")
    os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
    tmp = path + ".new"
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def render(gid, uids):
    """The table, byte for byte: install.sh loads it and check compares it."""
    if not uids:
        raise Refused("no accounts: there is no table to write")
    elements = ", ".join(str(u) for u in sorted(set(uids)))
    return f"""#!/usr/sbin/nft -f
# derm: agent accounts reach loopback only (packaging/linux/agent-user).
# Written by install.sh and uninstall.sh from {ANCHOR}; do not edit:
# both write it again, and `accounts.py check` compares it byte for byte.
# Undo: uninstall.sh --account <slug> for each account, or
#   nft delete table inet {TABLE}
table inet {TABLE}
delete table inet {TABLE}
table inet {TABLE} {{
	# Every account by uid as well as by group: a set-group-id program
	# changes the socket's fsgid (meta skgid reads the socket file's fsgid,
	# Linux 6.18 net/netfilter/nft_meta.c:152-154), a set-user-id one its fsuid.
	set uids {{
		type uid
		elements = {{ {elements} }}
	}}

	chain output {{
		type filter hook output priority filter; policy accept;
		meta skgid {gid} jump agents
		meta skuid @uids jump agents
	}}

	# Reject, not drop: a dropped TCP SYN is resent until connect() times
	# out; a reject fails it at once (EHOSTUNREACH), and UDP gets EPERM.
	chain agents {{
		meta l4proto {{ tcp, udp }} th dport 53 counter reject with icmpx admin-prohibited
		oif "lo" ip daddr 127.0.0.0/8 accept
		oif "lo" ip6 daddr ::1 accept
		counter reject with icmpx admin-prohibited
	}}
}}
"""


def group_gid():
    try:
        return grp.getgrnam(GROUP).gr_gid
    except KeyError:
        raise Refused(f"there is no group {GROUP}")


def render_installed(path=ANCHOR):
    data = read_anchor(path)
    if not data or not data["accounts"]:
        raise Refused("no accounts are installed")
    return render(group_gid(), [a["uid"] for a in data["accounts"]])


def boot_id():
    with open("/proc/sys/kernel/random/boot_id") as f:
        return f.read().strip()


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def unit_text(here):
    with open(os.path.join(here, "derm-agents-nft.service"), encoding="utf-8") as f:
        return f.read()


# --- the check -------------------------------------------------------------


class Report:
    def __init__(self):
        self.items = []

    def ok(self, name, detail=""):
        self.items.append({"check": name, "ok": True, "detail": detail})

    def fail(self, name, detail, fix):
        self.items.append({"check": name, "ok": False, "detail": detail, "fix": fix})

    def skip(self, name, detail):
        self.items.append({"check": name, "ok": True, "skipped": True, "detail": detail})

    @property
    def passed(self):
        return all(i["ok"] for i in self.items)


UNDO = "sudo packaging/linux/agent-user/install.sh --account <slug> --subscription <label>"


def check_static(rep, anchor=ANCHOR, rules=RULES, marker=MARKER, unit=UNIT, here=None):
    try:
        data = read_anchor(anchor)
    except Refused as e:
        rep.fail("accounts file", str(e), "fix or remove it as root, then run " + UNDO)
        return None
    if data is None:
        rep.fail("accounts file", f"{anchor} is missing: no agent accounts", "run " + UNDO)
        return None
    rep.ok("accounts file", f"{len(data['accounts'])} account(s)")

    try:
        g = grp.getgrnam(GROUP)
        gid = g.gr_gid
    except KeyError:
        rep.fail("group", f"there is no group {GROUP}", "run " + UNDO)
        return data
    if g.gr_mem:
        rep.fail("group", f"{GROUP} has members besides its accounts: {', '.join(g.gr_mem)}",
                 f"remove them (gpasswd -d <user> {GROUP})")
    else:
        rep.ok("group", f"{GROUP} is gid {gid}")

    for a in data["accounts"]:
        name = a["name"]
        try:
            pw = pwd.getpwnam(name)
        except KeyError:
            rep.fail(f"account {name}", "no such user", "run " + UNDO)
            continue
        problems = []
        if pw.pw_uid != a["uid"]:
            problems.append(f"uid is {pw.pw_uid}, the file says {a['uid']}")
        if pw.pw_gid != gid:
            problems.append(f"primary group is gid {pw.pw_gid}, not {GROUP}")
        others = [x.gr_name for x in grp.getgrall() if name in x.gr_mem]
        if others:
            problems.append(f"also in {', '.join(others)}")
        if pw.pw_dir != a["home"]:
            problems.append(f"home is {pw.pw_dir}")
        try:
            hs = os.lstat(a["home"])
            if not stat.S_ISDIR(hs.st_mode) or hs.st_uid != pw.pw_uid or stat.S_IMODE(hs.st_mode) & 0o077:
                problems.append(f"{a['home']} is not its own 0700 folder")
        except OSError as e:
            problems.append(f"{a['home']}: {e.strerror}")
        if problems:
            rep.fail(f"account {name}", "; ".join(problems), "run " + UNDO.replace("<slug>", name[len(PREFIX):]))
        else:
            rep.ok(f"account {name}", f"uid {pw.pw_uid}, only in {GROUP}")

    if not data["accounts"]:
        rep.fail("table file", "no accounts", "run " + UNDO)
        return data
    want = render(gid, [a["uid"] for a in data["accounts"]])
    try:
        trusted_regular(rules, "the table file")
        with open(rules, encoding="utf-8") as f:
            have = f.read()
        if have != want:
            rep.fail("table file", f"{rules} is not the table for these accounts", "run " + UNDO)
        else:
            rep.ok("table file", rules)
    except Refused as e:
        rep.fail("table file", str(e), "run " + UNDO)
        have = None

    if os.path.isdir("/run/systemd/system"):
        try:
            trusted_regular(unit, "the unit")
            here = here or os.path.dirname(os.path.abspath(__file__))
            with open(unit, encoding="utf-8") as f:
                if here and os.path.exists(os.path.join(here, "derm-agents-nft.service")) and f.read() != unit_text(here):
                    rep.fail("unit", f"{unit} is not the shipped unit", "run " + UNDO)
                else:
                    rep.ok("unit", unit)
        except Refused as e:
            rep.fail("unit", str(e) + ": the table will not come back after a reboot", "run " + UNDO)
    else:
        rep.skip("unit", "systemd is not running here (sd_booted: no /run/systemd/system); nothing loads the table at boot")

    try:
        trusted_regular(marker, "the load marker")
        with open(marker, encoding="utf-8") as f:
            lines = f.read().split("\n")
        loaded_boot = lines[0].strip() if lines else ""
        loaded_hash = lines[1].split()[0] if len(lines) > 1 and lines[1].split() else ""
        if loaded_boot != boot_id():
            rep.fail("loaded", "the table was not loaded since this boot", "sudo systemctl restart derm-agents-nft, or run " + UNDO)
        elif have is not None and loaded_hash != hashlib.sha256(have.encode("utf-8")).hexdigest():
            rep.fail("loaded", "the loaded table is not the table file", "sudo systemctl restart derm-agents-nft")
        else:
            rep.ok("loaded", "this boot, this table (root-written marker; --probe shows the kernel)")
    except (Refused, OSError) as e:
        rep.fail("loaded", str(e), "sudo systemctl restart derm-agents-nft, or run " + UNDO)
    return data


def send_errno(family, typ, addr, timeout=3.0):
    """Errno name of a send (UDP) or connect (TCP) to addr, 'ok', or 'timeout'."""
    try:
        s = socket.socket(family, typ)
    except OSError as e:
        return "unsupported:" + errno.errorcode.get(e.errno, str(e.errno))
    s.settimeout(timeout)
    try:
        if typ == socket.SOCK_DGRAM:
            s.sendto(b"derm-probe", addr)
        else:
            s.connect(addr)
        return "ok"
    except socket.timeout:
        return "timeout"
    except OSError as e:
        return errno.errorcode.get(e.errno, str(e.errno))
    finally:
        s.close()


def check_probe(rep, data):
    me = os.getuid()
    names = {a["uid"]: a["name"] for a in (data or {}).get("accounts", [])}
    if me not in names:
        rep.fail("probe", f"uid {me} is not an agent account", "run it as one: sudo -n -u derm-agent-<slug> python3 -I " + HELPER + " check --probe")
        return
    # Loopback: a UDP socket of our own on 127.0.0.1 takes the datagram.
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", 0))
    rx.settimeout(2)
    got = send_errno(socket.AF_INET, socket.SOCK_DGRAM, rx.getsockname())
    try:
        reached = got == "ok" and rx.recv(64) == b"derm-probe"
    except OSError:
        reached = False
    rx.close()
    if reached:
        rep.ok("probe: loopback", f"{names[me]} reaches 127.0.0.1")
    else:
        rep.fail("probe: loopback", f"{names[me]} cannot reach 127.0.0.1 ({got})", "the table refuses loopback; run " + UNDO)

    # What the kernel says when the table refuses: EPERM for a datagram (the
    # output hook's verdict reaches sendto), EHOSTUNREACH for a TCP connect
    # (the reject's ICMP admin-prohibited). Anything else, such as a quick
    # ECONNREFUSED from the network, is not the table's answer.
    cases = [
        ("probe: outbound UDP", socket.AF_INET, socket.SOCK_DGRAM, PROBE_V4, {"EPERM"}),
        ("probe: outbound TCP", socket.AF_INET, socket.SOCK_STREAM, PROBE_V4, {"EHOSTUNREACH", "EPERM"}),
        ("probe: DNS on loopback", socket.AF_INET, socket.SOCK_DGRAM, PROBE_DNS, {"EPERM"}),
        ("probe: outbound UDP over IPv6", socket.AF_INET6, socket.SOCK_DGRAM, PROBE_V6, {"EPERM"}),
    ]
    for name, fam, typ, addr, refused in cases:
        t0 = time.monotonic()
        got = send_errno(fam, typ, addr)
        took = time.monotonic() - t0
        if got.startswith("unsupported:") or (fam == socket.AF_INET6 and got in ("ENETUNREACH", "EADDRNOTAVAIL") and not has_v6_route()):
            rep.skip(name, f"no IPv6 here ({got})")
        elif got in refused and took < 1.0:
            rep.ok(name, f"{addr[0]} refused at once ({got})")
        else:
            rep.fail(name, f"{addr[0]} was not refused by the table ({got} after {took:.1f}s)",
                     "the table is not loaded: sudo systemctl restart derm-agents-nft, or run " + UNDO)


def has_v6_route():
    try:
        with open("/proc/net/ipv6_route") as f:
            return any(line.split()[0] == "0" * 32 and line.split()[9] != "lo" for line in f)
    except OSError:
        return False


def print_report(rep, as_json):
    if as_json:
        print(json.dumps({"ok": rep.passed, "checks": rep.items}, indent=2))
        return
    for i in rep.items:
        mark = "skip" if i.get("skipped") else ("ok  " if i["ok"] else "FAIL")
        print(f"{mark} {i['check']}: {i['detail']}")
        if not i["ok"]:
            print(f"     fix: {i['fix']}")
    print("agent accounts: " + ("ok" if rep.passed else "not ok"))


# --- install.sh and uninstall.sh -------------------------------------------


def need_root():
    if os.geteuid() != 0:
        raise Refused("this step runs as root (install.sh and uninstall.sh call it)")


def cmd_upsert(slug, uid, label):
    need_root()
    for p in (slug_problem(slug), label_problem(label)):
        if p:
            raise Refused(p)
    data = read_anchor() or {"version": 1, "group": GROUP, "accounts": []}
    entry = {"name": account_name(slug), "uid": int(uid), "subscription": label, "home": home_of(slug)}
    for i, a in enumerate(data["accounts"]):
        if a["name"] == entry["name"]:
            data["accounts"][i] = entry
            break
        if a["uid"] == entry["uid"]:
            raise Refused(f"uid {uid} is already {a['name']} in {ANCHOR}")
    else:
        data["accounts"].append(entry)
    write_anchor(data)


def cmd_remove(slug):
    need_root()
    data = read_anchor()
    if data is None:
        print("0")
        return
    data["accounts"] = [a for a in data["accounts"] if a["name"] != account_name(slug)]
    if data["accounts"]:
        write_anchor(data)
    else:
        os.unlink(ANCHOR)
    print(len(data["accounts"]))


def cmd_marker(rules=RULES, marker=MARKER):
    need_root()
    os.makedirs(os.path.dirname(marker), mode=0o755, exist_ok=True)
    tmp = marker + ".new"
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "w") as f:
        f.write(f"{boot_id()}\n{sha256(rules)}  {rules}\n")
    os.replace(tmp, marker)


def main(argv):
    if not argv:
        print(__doc__ or "usage: accounts.py check|render|valid-slug|valid-label|upsert|remove|marker", file=sys.stderr)
        return 2
    cmd, rest = argv[0], argv[1:]
    try:
        if cmd == "check":
            opts = set(rest)
            unknown = opts - {"--probe", "--json"}
            if unknown:
                print(f"accounts.py check: unknown {', '.join(sorted(unknown))}", file=sys.stderr)
                return 2
            rep = Report()
            data = check_static(rep)
            if "--probe" in opts:
                check_probe(rep, data)
            print_report(rep, "--json" in opts)
            return 0 if rep.passed else 1
        if cmd == "render":
            if rest[:1] == ["--gid"]:
                # render --gid <gid> --uid <uid>...: for tests and dry runs
                gid = int(rest[1])
                uids = [int(rest[i + 1]) for i in range(2, len(rest), 2) if rest[i] == "--uid"]
                sys.stdout.write(render(gid, uids))
            else:
                sys.stdout.write(render_installed())
            return 0
        if cmd == "valid-slug" and len(rest) == 1:
            p = slug_problem(rest[0])
            if p:
                print(p, file=sys.stderr)
                return 1
            return 0
        if cmd == "valid-label" and len(rest) == 1:
            p = label_problem(rest[0])
            if p:
                print(p, file=sys.stderr)
                return 1
            return 0
        if cmd == "upsert" and len(rest) == 3:
            cmd_upsert(rest[0], rest[1], rest[2])
            return 0
        if cmd == "remove" and len(rest) == 1:
            cmd_remove(rest[0])
            return 0
        if cmd == "marker" and not rest:
            cmd_marker()
            return 0
        if cmd == "anchor-names" and not rest:
            data = read_anchor()
            for a in (data or {}).get("accounts", []):
                print(a["name"])
            return 0
    except Refused as e:
        print(f"accounts.py: {e}", file=sys.stderr)
        return 1
    print(f"accounts.py: unknown command {' '.join(argv)!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
