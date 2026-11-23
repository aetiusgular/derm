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
#   accounts.py layout <slug>                  root: the account's signin/ and projects/
#   accounts.py trusted-dir <path>             anyone: every folder to it root's alone
#   accounts.py install-uninstaller <dir>      root: the undo, copied where only root writes
#   accounts.py verify-uninstaller             anyone: that copy is what the install recorded
#   accounts.py remove-uninstaller             root: with the last account
#   accounts.py tiocsti-off | tiocsti-restore  root: dev.tty.legacy_tiocsti, and its undo
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
# Review AI-8 (lane PF; note CC section 6; case 284): the undo lines run as
# root, so what they name lives where only root writes, as dpkg keeps a
# package's maintainer scripts in root's /var/lib/dpkg/info with their
# md5sums beside them (dpkg 1.22.6 here, run), and its sha256 is recorded
# in /etc/derm. Every folder from / to it is checked: Debian's policy 9.1.2
# makes /usr/local root:staff 2775 when /etc/staff-group-for-usr-local
# exists (https://www.debian.org/doc/debian-policy/ch-opersys), which would
# let group staff replace it.
UNINSTALLER = "/usr/local/libexec/derm/agent-user"
UNINSTALLER_FILES = (("uninstall.sh", 0o755), ("uninstall-account.sh", 0o755), ("accounts.py", 0o644))
UNINSTALLER_SUMS = "/etc/derm/uninstall.sha256"
# dev.tty.legacy_tiocsti (note CC section 4, option 4d; plan P5): 0 makes
# TIOCSTI, which pushes bytes into a terminal's input, fail with EIO for any
# process without CAP_SYS_ADMIN (Linux v6.18 and v7.0
# drivers/tty/tty_io.c:2277; the sysctl is new in 6.2, absent in 6.1; at 6.2
# itself it refuses every caller). systemd-sysctl applies /etc/sysctl.d at
# boot, the lexically last file winning for a key (systemd v255
# man/standard-conf.xml, "confd"), so a later file can set it back; the
# check reads the running value, not the file.
TIOCSTI = "/proc/sys/dev/tty/legacy_tiocsti"
TIOCSTI_CONF = "/etc/sysctl.d/90-derm-agents.conf"
TIOCSTI_BEFORE = "/etc/derm/tiocsti.before"
TIOCSTI_TEXT = """# derm: agent accounts (packaging/linux/agent-user). TIOCSTI pushes bytes
# into a terminal's input, which no agent account needs; 0 refuses it to
# every process without CAP_SYS_ADMIN (Linux 6.2 and later).
# Undo: the last account's uninstall.sh puts back the value from before the
# install (/etc/derm/tiocsti.before) and removes this file.
dev.tty.legacy_tiocsti = 0
"""
# Under each account home (contracts/projects.md section 2.2, which the
# base wrote; derm_core::project::layout names the same): the sign-in store
# and each harness's folder in it, and the projects' parent, the account's
# and 0700, made by the installer. A project's own folders are the helper's.
SIGNIN = "signin"
SIGNIN_HARNESSES = ("claude-code", "codex", "pi")
PROJECTS = "projects"
GROUP = "derm-agents"
PREFIX = "derm-"
HOMES = "/var/lib/derm/agents"
TABLE = "derm_agents"
# One form on every system (plans/parallel_build_accounts.md section 2, as
# integration narrowed it from acct_W section 7 and Tony's call of 20 Nov,
# acct_W 12.1): Windows takes a local account name of at most 20 characters
# (USER_INFO_1), so derm-<slug> leaves 15. useradd's own limit is 32
# (shadow 4.13, run by lane L2).
SLUG_MAX = 15
# derm-agent is wave 5's agents' user (install.sh --owner) and derm-agents
# the group every account is in; a slug starting agent- would give
# derm-agent-<x>, the name of wave 5's sudoers file for a person x.
RESERVED = ("agent", "agents")
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
    if not re.fullmatch(r"[a-z0-9-]+", slug or ""):
        return "a slug is 1 to 15 of a-z, 0-9 and -"
    if len(slug) > SLUG_MAX:
        return f"a slug is at most {SLUG_MAX} characters: Windows takes 20 characters for an account name and {PREFIX!r} is 5, and the slug is the same on every system"
    if slug in RESERVED or slug.startswith("agent-"):
        return f"the slug {slug!r} is reserved: derm-agent is wave 5's agents' user and derm-agents the accounts' group"
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
        if not isinstance(name, str) or not name.startswith(PREFIX) or slug_problem(name[len(PREFIX):]):
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
# Undo: sudo {UNINSTALLER}/uninstall.sh --account <slug> for each account, or
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


def _dir_problem(st, where):
    if not stat.S_ISDIR(st.st_mode):
        return f"{where} is not a folder"
    if st.st_uid != 0:
        return f"{where} is not root's (owner uid {st.st_uid})"
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return f"{where} is writable by others (mode {stat.S_IMODE(st.st_mode):o})"
    return None


def root_dir_fd(path, make=False):
    """An open fd of `path`, after every folder from / to it was opened
    without following a link and found root's and writable by no one else.
    With `make`, a missing folder is made (root's, 0755) under the open one
    above it. Raises Refused."""
    if not path.startswith("/") or "//" in path or path.endswith("/") or any(p in (".", "..") for p in path.split("/")):
        raise Refused(f"{path} is not a plain absolute path")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    where = "/"
    try:
        problem = _dir_problem(os.fstat(fd), where)
        if problem:
            raise Refused(problem)
        for part in path.strip("/").split("/"):
            where = where.rstrip("/") + "/" + part
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            try:
                nfd = os.open(part, flags, dir_fd=fd)
            except FileNotFoundError:
                if not make:
                    raise Refused(f"{where} is missing")
                os.mkdir(part, 0o755, dir_fd=fd)
                nfd = os.open(part, flags, dir_fd=fd)
                os.fchown(nfd, 0, 0)
                os.fchmod(nfd, 0o755)
            except OSError as e:
                if e.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise Refused(f"{where} is a link or not a folder")
                raise
            os.close(fd)
            fd = nfd
            problem = _dir_problem(os.fstat(fd), where)
            if problem:
                raise Refused(problem)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_at(dir_fd, name, limit=1 << 20):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Refused(f"{name} is not a regular file")
        data = b""
        while len(data) <= limit:
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                break
            data += chunk
        if len(data) > limit:
            raise Refused(f"{name} is over {limit} bytes")
        return st, data
    finally:
        os.close(fd)


def _write_at(dir_fd, name, data, mode):
    """Writes `name` in the open folder as a new file renamed over the old
    one, never through a link."""
    tmp = "." + name + ".new"
    try:
        os.unlink(tmp, dir_fd=dir_fd)
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=dir_fd)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fchown(fd, 0, 0)
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.rename(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)


def sums_text(digests):
    """sha256sum's own format, absolute paths: `sha256sum -c` reads it
    from any folder."""
    return "".join(f"{digests[name]}  {UNINSTALLER}/{name}\n" for name, _ in UNINSTALLER_FILES)


def cmd_install_uninstaller(src):
    """Copies the undo into UNINSTALLER and records each file's sha256 in
    UNINSTALLER_SUMS. The hash is of the bytes as read back from the copy."""
    need_root()
    fd = root_dir_fd(UNINSTALLER, make=True)
    try:
        digests = {}
        for name, mode in UNINSTALLER_FILES:
            with open(os.path.join(src, name), "rb") as f:
                data = f.read()
            _write_at(fd, name, data, mode)
            st, back = _read_at(fd, name)
            if back != data or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != mode:
                raise Refused(f"{UNINSTALLER}/{name} is not what was copied")
            digests[name] = hashlib.sha256(back).hexdigest()
    finally:
        os.close(fd)
    etc = root_dir_fd(os.path.dirname(UNINSTALLER_SUMS), make=True)
    try:
        _write_at(etc, os.path.basename(UNINSTALLER_SUMS), sums_text(digests).encode(), 0o644)
    finally:
        os.close(etc)
    return digests


def uninstaller_problem():
    """None when the copy is whole: every folder to it root's and writable
    by no one else, each file a regular file of root's that only root can
    write, with the sha256 the install recorded. Else why not."""
    try:
        trusted_regular(UNINSTALLER_SUMS, "the uninstaller's sums")
        with open(UNINSTALLER_SUMS, "rb") as f:
            recorded = f.read(1 << 16)
        fd = root_dir_fd(UNINSTALLER)
    except Refused as e:
        return str(e)
    except OSError as e:
        return f"{UNINSTALLER_SUMS}: {e.strerror}"
    try:
        digests = {}
        for name, mode in UNINSTALLER_FILES:
            try:
                st, data = _read_at(fd, name)
            except FileNotFoundError:
                return f"{UNINSTALLER}/{name} is missing"
            except OSError as e:
                return f"{UNINSTALLER}/{name}: {e.strerror}"
            if st.st_uid != 0 or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                return f"{UNINSTALLER}/{name} is not root's alone (owner uid {st.st_uid}, mode {stat.S_IMODE(st.st_mode):o})"
            digests[name] = hashlib.sha256(data).hexdigest()
    except Refused as e:
        return f"{UNINSTALLER}: {e}"
    finally:
        os.close(fd)
    if recorded != sums_text(digests).encode():
        return f"{UNINSTALLER} is not what the install recorded in {UNINSTALLER_SUMS}"
    return None


def cmd_remove_uninstaller():
    need_root()
    for path in [os.path.join(UNINSTALLER, n) for n, _ in UNINSTALLER_FILES] + [UNINSTALLER_SUMS]:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
    for d in (UNINSTALLER, os.path.dirname(UNINSTALLER)):
        try:
            os.rmdir(d)
        except OSError:
            pass


def tiocsti_value():
    """'0' or '1', or None on a kernel without the sysctl (before 6.2)."""
    try:
        with open(TIOCSTI) as f:
            return f.read().strip()
    except FileNotFoundError:
        return None


def cmd_tiocsti_off():
    """Records the value before the first install, writes the boot file
    and sets 0 now. Prints the value now, or 'absent'."""
    need_root()
    before = tiocsti_value()
    if before is None:
        print("absent")
        return
    if before not in ("0", "1"):
        raise Refused(f"{TIOCSTI} reads {before!r}, not 0 or 1")
    etc = root_dir_fd(os.path.dirname(TIOCSTI_BEFORE), make=True)
    try:
        if not os.path.lexists(TIOCSTI_BEFORE):
            _write_at(etc, os.path.basename(TIOCSTI_BEFORE), (before + "\n").encode(), 0o644)
        else:
            trusted_regular(TIOCSTI_BEFORE, "the value from before the install")
    finally:
        os.close(etc)
    sysctl_d = root_dir_fd(os.path.dirname(TIOCSTI_CONF), make=True)
    try:
        _write_at(sysctl_d, os.path.basename(TIOCSTI_CONF), TIOCSTI_TEXT.encode(), 0o644)
    finally:
        os.close(sysctl_d)
    with open(TIOCSTI, "w") as f:
        f.write("0")
    now = tiocsti_value()
    if now != "0":
        raise Refused(f"{TIOCSTI} reads {now!r} after writing 0")
    print(now)


def cmd_tiocsti_restore():
    """With the last account: the value from before the install, back, and
    the boot file gone. Prints what it set, or 'kept' when there is nothing
    recorded (an install before this step, or a kernel without the sysctl)."""
    need_root()
    if not os.path.lexists(TIOCSTI_BEFORE):
        print("kept")
        return
    trusted_regular(TIOCSTI_BEFORE, "the value from before the install")
    with open(TIOCSTI_BEFORE) as f:
        before = f.read().strip()
    if before not in ("0", "1"):
        raise Refused(f"{TIOCSTI_BEFORE} holds {before!r}, not 0 or 1; set dev.tty.legacy_tiocsti by hand")
    try:
        os.unlink(TIOCSTI_CONF)
    except FileNotFoundError:
        pass
    if tiocsti_value() is not None:
        with open(TIOCSTI, "w") as f:
            f.write(before)
    os.unlink(TIOCSTI_BEFORE)
    print(before)


def layout_problems(home, uid, gid=None, make=False):
    """The account's signin/, signin/<harness>/ and projects/ under its
    home: real folders (no link), the account's, 0700. With `make` (root),
    a missing one is made and an existing one given that owner and mode,
    every step through an open folder and never through a link
    (contracts/projects.md 2.2; the shape of case 273). Returns the
    problems, or None when the home cannot be read (another user)."""
    problems = []
    try:
        parent = os.open(os.path.dirname(home), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as e:
        return [f"{os.path.dirname(home)}: {e.strerror}"]
    try:
        try:
            hfd = os.open(os.path.basename(home), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        except PermissionError:
            return None
        except OSError as e:
            return [f"{home}: {e.strerror}"]
    finally:
        os.close(parent)
    try:
        st = os.fstat(hfd)
        if st.st_uid != uid or stat.S_IMODE(st.st_mode) & 0o077:
            return [f"{home} is not its own 0700 folder"]

        def one(dfd, name, where):
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            try:
                fd = os.open(name, flags, dir_fd=dfd)
            except FileNotFoundError:
                if not make:
                    problems.append(f"{where} is missing")
                    return None
                os.mkdir(name, 0o700, dir_fd=dfd)
                fd = os.open(name, flags, dir_fd=dfd)
            except PermissionError:
                problems.append(f"{where} cannot be opened")
                return None
            except OSError as e:
                if e.errno in (errno.ELOOP, errno.ENOTDIR):
                    problems.append(f"{where} is a link or not a folder; move it away and run the install again")
                else:
                    problems.append(f"{where}: {e.strerror}")
                return None
            if make:
                os.fchown(fd, uid, gid)
                os.fchmod(fd, 0o700)
            s2 = os.fstat(fd)
            if s2.st_uid != uid or stat.S_IMODE(s2.st_mode) != 0o700:
                problems.append(f"{where} is not the account's 0700 folder (owner uid {s2.st_uid}, mode {stat.S_IMODE(s2.st_mode):o})")
            return fd

        sfd = one(hfd, SIGNIN, f"{home}/{SIGNIN}")
        if sfd is not None:
            for h in SIGNIN_HARNESSES:
                fd = one(sfd, h, f"{home}/{SIGNIN}/{h}")
                if fd is not None:
                    os.close(fd)
            os.close(sfd)
        pfd = one(hfd, PROJECTS, f"{home}/{PROJECTS}")
        if pfd is not None:
            os.close(pfd)
    finally:
        os.close(hfd)
    return problems


def cmd_layout(slug):
    need_root()
    p = slug_problem(slug)
    if p:
        raise Refused(p)
    try:
        pw = pwd.getpwnam(account_name(slug))
    except KeyError:
        raise Refused(f"no user {account_name(slug)}")
    home = home_of(slug)
    if pw.pw_dir != home:
        raise Refused(f"{pw.pw_name} has home {pw.pw_dir}, not {home}")
    fd = root_dir_fd(os.path.dirname(home))
    os.close(fd)
    problems = layout_problems(home, pw.pw_uid, pw.pw_gid, make=True)
    if problems:
        raise Refused("; ".join(problems))


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
        check_layout(rep, name, a["home"], pw.pw_uid)

    check_machine(rep)
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


def check_layout(rep, name, home, uid):
    """The account's signin/ and projects/ (contracts/projects.md 2.2). Its
    home is 0700, so only root and the account can look; anyone else skips."""
    problems = layout_problems(home, uid)
    slug = name[len(PREFIX):]
    if problems is None:
        rep.skip(f"folders of {name}", f"{home} is the account's own; check --probe as {name}, or as root, looks inside")
    elif problems:
        rep.fail(f"folders of {name}", "; ".join(problems), "run " + UNDO.replace("<slug>", slug))
    else:
        rep.ok(f"folders of {name}", f"{SIGNIN}/ ({', '.join(SIGNIN_HARNESSES)}) and {PROJECTS}/, its own, 0700")


def check_machine(rep):
    """What the install sets once for every account: the undo where only
    root writes (AI-8), and TIOCSTI off (note CC 4d)."""
    problem = uninstaller_problem()
    if problem:
        rep.fail("uninstaller", problem, "run " + UNDO + " again, which copies it and records it anew")
    else:
        rep.ok("uninstaller", f"{UNINSTALLER}/uninstall.sh, root's, as recorded in {UNINSTALLER_SUMS}")
    value = tiocsti_value()
    if value is None:
        rep.skip("TIOCSTI", "this kernel has no dev.tty.legacy_tiocsti (Linux 6.2 and later have it): it cannot be turned off here")
        return
    if value != "0":
        rep.fail("TIOCSTI", f"dev.tty.legacy_tiocsti is {value}: a process can push bytes into its terminal's input",
                 f"sudo sysctl -w dev.tty.legacy_tiocsti=0; a file in /etc/sysctl.d, /run/sysctl.d or /usr/lib/sysctl.d named after {os.path.basename(TIOCSTI_CONF)} may set it back at boot")
        return
    try:
        trusted_regular(TIOCSTI_CONF, "the boot setting")
        with open(TIOCSTI_CONF, encoding="utf-8") as f:
            same = f.read() == TIOCSTI_TEXT
    except (Refused, OSError) as e:
        rep.fail("TIOCSTI", f"off now, but {e}: it comes back on at the next boot", "run " + UNDO + " again")
        return
    if not same:
        rep.fail("TIOCSTI", f"off now, but {TIOCSTI_CONF} is not the shipped text", "run " + UNDO + " again")
    else:
        rep.ok("TIOCSTI", f"dev.tty.legacy_tiocsti is 0, and {TIOCSTI_CONF} keeps it at boot")


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
        rep.fail("probe", f"uid {me} is not an agent account", "run it as one: sudo -n -u derm-<slug> python3 -I " + HELPER + " check --probe")
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
        if cmd == "trusted-dir" and len(rest) == 1:
            os.close(root_dir_fd(rest[0]))
            return 0
        if cmd == "layout" and len(rest) == 1:
            cmd_layout(rest[0])
            return 0
        if cmd == "install-uninstaller" and len(rest) == 1:
            cmd_install_uninstaller(rest[0])
            return 0
        if cmd == "verify-uninstaller" and not rest:
            problem = uninstaller_problem()
            if problem:
                print(f"accounts.py: {problem}", file=sys.stderr)
                return 1
            return 0
        if cmd == "remove-uninstaller" and not rest:
            cmd_remove_uninstaller()
            return 0
        if cmd == "tiocsti-off" and not rest:
            cmd_tiocsti_off()
            return 0
        if cmd == "tiocsti-restore" and not rest:
            cmd_tiocsti_restore()
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
