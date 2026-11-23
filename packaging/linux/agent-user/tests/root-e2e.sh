#!/bin/bash
# End-to-end test of the agent-account installer with real users, the real
# nftables table and real sockets (accounts build, lane L2). It changes the
# system as root: run it only on a throwaway machine (a cloud workspace, a
# VM), never on a person's box or Mac.
#
#   sudo DERM_L2_ROOT_TEST=1 packaging/linux/agent-user/tests/root-e2e.sh
#
# It refuses to start when an agent account, /etc/derm/agents.json or the
# table already exists, makes two people (an owner and another user) and two
# agent accounts, checks what each can reach, tampers with each file, removes
# everything, and checks that nothing is left. Exit 0 when every case passed.

set -uo pipefail
export LC_ALL=C

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
PY=/usr/bin/python3
NFT=/usr/sbin/nft
INSTALL="$HERE/install.sh"
UNINSTALL="$HERE/uninstall.sh"
HELPER=/usr/local/lib/derm/agents.py
LIBEXEC=/usr/local/libexec/derm/agent-user
ROOT_UNINSTALL="$LIBEXEC/uninstall.sh"
SUMS=/etc/derm/uninstall.sha256
TIOCSTI=/proc/sys/dev/tty/legacy_tiocsti
SYSCTL_CONF=/etc/sysctl.d/90-derm-agents.conf
OWNER=dermtest-owner
OTHER=dermtest-other

[ "${DERM_L2_ROOT_TEST:-}" = 1 ] || { echo "set DERM_L2_ROOT_TEST=1: this test changes the system" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
for t in "$PY" "$NFT" /usr/sbin/runuser /usr/bin/sudo gcc; do command -v "$t" >/dev/null || { echo "missing $t" >&2; exit 2; }; done
if getent group derm-agents >/dev/null || [ -e /etc/derm/agents.json ] || [ -e "$LIBEXEC" ] || [ -e "$SYSCTL_CONF" ] || "$NFT" list table inet derm_agents >/dev/null 2>&1; then
	echo "agent accounts are installed here already; this test starts from none" >&2
	exit 2
fi

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); echo "  pass: $*"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $*"; }
expect() { # expect <name> <want> <got>
	if [ "$2" = "$3" ]; then pass "$1 ($3)"; else fail "$1: want $2, got $3"; fi
}
case_() { echo "== $*"; }

WORK="$(mktemp -d /tmp/derm-l2-e2e.XXXXXX)"
chmod 0755 "$WORK"
TIOCSTI_PRE="$(cat "$TIOCSTI" 2>/dev/null || echo absent)"
cleanup() {
	for a in max1 t2 foreign; do "$UNINSTALL" --account "$a" --yes >/dev/null 2>&1 || true; done
	# Whatever a failed case left: the value this test found, and its files.
	if [ "$TIOCSTI_PRE" != absent ]; then echo "$TIOCSTI_PRE" >"$TIOCSTI" 2>/dev/null || true; fi
	rm -f "$SYSCTL_CONF" /etc/derm/tiocsti.before "$SUMS" 2>/dev/null || true
	chmod 0755 /usr/local/libexec /usr/local/libexec/derm 2>/dev/null || true
	rm -rf "$LIBEXEC" 2>/dev/null || true
	rmdir /usr/local/libexec/derm /etc/derm 2>/dev/null || true
	"$NFT" delete table inet l2e2e_accept >/dev/null 2>&1 || true
	for u in "$OWNER" "$OTHER"; do userdel --remove "$u" >/dev/null 2>&1 || true; done
	groupdel derm-agents >/dev/null 2>&1 || true
	kill "${LISTENER_PID:-}" >/dev/null 2>&1 || true
	rm -rf "$WORK"
}
trap cleanup EXIT

useradd -m -s /bin/bash "$OWNER"
useradd -m -s /bin/bash "$OTHER"

# The socket helper: one attempt, prints the errno name, "ok", or "timeout".
cat >"$WORK/try.py" <<'PY'
import errno, socket, sys
proto, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
fam = socket.AF_INET6 if ":" in host else socket.AF_INET
try:
    s = socket.socket(fam, socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM)
except OSError as e:
    print("unsupported"); sys.exit()
s.settimeout(4)
try:
    if proto == "tcp":
        s.connect((host, port)); s.sendall(b"hi")
    else:
        s.sendto(b"hi", (host, port))
    print("ok")
except socket.timeout:
    print("timeout")
except OSError as e:
    print(errno.errorcode.get(e.errno, str(e.errno)))
PY
# A listener on loopback and on this machine's own non-loopback address,
# which the kernel routes through lo too.
LOCAL_IP="$("$PY" -c 'import socket; s=socket.socket(2,2); s.connect(("192.0.2.1",9)); print(s.getsockname()[0])')"
cat >"$WORK/listen.py" <<'PY'
import socket, sys, threading
def tcp(host, port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind((host, port)); s.listen(16)
    while True:
        c, _ = s.accept(); c.close()
def udp(host, port):
    s = socket.socket(2, 2); s.bind((host, port))
    while True: s.recv(64)
for spec in sys.argv[1:]:
    p, h, port = spec.split(":")
    threading.Thread(target=tcp if p == "tcp" else udp, args=(h, int(port)), daemon=True).start()
threading.Event().wait()
PY
"$PY" -I "$WORK/listen.py" tcp:127.0.0.1:47301 udp:127.0.0.1:47302 "tcp:$LOCAL_IP:47303" &
LISTENER_PID=$!
sleep 0.5

try_as() { runuser -u "$1" -- "$PY" -I "$WORK/try.py" "$2" "$3" "$4"; }
# TIOCSTI on the caller's own controlling terminal, a new pty (the one case
# legacy_tiocsti = 1 allows a process without CAP_SYS_ADMIN): ok or the errno.
cat >"$WORK/sti.py" <<'PY'
import errno, fcntl, os, pty, termios
m, s = pty.openpty()
r, w = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(r)
    os.setsid()
    fcntl.ioctl(s, termios.TIOCSCTTY, 0)
    try:
        fcntl.ioctl(s, termios.TIOCSTI, b"x")
        out = "ok"
    except OSError as e:
        out = errno.errorcode.get(e.errno, str(e.errno))
    os.write(w, out.encode())
    os._exit(0)
os.close(w)
os.waitpid(pid, 0)
print(os.read(r, 64).decode())
PY
sti_as() { runuser -u "$1" -- "$PY" -I "$WORK/sti.py"; }
if [ "$TIOCSTI_PRE" != absent ]; then
	echo 1 >"$TIOCSTI"
	expect "before the install, TIOCSTI on its own terminal as $OTHER" ok "$(sti_as "$OTHER")"
fi
NET="$("$PY" -I "$WORK/try.py" tcp 1.1.1.1 443)"
[ "$NET" = ok ] || echo "  note: this machine reaches no outside TCP host (1.1.1.1:443 gave $NET); those cases are not run"

case_ "refusals before anything is made"
for bad in "" A x_y ../a "a b" abcdefghijklmnop agent agents agent-x; do
	"$INSTALL" --account "$bad" --subscription x --owner "$OWNER" --yes >/dev/null 2>&1
	expect "slug '$bad' refused" 1 "$?"
done
"$INSTALL" --account ok1 --owner "$OWNER" --yes >/dev/null 2>&1; expect "missing --subscription refused" 1 "$?"
"$INSTALL" --account ok1 --subscription "$(printf 'a\nb')" --owner "$OWNER" --yes >/dev/null 2>&1; expect "label with a newline refused" 1 "$?"
"$INSTALL" --account ok1 --subscription "$(printf 'a‮b')" --owner "$OWNER" --yes >/dev/null 2>&1; expect "label with a bidi override refused" 1 "$?"
"$INSTALL" --account ok1 --subscription x --owner root --yes >/dev/null 2>&1; expect "root as owner refused" 1 "$?"
"$INSTALL" --account ok1 --subscription x --owner "$OWNER" --dry-run >/dev/null 2>&1; expect "dry run" 0 "$?"
getent group derm-agents >/dev/null; expect "dry run made no group" 2 "$?"
getent passwd derm-ok1 >/dev/null; expect "dry run made no user" 2 "$?"
# A group of that name that someone else uses.
groupadd derm-agents && usermod -aG derm-agents "$OTHER"
"$INSTALL" --account ok1 --subscription x --owner "$OWNER" --yes >/dev/null 2>&1; expect "a foreign derm-agents group refused" 1 "$?"
getent passwd derm-ok1 >/dev/null; expect "...and no user made" 2 "$?"
gpasswd -d "$OTHER" derm-agents >/dev/null; groupdel derm-agents
# An accounts file root did not write.
install -d -m 0755 /etc/derm && echo '{"version":1,"group":"derm-agents","accounts":[]}' >/etc/derm/agents.json && chown "$OWNER" /etc/derm/agents.json
"$INSTALL" --account ok1 --subscription x --owner "$OWNER" --yes >/dev/null 2>&1; expect "an accounts file not root's refused" 1 "$?"
getent group derm-agents >/dev/null; expect "...and no group made" 2 "$?"
rm -f /etc/derm/agents.json; rmdir /etc/derm

case_ "install max1"
"$INSTALL" --account max1 --subscription "Claude Max, personal" --owner "$OWNER" --yes >"$WORK/install.log" 2>&1
expect "install exit" 0 "$?"
GID="$(getent group derm-agents | cut -d: -f3)"
OWNER_UID_E2E="$(id -u "$OWNER")"
expect "the bridges' base, remade at boot" "d /run/derm-agent/$OWNER_UID_E2E 0711 $OWNER $(id -gn "$OWNER") -" "$(grep '^d /run/derm-agent/' "/etc/tmpfiles.d/derm-accounts-$OWNER.conf")"
expect "the bridges' base made" "711 $OWNER" "$(stat -c '%a %U' "/run/derm-agent/$OWNER_UID_E2E")"
UID1="$(id -u derm-max1)"
expect "max1 groups" "$GID" "$(id -G derm-max1)"
expect "max1 shadow locked" L "$(passwd -S derm-max1 | cut -d' ' -f2)"
expect "home mode" "700 derm-max1 derm-agents" "$(stat -c '%a %U %G' /var/lib/derm/agents/max1)"
expect "agents.json mode" "644 root" "$(stat -c '%a %U' /etc/derm/agents.json)"

case_ "the sign-in store and the projects' parent (lane PF, contracts/projects.md 2.2)"
for d in signin signin/claude-code signin/codex signin/pi projects; do
	expect "max1 $d" "700 derm-max1 derm-agents directory" "$(stat -c '%a %U %G %F' "/var/lib/derm/agents/max1/$d")"
done

case_ "the undo where only root writes (AI-8)"
for f in uninstall.sh uninstall-account.sh; do expect "$LIBEXEC/$f" "755 root root" "$(stat -c '%a %U %G' "$LIBEXEC/$f")"; done
expect "$LIBEXEC/accounts.py" "644 root root" "$(stat -c '%a %U %G' "$LIBEXEC/accounts.py")"
for d in /usr/local/libexec /usr/local/libexec/derm "$LIBEXEC"; do expect "$d" "755 root" "$(stat -c '%a %U' "$d")"; done
expect "$SUMS" "644 root" "$(stat -c '%a %U' "$SUMS")"
(cd / && sha256sum -c --strict --quiet "$SUMS"); expect "sha256sum -c takes the record" 0 "$?"
expect "the record names the three files" 3 "$(wc -l <"$SUMS")"
cmp -s "$HERE/uninstall-account.sh" "$LIBEXEC/uninstall-account.sh"; expect "the copy is the package's" 0 "$?"
grep -q "^Undo: *sudo $ROOT_UNINSTALL --account max1\$" "$WORK/install.log"; expect "the undo line names root's copy" 0 "$?"
grep -q "Undo: $LIBEXEC/uninstall.sh --account max1" /etc/sudoers.d/derm-max1; expect "the sudoers comment names it too" 0 "$?"
runuser -u "$OTHER" -- "$PY" -I "$HELPER" verify-uninstaller; expect "verify-uninstaller as another user" 0 "$?"

case_ "the account's audit rules (step P, PC R4)"
grep -q "^== 12. this account's audit rules" "$WORK/install.log"; expect "step 12 is named" 0 "$?"
if [ -x /usr/sbin/augenrules ] && [ -d /etc/audit/rules.d ]; then
	echo "  not run here: auditd is installed; the box test installs the rules"
else
	grep -q "not installed: no auditd here" "$WORK/install.log"; expect "with no auditd it says so and goes on" 0 "$?"
	expect "no rules file was made" 0 "$(ls /etc/audit/rules.d/50-derm-* 2>/dev/null | wc -l)"
fi

case_ "TIOCSTI off (note CC 4d)"
if [ "$TIOCSTI_PRE" = absent ]; then
	echo "  not run: this kernel has no dev.tty.legacy_tiocsti"
else
	expect "dev.tty.legacy_tiocsti" 0 "$(cat "$TIOCSTI")"
	expect "the value before, kept for the undo" 1 "$(cat /etc/derm/tiocsti.before)"
	expect "$SYSCTL_CONF" "644 root" "$(stat -c '%a %U' "$SYSCTL_CONF")"
	grep -qx "dev.tty.legacy_tiocsti = 0" "$SYSCTL_CONF"; expect "...sets it at boot" 0 "$?"
	expect "TIOCSTI on its own terminal as $OTHER" EIO "$(sti_as "$OTHER")"
	expect "TIOCSTI on its own terminal as derm-max1" EIO "$(sti_as derm-max1)"
	expect "TIOCSTI as root (CAP_SYS_ADMIN keeps it)" ok "$(sti_as root)"
fi
want="$("$PY" -c 'import json,sys; print(json.dumps({"version":1,"group":"derm-agents","accounts":[{"name":"derm-max1","uid":int(sys.argv[1]),"subscription":"Claude Max, personal","home":"/var/lib/derm/agents/max1"}]}, sort_keys=True))' "$UID1")"
got="$("$PY" -c 'import json; print(json.dumps(json.load(open("/etc/derm/agents.json")), sort_keys=True))')"
expect "agents.json is the contract" "$want" "$got"
expect "the table's uid set" "$UID1" "$("$NFT" -j list set inet derm_agents uids | "$PY" -c 'import json,sys; d=json.load(sys.stdin); print(" ".join(str(e) for x in d["nftables"] if "set" in x for e in x["set"].get("elem",[])))')"
"$NFT" -c -f /etc/derm/agents.nft; expect "nft -c takes the written file" 0 "$?"

case_ "real sockets: max1 reaches loopback and nothing else"
expect "max1 TCP 127.0.0.1" ok "$(try_as derm-max1 tcp 127.0.0.1 47301)"
expect "max1 UDP 127.0.0.1" ok "$(try_as derm-max1 udp 127.0.0.1 47302)"
expect "max1 TCP to this machine's own $LOCAL_IP (not loopback)" EHOSTUNREACH "$(try_as derm-max1 tcp "$LOCAL_IP" 47303)"
expect "max1 UDP 192.0.2.1" EPERM "$(try_as derm-max1 udp 192.0.2.1 9)"
expect "max1 TCP 192.0.2.1, refused at once" EHOSTUNREACH "$(try_as derm-max1 tcp 192.0.2.1 9)"
expect "max1 DNS UDP 127.0.0.53" EPERM "$(try_as derm-max1 udp 127.0.0.53 53)"
expect "max1 DNS TCP 127.0.0.1:53" EHOSTUNREACH "$(try_as derm-max1 tcp 127.0.0.1 53)"
[ "$NET" = ok ] && expect "max1 TCP 1.1.1.1:443" EHOSTUNREACH "$(try_as derm-max1 tcp 1.1.1.1 443)"
v6="$(try_as derm-max1 udp 2001:db8::1 9)"
if [ "$v6" = unsupported ]; then echo "  not run: IPv6 (the kernel here has no AF_INET6)"; else expect "max1 UDP 2001:db8::1" EPERM "$v6"; fi

case_ "real sockets: the owner and another user are unaffected"
for u in "$OWNER" "$OTHER" root; do
	expect "$u TCP 127.0.0.1" ok "$(try_as "$u" tcp 127.0.0.1 47301)"
	expect "$u UDP 192.0.2.1" ok "$(try_as "$u" udp 192.0.2.1 9)"
	expect "$u DNS UDP 127.0.0.53" ok "$(try_as "$u" udp 127.0.0.53 53)"
	expect "$u TCP $LOCAL_IP" ok "$(try_as "$u" tcp "$LOCAL_IP" 47303)"
	[ "$NET" = ok ] && expect "$u TCP 1.1.1.1:443" ok "$(try_as "$u" tcp 1.1.1.1 443)"
done

case_ "a set-id program does not take max1 out of the table"
cat >"$WORK/sendto.c" <<'C'
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
int main(void) {
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in a = {0};
	a.sin_family = AF_INET; a.sin_port = htons(9);
	inet_pton(AF_INET, "192.0.2.1", &a.sin_addr);
	if (sendto(s, "x", 1, 0, (struct sockaddr *)&a, sizeof a) < 0) puts(errno == EPERM ? "EPERM" : strerror(errno));
	else puts("ok");
	return 0;
}
C
gcc -O2 -o "$WORK/sgid" "$WORK/sendto.c" && cp "$WORK/sgid" "$WORK/suid"
chown root:mail "$WORK/sgid" && chmod 2755 "$WORK/sgid"
chown nobody:root "$WORK/suid" && chmod 4755 "$WORK/suid"
expect "set-group-id (mail) program as max1" EPERM "$(runuser -u derm-max1 -- "$WORK/sgid")"
expect "set-user-id (nobody) program as max1" EPERM "$(runuser -u derm-max1 -- "$WORK/suid")"
expect "the set-group-id program as $OTHER" ok "$(runuser -u "$OTHER" -- "$WORK/sgid")"

case_ "another table's accept does not undo the refusal"
"$NFT" -f - <<'NFT'
table inet l2e2e_accept {
	chain output {
		type filter hook output priority -10; policy accept;
		accept
	}
}
NFT
expect "max1 UDP 192.0.2.1 with an accept elsewhere" EPERM "$(try_as derm-max1 udp 192.0.2.1 9)"
"$NFT" delete table inet l2e2e_accept

case_ "sudo: the owner may start programs as max1, no one else"
expect "owner sudo -n -u max1" derm-max1 "$(runuser -u "$OWNER" -- sudo -n -u derm-max1 id -un 2>&1)"
runuser -u "$OTHER" -- sudo -n -u derm-max1 true >/dev/null 2>&1; expect "other user's sudo -n -u max1 refused" 1 "$?"
runuser -u derm-max1 -- sudo -n true >/dev/null 2>&1; expect "max1's own sudo refused" 1 "$?"

case_ "the check, unprivileged"
runuser -u "$OTHER" -- "$PY" -I "$HELPER" check >"$WORK/check.out" 2>&1; expect "check as another user" 0 "$?"
runuser -u "$OWNER" -- sudo -n -u derm-max1 "$PY" -I "$HELPER" check --probe >"$WORK/probe.out" 2>&1; expect "probe as max1 through the owner's sudo" 0 "$?"
runuser -u "$OTHER" -- "$PY" -I "$HELPER" check --probe >/dev/null 2>&1; expect "probe as a non-agent refused" 1 "$?"
runuser -u "$OTHER" -- "$PY" -I "$HELPER" check --json | "$PY" -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d["ok"] and d["checks"] else 1)'; expect "check --json" 0 "$?"
chmod 0664 /etc/derm/agents.json
runuser -u "$OTHER" -- "$PY" -I "$HELPER" check >"$WORK/c.out" 2>&1; expect "check with a group-writable agents.json" 1 "$?"
grep -q "writable by others" "$WORK/c.out"; expect "...says why" 0 "$?"
chmod 0644 /etc/derm/agents.json
echo "# extra" >>/etc/derm/agents.nft
runuser -u "$OTHER" -- "$PY" -I "$HELPER" check >/dev/null 2>&1; expect "check with an edited table file" 1 "$?"
"$INSTALL" --account max1 --subscription "Claude Max, personal" --owner "$OWNER" --yes >/dev/null 2>&1; expect "install again, same account" 0 "$?"
runuser -u "$OTHER" -- "$PY" -I "$HELPER" check >/dev/null 2>&1; expect "check after it" 0 "$?"
"$NFT" delete table inet derm_agents
runuser -u "$OWNER" -- sudo -n -u derm-max1 "$PY" -I "$HELPER" check --probe >"$WORK/p.out" 2>&1; expect "probe with the table gone" 1 "$?"
grep -q "FAIL probe: outbound UDP" "$WORK/p.out"; expect "...names outbound UDP" 0 "$?"
expect "max1 UDP 192.0.2.1 with the table gone (what the probe saw)" ok "$(try_as derm-max1 udp 192.0.2.1 9)"
"$NFT" -f /etc/derm/agents.nft
expect "max1 UDP 192.0.2.1 after loading it again" EPERM "$(try_as derm-max1 udp 192.0.2.1 9)"

case_ "the undo's copy changed, or its folder opened to others"
echo "# changed" >>"$LIBEXEC/uninstall-account.sh"
runuser -u "$OTHER" -- "$PY" -I "$HELPER" check >"$WORK/c.out" 2>&1; expect "check with a changed undo" 1 "$?"
grep -q "FAIL uninstaller: .*not what the install recorded" "$WORK/c.out"; expect "...says why" 0 "$?"
"$ROOT_UNINSTALL" --account max1 --yes >"$WORK/u.out" 2>&1; expect "the changed copy refuses to run" 1 "$?"
grep -q "not what the install recorded; nothing changed" "$WORK/u.out"; expect "...and says so" 0 "$?"
getent passwd derm-max1 >/dev/null; expect "...and max1 is still there" 0 "$?"
[ -e /etc/sudoers.d/derm-max1 ]; expect "...with its sudoers rule" 0 "$?"
"$INSTALL" --account max1 --subscription "Claude Max, personal" --owner "$OWNER" --yes >/dev/null 2>&1; expect "install again restores the copy" 0 "$?"
runuser -u "$OTHER" -- "$PY" -I "$HELPER" verify-uninstaller; expect "...and its record" 0 "$?"
chmod 0775 /usr/local/libexec/derm
runuser -u "$OTHER" -- "$PY" -I "$HELPER" verify-uninstaller 2>"$WORK/v.out"; expect "verify with a group-writable folder on the way" 1 "$?"
grep -q "writable by others" "$WORK/v.out"; expect "...says why" 0 "$?"
"$INSTALL" --account max1 --subscription "Claude Max, personal" --owner "$OWNER" --yes >"$WORK/i.out" 2>&1; expect "install refuses to copy the undo there" 1 "$?"
grep -q "could not be put in $LIBEXEC" "$WORK/i.out"; expect "...and says so" 0 "$?"
chmod 0755 /usr/local/libexec/derm
mv "$LIBEXEC" "$WORK/libexec-real" && ln -s "$WORK/libexec-real" "$LIBEXEC"
runuser -u "$OTHER" -- "$PY" -I "$HELPER" verify-uninstaller 2>"$WORK/v.out"; expect "verify with the folder a link" 1 "$?"
grep -q "is a link or not a folder" "$WORK/v.out"; expect "...says why" 0 "$?"
rm "$LIBEXEC" && mv "$WORK/libexec-real" "$LIBEXEC"
runuser -u "$OTHER" -- "$PY" -I "$HELPER" verify-uninstaller; expect "verify once it is back" 0 "$?"

case_ "a link the account planted where the install makes a folder"
mkdir -p "$WORK/planted" && chmod 0755 "$WORK/planted"
runuser -u derm-max1 -- rmdir /var/lib/derm/agents/max1/signin/codex
runuser -u derm-max1 -- ln -s "$WORK/planted" /var/lib/derm/agents/max1/signin/codex
"$INSTALL" --account max1 --subscription "Claude Max, personal" --owner "$OWNER" --yes >"$WORK/i.out" 2>&1; expect "install with signin/codex a link" 1 "$?"
grep -q "signin/codex is a link or not a folder" "$WORK/i.out"; expect "...names it" 0 "$?"
expect "...and the link's target is not handed to the account" "755 root" "$(stat -c '%a %U' "$WORK/planted")"
runuser -u "$OTHER" -- "$PY" -I "$HELPER" check >/dev/null 2>&1; expect "check as another user cannot see inside the home" 0 "$?"
"$PY" -I "$HELPER" check >"$WORK/c.out" 2>&1; expect "check as root sees the link" 1 "$?"
grep -q "FAIL folders of derm-max1" "$WORK/c.out"; expect "...and names the folders" 0 "$?"
runuser -u derm-max1 -- rm /var/lib/derm/agents/max1/signin/codex
"$INSTALL" --account max1 --subscription "Claude Max, personal" --owner "$OWNER" --yes >/dev/null 2>&1; expect "install again, the link gone" 0 "$?"
expect "signin/codex made again" "700 derm-max1 directory" "$(stat -c '%a %U %F' /var/lib/derm/agents/max1/signin/codex)"
runuser -u derm-max1 -- chmod 0755 /var/lib/derm/agents/max1/projects
runuser -u "$OWNER" -- sudo -n -u derm-max1 "$PY" -I "$HELPER" check --probe >"$WORK/p.out" 2>&1; expect "the account's own check sees a projects/ others can read" 1 "$?"
grep -q "projects is not the account's 0700 folder" "$WORK/p.out"; expect "...says why" 0 "$?"
"$INSTALL" --account max1 --subscription "Claude Max, personal" --owner "$OWNER" --yes >/dev/null 2>&1; expect "install again sets 0700" 0 "$?"
expect "projects/ is 0700 again" 700 "$(stat -c '%a' /var/lib/derm/agents/max1/projects)"

case_ "TIOCSTI turned back on by hand"
if [ "$TIOCSTI_PRE" != absent ]; then
	echo 1 >"$TIOCSTI"
	runuser -u "$OTHER" -- "$PY" -I "$HELPER" check >"$WORK/c.out" 2>&1; expect "check with TIOCSTI on" 1 "$?"
	grep -q "FAIL TIOCSTI: dev.tty.legacy_tiocsti is 1" "$WORK/c.out"; expect "...says why" 0 "$?"
	"$INSTALL" --account max1 --subscription "Claude Max, personal" --owner "$OWNER" --yes >/dev/null 2>&1; expect "install again" 0 "$?"
	expect "...turns it off" 0 "$(cat "$TIOCSTI")"
	expect "...and keeps the first install's value before" 1 "$(cat /etc/derm/tiocsti.before)"
	rm "$SYSCTL_CONF"
	runuser -u "$OTHER" -- "$PY" -I "$HELPER" check >"$WORK/c.out" 2>&1; expect "check with the boot file gone" 1 "$?"
	grep -q "comes back on at the next boot" "$WORK/c.out"; expect "...says why" 0 "$?"
	"$INSTALL" --account max1 --subscription "Claude Max, personal" --owner "$OWNER" --yes >/dev/null 2>&1; expect "install again writes it" 0 "$?"
fi

case_ "a second account, and a label changed"
"$INSTALL" --account t2 --subscription "ChatGPT Plus" --owner "$OWNER" --yes >/dev/null 2>&1; expect "install t2" 0 "$?"
UID2="$(id -u derm-t2)"
"$INSTALL" --account max1 --subscription "Claude Max, work" --owner "$OWNER" --yes >/dev/null 2>&1; expect "max1 again with a new label" 0 "$?"
expect "two accounts, max1 relabelled" "derm-max1:Claude Max, work derm-t2:ChatGPT Plus" \
	"$("$PY" -c 'import json; print(" ".join(a["name"]+":"+a["subscription"] for a in json.load(open("/etc/derm/agents.json"))["accounts"]))')"
expect "the set holds both" "$(printf '%s\n' "$UID1" "$UID2" | sort -n | tr '\n' ' ')" \
	"$("$NFT" -j list set inet derm_agents uids | "$PY" -c 'import json,sys; d=json.load(sys.stdin); print(" ".join(str(e) for e in sorted(e for x in d["nftables"] if "set" in x for e in x["set"].get("elem",[]))) + " ")')"
expect "t2 UDP 192.0.2.1" EPERM "$(try_as derm-t2 udp 192.0.2.1 9)"
expect "t2 TCP 127.0.0.1" ok "$(try_as derm-t2 tcp 127.0.0.1 47301)"
runuser -u "$OWNER" -- sudo -n -u derm-t2 "$PY" -I "$HELPER" check --probe >/dev/null 2>&1; expect "probe as t2" 0 "$?"

case_ "uninstall max1, through the undo line's own copy"
"$ROOT_UNINSTALL" --account max1 --dry-run >/dev/null 2>&1; expect "uninstall dry run" 0 "$?"
getent passwd derm-max1 >/dev/null; expect "...left max1" 0 "$?"
runuser -u derm-max1 -- sleep 60 &
sleep 0.3
"$ROOT_UNINSTALL" --account max1 --yes >"$WORK/un1.log" 2>&1; expect "uninstall max1" 0 "$?"
runuser -u "$OTHER" -- "$PY" -I "$HELPER" verify-uninstaller; expect "the copy stays for t2" 0 "$?"
[ "$TIOCSTI_PRE" = absent ] || expect "TIOCSTI stays off for t2" 0 "$(cat "$TIOCSTI")"
getent passwd derm-max1 >/dev/null; expect "max1 gone" 2 "$?"
[ -e /var/lib/derm/agents/max1 ]; expect "its home gone" 1 "$?"
[ -e /etc/sudoers.d/derm-max1 ]; expect "its sudoers rule gone" 1 "$?"
pgrep -u "$UID1" >/dev/null; expect "its processes gone" 1 "$?"
expect "the set holds t2 only" "$UID2" "$("$NFT" -j list set inet derm_agents uids | "$PY" -c 'import json,sys; d=json.load(sys.stdin); print(" ".join(str(e) for x in d["nftables"] if "set" in x for e in x["set"].get("elem",[])))')"
expect "t2 still refused" EPERM "$(try_as derm-t2 udp 192.0.2.1 9)"
expect "$OTHER still unaffected" ok "$(try_as "$OTHER" udp 192.0.2.1 9)"
runuser -u "$OTHER" -- "$PY" -I "$HELPER" check >/dev/null 2>&1; expect "check after it" 0 "$?"

case_ "uninstall t2, the last account, through the copy it removes"
"$ROOT_UNINSTALL" --account t2 --yes >"$WORK/un2.log" 2>&1; expect "uninstall t2" 0 "$?"
grep -q "^== done" "$WORK/un2.log"; expect "...ran to its end after removing its own copy" 0 "$?"
"$NFT" list table inet derm_agents >/dev/null 2>&1; expect "the table gone" 1 "$?"
[ "$TIOCSTI_PRE" = absent ] || expect "TIOCSTI back to what the first install found" 1 "$(cat "$TIOCSTI")"
[ "$TIOCSTI_PRE" = absent ] || expect "TIOCSTI on its own terminal as $OTHER again" ok "$(sti_as "$OTHER")"
for f in /etc/derm/agents.json /etc/derm/agents.nft /etc/systemd/system/derm-agents-nft.service /run/derm/agents-nft.loaded "$HELPER" /etc/sudoers.d/derm-t2 "/etc/tmpfiles.d/derm-accounts-$OWNER.conf" /var/lib/derm "$LIBEXEC" /usr/local/libexec/derm "$SUMS" "$SYSCTL_CONF" /etc/derm/tiocsti.before /etc/derm; do
	[ -e "$f" ]; expect "$f gone" 1 "$?"
done
getent group derm-agents >/dev/null; expect "the group gone" 2 "$?"
expect "$OTHER unaffected after all" ok "$(try_as "$OTHER" udp 192.0.2.1 9)"
"$UNINSTALL" --account nosuch --yes >/dev/null 2>&1; expect "uninstall of an account that is not there" 0 "$?"

case_ "an account someone else made is not removed"
useradd --system -M -c "someone's" derm-foreign
"$UNINSTALL" --account foreign --yes >/dev/null 2>&1; expect "uninstall refuses it" 1 "$?"
getent passwd derm-foreign >/dev/null; expect "...and it is still there" 0 "$?"
userdel derm-foreign

echo
echo "root-e2e: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
