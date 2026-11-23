#!/bin/bash
# One agent account for one subscription (derm, plans/parallel_build_accounts.md
# lane L2; note CB sections 2.1 and 5). Run as root, on the person's yes; read
# --dry-run first. uninstall.sh --account <slug> undoes every step.
#
#   sudo packaging/linux/agent-user/install.sh --account <slug> --subscription <label> \
#        [--owner <you>] [--dry-run] [--yes]
#
# <slug>: 1 to 15 of a-z, 0-9 and - (the account is derm-<slug>, the same
# form on every system: Windows takes 20 characters); agent, agents and
# agent-* are reserved. <label>: what you call the subscription, shown back
# and never parsed ("Claude Max, personal").
#
# Each step is printed before it runs, with its undo:
#   1. /usr/local/libexec/derm/agent-user/ (root's, 0755): the undo
#      (uninstall.sh, uninstall-account.sh, accounts.py), copied where only
#      root writes, every folder to it checked, each file's sha256 recorded
#      in /etc/derm/uninstall.sha256. Every undo line names this copy
#      (review AI-8; a line naming this folder would have root run files you
#      own).
#   2. /usr/local/lib/derm/agents.py (root's, 0644): the helper the unit and
#      derm's check run, copied from here and checked by hash.
#   3. the group derm-agents (system group, no members listed).
#   4. the user derm-<slug>: system user, primary group derm-agents and
#      no other group, home /var/lib/derm/agents/<slug> (0700), password
#      locked, shell /bin/bash.
#   5. in that home, signin/ with claude-code/, codex/ and pi/ (the sign-in
#      store, one folder per harness) and projects/ (each project's folders
#      go there): the account's, 0700 (contracts/projects.md section 2.2).
#   6. /etc/derm/agents.json (root's, 0644): the account, exactly as the
#      contract in plans/parallel_build_accounts.md section 2 says.
#   7. /etc/derm/agents.nft and the table inet derm_agents: every outbound
#      packet from the group or from an account's uid is refused unless it
#      goes to 127.0.0.0/8 or ::1, and DNS (port 53) is refused on loopback
#      too: derm-egress resolves names.
#   8. derm-agents-nft.service, enabled, so the table comes back at boot and
#      after nftables.service flushes the ruleset.
#   9. /etc/tmpfiles.d/derm-accounts-<you>.conf: /run/derm-agent/<your uid>
#      (0711, yours), the base of each chat's bridge, remade at boot.
#  10. TIOCSTI off: /etc/sysctl.d/90-derm-agents.conf and
#      dev.tty.legacy_tiocsti = 0 now, so no process without CAP_SYS_ADMIN
#      pushes bytes into a terminal's input (Linux 6.2 and later); the value
#      before is kept in /etc/derm/tiocsti.before for the undo.
#  11. /etc/sudoers.d/derm-<slug>: <you> may start programs as the
#      account without a password (derm run, derm agents login). Last, so
#      nothing runs as the account before its table is in place.
#  12. the account's own audit rules (step P, lane PC's request R4):
#      /etc/audit/rules.d/50-derm-<uid>.rules from
#      /usr/local/bin/derm-audit-feed rules --account <slug>, then
#      augenrules --load, so the Linux feed sees the account's processes
#      (the person's file names only the person's uid). Only where auditd's
#      augenrules is there and derm-audit-feed is a root-owned program only
#      root can change; otherwise it says what to install and goes on.

set -euo pipefail
umask 022
export LC_ALL=C

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PY=/usr/bin/python3
NFT=/usr/sbin/nft
HELPER=/usr/local/lib/derm/agents.py
UNINSTALLER=/usr/local/libexec/derm/agent-user
UNINSTALLER_SUMS=/etc/derm/uninstall.sha256
TIOCSTI_CONF=/etc/sysctl.d/90-derm-agents.conf
ANCHOR=/etc/derm/agents.json
RULES=/etc/derm/agents.nft
AUDIT_FEED=/usr/local/bin/derm-audit-feed
AUGENRULES=/usr/sbin/augenrules
AUDIT_DIR=/etc/audit/rules.d
UNIT=/etc/systemd/system/derm-agents-nft.service
GROUP=derm-agents
HOMES=/var/lib/derm/agents
NAME_RE='^[a-z_][a-z0-9_-]{0,31}$'

SLUG=""
LABEL=""
LABEL_SET=0
OWNER="${SUDO_USER:-}"
DRY=0
YES=0

die() { echo "install.sh: $*" >&2; exit 1; }
say() { echo "== $*"; }
run() {
	printf '   $'; printf ' %q' "$@"; printf '\n'
	if [ "$DRY" = 0 ]; then "$@"; fi
}

while [ $# -gt 0 ]; do
	case "$1" in
		--account) SLUG="${2-}"; shift 2 || die "--account needs a slug" ;;
		--subscription) LABEL="${2-}"; LABEL_SET=1; shift 2 || die "--subscription needs a label" ;;
		--owner) OWNER="${2-}"; shift 2 || die "--owner needs a login" ;;
		--dry-run) DRY=1; shift ;;
		--yes) YES=1; shift ;;
		-h|--help) sed -n '2,45p' "$0"; exit 0 ;;
		*) die "unknown argument: $1" ;;
	esac
done

for tool in "$PY" "$NFT"; do [ -x "$tool" ] || die "$tool is not installed"; done
for tool in useradd groupadd groupdel passwd visudo getent install id sha256sum; do
	command -v "$tool" >/dev/null || die "$tool is not installed"
done
"$PY" -I "$HERE/accounts.py" valid-slug "$SLUG" || die "--account '$SLUG' refused"
[ "$LABEL_SET" = 1 ] || die "--subscription <label> is required: what you call this subscription"
"$PY" -I "$HERE/accounts.py" valid-label "$LABEL" || die "--subscription refused"
[[ "$OWNER" =~ $NAME_RE ]] || die "--owner must be a plain login name (got '$OWNER'); run with sudo or pass --owner"
if [ "$DRY" = 0 ] && [ "$(id -u)" != 0 ]; then die "run as root (or with --dry-run)"; fi

ACCOUNT="derm-$SLUG"
HOME_DIR="$HOMES/$SLUG"
COMMENT="derm agent $SLUG"
SUDOERS="/etc/sudoers.d/derm-$SLUG"
OWNER_UID="$(getent passwd "$OWNER" | cut -d: -f3)" || true
[ -n "$OWNER_UID" ] || die "no user $OWNER"
OWNER_GROUP="$(id -gn "$OWNER")"
TMPFILES="/etc/tmpfiles.d/derm-accounts-$OWNER.conf"
[ "$OWNER_UID" -ge 1000 ] || die "$OWNER has uid $OWNER_UID: the owner must be a person's account"
case "$OWNER" in derm-*) die "the owner cannot be an agent account" ;; esac

# What exists already. An existing group is used only with no members listed;
# an existing user only if this script made it, in this group.
GROUP_EXISTS=0
if getent group "$GROUP" >/dev/null; then
	GROUP_EXISTS=1
	members="$(getent group "$GROUP" | cut -d: -f4)"
	[ -z "$members" ] || die "the group $GROUP exists with members ($members): it is not derm's to use; remove them or the group"
fi
USER_EXISTS=0
if getent passwd "$ACCOUNT" >/dev/null; then
	IFS=: read -r _ _ uid gid comment home _ < <(getent passwd "$ACCOUNT")
	[ "$comment" = "$COMMENT" ] || die "a user $ACCOUNT exists and was not made by this script (comment '$comment')"
	[ "$home" = "$HOME_DIR" ] || die "$ACCOUNT has home $home, not $HOME_DIR"
	[ "$GROUP_EXISTS" = 1 ] && [ "$gid" = "$(getent group "$GROUP" | cut -d: -f3)" ] \
		|| die "$ACCOUNT's primary group is not $GROUP"
	USER_EXISTS=1
fi
# The accounts file must be one root wrote; a reader refuses anything else,
# and so does this script, rather than write over it.
if [ -e "$ANCHOR" ] || [ -L "$ANCHOR" ]; then
	"$PY" -I "$HERE/accounts.py" anchor-names >/dev/null || die "fix $ANCHOR by hand first; nothing changed"
fi

echo "This makes the agent account $ACCOUNT for the subscription \"$LABEL\" (derm)."
echo "Its traffic reaches loopback only. $OWNER (uid $OWNER_UID) may start programs as it."
[ "$DRY" = 1 ] && echo "(dry run: nothing changes)"
if [ "$DRY" = 0 ] && [ "$YES" = 0 ]; then
	read -r -p "Go ahead? [y/N] " answer
	[ "$answer" = y ] || [ "$answer" = Y ] || die "stopped; nothing changed"
fi
# Every undo line names root's copy of the undo (step 1; review AI-8, rules
# case 284): this folder may be yours ($HERE), or the root-owned copy derm
# agents add removes when this ends (lane L4's request R2), and a line that
# names either has root run files that root does not keep.
UNDO_CMD="sudo $UNINSTALLER/uninstall.sh --account $SLUG"
STEP1=0
DONE=0
if [ "$DRY" = 0 ]; then
	trap '[ "$DONE" = 1 ] || { if [ "$STEP1" = 1 ]; then echo "install.sh: stopped before the end; undo what it did: $UNDO_CMD" >&2; else echo "install.sh: stopped before it changed anything but the folders of $UNINSTALLER" >&2; fi; }' EXIT
fi

say "1. $UNINSTALLER, the undo, where only root writes (undo: removed with the last account)"
if [ "$DRY" = 0 ]; then
	"$PY" -I "$HERE/accounts.py" install-uninstaller "$HERE" || die "the undo could not be put in $UNINSTALLER"
	sed 's/^/   /' "$UNINSTALLER_SUMS"
	STEP1=1
else
	echo "   uninstall.sh, uninstall-account.sh and accounts.py copied there; their sha256 in $UNINSTALLER_SUMS"
	"$PY" -I "$HERE/accounts.py" trusted-dir /usr/local || echo "   (the install would stop here: the undo would sit where others can change it)"
fi

say "2. $HELPER (undo: rm, with the last account)"
if ! "$PY" -I "$HERE/accounts.py" trusted-dir /usr/local/lib; then
	[ "$DRY" = 1 ] || die "/usr/local/lib is not root's alone: the helper would sit where others can change it"
	echo "   (the install would stop here: the helper would sit where others can change it)"
fi
run install -d -o root -g root -m 0755 /usr/local/lib/derm
run install -o root -g root -m 0644 "$HERE/accounts.py" "$HELPER"
if [ "$DRY" = 0 ]; then
	[ "$(sha256sum <"$HERE/accounts.py")" = "$(sha256sum <"$HELPER")" ] || die "$HELPER does not match what was copied"
	A=("$PY" -I "$HELPER")
else
	A=("$PY" -I "$HERE/accounts.py")
fi

say "3. the group $GROUP (undo: groupdel, with the last account)"
if [ "$GROUP_EXISTS" = 0 ]; then
	run groupadd --system "$GROUP"
else
	echo "   exists"
fi

say "4. the user $ACCOUNT (undo: userdel --remove $ACCOUNT)"
run install -d -o root -g root -m 0755 /var/lib/derm "$HOMES"
if [ "$USER_EXISTS" = 0 ]; then
	run useradd --system --gid "$GROUP" --no-user-group --create-home --home-dir "$HOME_DIR" \
		--shell /bin/bash --comment "$COMMENT" "$ACCOUNT"
	run passwd --lock "$ACCOUNT"
else
	echo "   exists"
fi
run chmod 0700 "$HOME_DIR"
if [ "$DRY" = 0 ]; then
	ACCOUNT_UID="$(id -u "$ACCOUNT")"
	GID="$(getent group "$GROUP" | cut -d: -f3)"
	[ "$(id -G "$ACCOUNT")" = "$GID" ] || die "$ACCOUNT is in groups $(id -Gn "$ACCOUNT"), not only $GROUP; remove the others (gpasswd -d $ACCOUNT <group>) and run again"
else
	ACCOUNT_UID="<uid>"
	GID="<gid>"
fi

say "5. $HOME_DIR/signin and $HOME_DIR/projects (undo: they go with the home)"
echo "   signin/claude-code, signin/codex, signin/pi and projects/: $ACCOUNT's, 0700, made through open folders, never through a link"
if [ "$DRY" = 0 ]; then
	"${A[@]}" layout "$SLUG" || die "the sign-in store or the projects folder could not be made"
fi

say "6. $ANCHOR (undo: the entry removed; the file goes with the last account)"
echo "   {\"name\": \"$ACCOUNT\", \"uid\": $ACCOUNT_UID, \"subscription\": <the label>, \"home\": \"$HOME_DIR\"}"
if [ "$DRY" = 0 ]; then
	install -d -o root -g root -m 0755 /etc/derm
	"${A[@]}" upsert "$SLUG" "$ACCOUNT_UID" "$LABEL"
fi

say "7. $RULES and the table inet derm_agents (undo: nft delete table inet derm_agents, with the last account)"
if [ "$DRY" = 0 ]; then
	tmp="$(mktemp /etc/derm/.agents.nft.XXXXXX)"
	"${A[@]}" render >"$tmp"
	"$NFT" -c -f "$tmp" || { rm -f "$tmp"; die "nft refused the table; nothing loaded"; }
	chmod 0644 "$tmp"
	mv -f "$tmp" "$RULES"
	run "$NFT" -f "$RULES"
	"${A[@]}" marker
	sed 's/^/   | /' "$RULES"
else
	echo "   (the group's gid and the account's uid are known only after steps 2 and 3)"
	"${A[@]}" render --gid 0 --uid 0 | sed 's/^/   | /'
fi

say "8. $UNIT (undo: systemctl disable, rm, with the last account)"
run install -o root -g root -m 0644 "$HERE/derm-agents-nft.service" "$UNIT"
if [ -d /run/systemd/system ]; then
	run systemctl daemon-reload
	run systemctl enable derm-agents-nft.service
	# Started already by hand above; this records it as active.
	run systemctl start derm-agents-nft.service
else
	echo "   systemd is not running here: the unit is in place but nothing loads the table at"
	echo "   boot. After a reboot run: sudo $NFT -f $RULES"
fi

say "9. $TMPFILES (undo: rm, with the last account)"
# The base of each chat's bridge (derm run, run/user/bridge.rs BASE_ROOT),
# remade at boot: lane L1's request L1-5. The same folders as wave 5's
# install.sh --owner makes, in a file of this form's own.
tmpfiles="d /run/derm-agent 0755 root root -
d /run/derm-agent/$OWNER_UID 0711 $OWNER $OWNER_GROUP -"
echo "$tmpfiles" | sed 's/^/   /'
if [ "$DRY" = 0 ]; then
	printf '# derm: per-chat bridges for %s (agent accounts). Undo: %s/uninstall.sh --account <the last slug>\n%s\n' "$OWNER" "$UNINSTALLER" "$tmpfiles" >"$TMPFILES"
	chmod 0644 "$TMPFILES"
	if command -v systemd-tmpfiles >/dev/null; then
		systemd-tmpfiles --create "$TMPFILES"
	else
		install -d -o root -g root -m 0755 /run/derm-agent
		install -d -o "$OWNER" -g "$OWNER_GROUP" -m 0711 "/run/derm-agent/$OWNER_UID"
	fi
fi

say "10. TIOCSTI off: $TIOCSTI_CONF and dev.tty.legacy_tiocsti = 0 (undo: the value from before, back, with the last account)"
if [ "$DRY" = 0 ]; then
	now="$("${A[@]}" tiocsti-off)" || die "TIOCSTI could not be turned off"
	if [ "$now" = absent ]; then
		echo "   this kernel has no dev.tty.legacy_tiocsti (Linux 6.2 and later have it): TIOCSTI stays as it is"
	else
		echo "   dev.tty.legacy_tiocsti = $now (before the install: $(cat /etc/derm/tiocsti.before))"
	fi
else
	echo "   $TIOCSTI_CONF written and dev.tty.legacy_tiocsti set to 0 (now: $(cat /proc/sys/dev/tty/legacy_tiocsti 2>/dev/null || echo 'absent, before Linux 6.2'))"
fi

say "11. $SUDOERS (undo: rm)"
rule="$OWNER ALL=($ACCOUNT) NOPASSWD:SETENV: ALL"
echo "   $rule"
if [ "$DRY" = 0 ]; then
	tmp="$(mktemp)"
	printf '# derm: %s may start programs as %s. Undo: %s/uninstall.sh --account %s\n%s\n' "$OWNER" "$ACCOUNT" "$UNINSTALLER" "$SLUG" "$rule" >"$tmp"
	visudo -c -q -f "$tmp" || { rm -f "$tmp"; die "visudo refused the rule; the account has no sudo rule"; }
	install -o root -g root -m 0440 "$tmp" "$SUDOERS"
	rm -f "$tmp"
fi

say "12. this account's audit rules in $AUDIT_DIR/50-derm-<its uid>.rules, from $AUDIT_FEED rules --account $SLUG, then augenrules --load (undo: rm, then augenrules --load)"
# A program root runs must be root's and closed, by its real path, and so
# must every folder to it (rules case 37).
feed_ok() {
	[ -f "$AUDIT_FEED" ] && [ ! -L "$AUDIT_FEED" ] || return 1
	"$PY" -I "$HERE/accounts.py" trusted-dir "$(dirname "$AUDIT_FEED")" 2>/dev/null || return 1
	read -r owner mode < <(stat -c '%u %a' "$AUDIT_FEED") || return 1
	[ "$owner" = 0 ] || return 1
	case "$mode" in *[2367]?|*[2367]) return 1 ;; esac
	[ -x "$AUDIT_FEED" ]
}
if [ ! -x "$AUGENRULES" ] || [ ! -d "$AUDIT_DIR" ]; then
	echo "   not installed: no auditd here ($AUGENRULES and $AUDIT_DIR); without it this account's chats have no OS records (no project.control, signin.read or net.unix)"
elif ! feed_ok; then
	echo "   not installed: $AUDIT_FEED is not a root-owned program only root can change; install derm-audit-feed there as root, then run this install again"
elif [ "$DRY" = 1 ]; then
	echo "   $AUDIT_FEED rules --account $SLUG > $AUDIT_DIR/50-derm-<uid>.rules (0640, root's); $AUGENRULES --load"
else
	acct_uid="$(id -u "$ACCOUNT")"
	audit_file="$AUDIT_DIR/50-derm-$acct_uid.rules"
	tmp="$(mktemp)"
	"$AUDIT_FEED" rules --account "$SLUG" --uid "$acct_uid" >"$tmp" || { rm -f "$tmp"; die "derm-audit-feed could not render the account's rules"; }
	install -o root -g root -m 0640 "$tmp" "$audit_file"
	rm -f "$tmp"
	echo "   $audit_file"
	"$AUGENRULES" --load || echo "   augenrules --load failed: the rules load at the next boot, or run it again"
fi

DONE=1
say "done"
cat <<EOF
Check, as anyone:          $PY -I $HELPER check
Check the kernel, as it:   sudo -n -u $ACCOUNT $PY -I $HELPER check --probe
Sign it in to a harness:   derm agents login <harness> --account $SLUG
Undo:                      $UNDO_CMD
EOF
