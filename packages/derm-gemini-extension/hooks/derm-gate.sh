#!/bin/sh
# derm's gate launcher for a plugin's hooks file (wave 5b lane 5bF).
#
#   /bin/sh <plugin>/hooks/derm-gate.sh <agent> <event>
#
# A plugin's own hooks file cannot know where derm is when it is installed,
# so it runs this file with /bin/sh by its absolute path, and this file runs
# `derm hook <agent> <event>` from derm's own install folders
# (contracts/hook-dialects.md 9.1; rules case 227). Until wave 5b the hooks
# file ran `node` found on PATH, and a project's settings `env.PATH` chose
# which node ran derm's gate (note BC, BC-3, run). Nothing here looks a
# program up on PATH, and nothing here reads a variable a project can set,
# except HOME, which no project setting reaches in Claude Code (note BC
# section 3, run) and which is used only when it is absolute.
#
# The folders are the ones derm's installs use, in the order the in-process
# plugins try them (packages/*/src/serve/client.ts, installCandidates; a
# Rust test holds the two lists equal, case 112). A derm is run only when its
# real path is a regular, executable file owned by you or root that no one
# else may write, in a folder of the same kind, the folder it is named in
# too, none of it inside the session's folder, as case 109's rule says
# ("no one else" as `closed` below reads it; derm connect's check and the
# in-process clients read it the same way, case 112).
# Anything else blocks the call in the agent's own form and says why.
#
# The same file sits in derm's Claude Code plugin, Codex plugin and Gemini
# extension (a test holds the three equal). POSIX sh only: dash, bash and
# macOS's sh run it. Windows does not (lane 5bF's Windows half).

agent=${1-}
event=${2-}

# The agent's own block when derm cannot run: Claude Code and Codex read
# exit 2 with the reason on stderr; Gemini reads its JSON on stdout as well.
block() {
  reason="derm: $*"
  if [ "$agent" = gemini ]; then
    printf '{"decision":"deny","reason":"%s"}\n' "$(printf '%s' "$reason" | /usr/bin/tr -d '"\\')"
  fi
  printf '%s\n' "$reason" >&2
  exit 2
}

case "$agent:$event" in
  claude-code:pre | claude-code:post | codex:pre | codex:post | gemini:before | gemini:after) ;;
  *) agent=; block "derm-gate.sh takes claude-code pre|post, codex pre|post or gemini before|after" ;;
esac

[ -x /usr/bin/id ] || block "no /usr/bin/id to read your user id"
me=$(/usr/bin/id -u) || block "cannot read your user id"

# The mode string, owner and group of a path, links not followed:
# "<mode> <uid> <gid>".
mode_owner() {
  out=$(/bin/ls -ldn -- "$1" 2>/dev/null) || return 1
  # shellcheck disable=SC2086
  set -- $out
  printf '%s %s %s' "$1" "$3" "$4"
}

# macOS only (MW5B-1): whether a path's access list lets anyone write.
# macOS keeps access lists apart from the mode bits, and `ls -l` shows "@"
# for extended attributes before it would show "+" for an access list, so
# the entries are read: each line after the first is
# " <n>: <uuid>[ inherited] <allow|deny> <perm,...>" (Apple file_cmds-479,
# ls/print.c:322-385). An entry that is not a deny and names a permission
# that lets its holder change the file or what a folder holds is open,
# whoever it names; a line that cannot be placed is open; so is a path ls
# cannot read. Returns 0 when open.
acl_open() {
  lines=$(/bin/ls -lden -- "$1" 2>/dev/null) || return 0
  printf '%s\n' "$lines" | {
    read -r _first
    while read -r n _who t1 t2 rest; do
      case "$n" in *:) ;; *) exit 0 ;; esac
      if [ "$t1" = inherited ]; then
        kind=$t2
        perms=${rest%% *}
      else
        kind=$t1
        perms=$t2
      fi
      [ -n "$kind" ] || exit 0
      [ "$kind" = deny ] && continue
      case ",$perms," in
        *,write,* | *,append,* | *,delete,* | *,add_file,* | *,add_subdirectory,* | *,delete_child,* | *,writeattr,* | *,writeextattr,* | *,writesecurity,* | *,chown,*) exit 0 ;;
      esac
    done
    exit 1
  }
}

# Owned by you or root, no other write bit, no group write bit unless the
# group is macOS's admin and you are in it (MW5B-2: Homebrew's installer
# gives its prefix folders g+rwx with group admin for an admin, install.sh
# at 7986efa lines 182-192; an admin can already sudo, and staff, which
# every account shares, stays refused). On macOS no access list entry that
# lets anyone write (MW5B-1); elsewhere no access list at all ("+"; on Linux
# the group bits are the list's mask, acl(5), so this is stricter than it
# needs to be).
closed() {
  mo=$(mode_owner "$1") || return 1
  mode=${mo%% *}
  rest=${mo#* }
  uid=${rest%% *}
  gid=${rest#* }
  case "$uid" in "$me" | 0) ;; *) return 1 ;; esac
  case "$mode" in ????????w*) return 1 ;; esac
  case "$mode" in
    ?????w*) { [ -n "$admin" ] && [ "$gid" = "$admin_gid" ]; } || return 1 ;;
  esac
  if [ "$sys" = Darwin ]; then
    acl_open "$1" && return 1
  else
    case "$mode" in *+) return 1 ;; esac
  fi
  return 0
}

# The real folder of a path's parent, links followed.
real_dir() {
  (cd -P -- "${1%/*}" 2>/dev/null && pwd -P)
}

here=$(pwd -P 2>/dev/null) || here=

# Why a candidate may not run, or nothing when it may.
refuse() {
  c=$1
  [ -e "$c" ] || [ -L "$c" ] || { echo "not there"; return; }
  dir=$(real_dir "$c") || { echo "its folder cannot be read"; return; }
  closed "$dir" || { echo "others may write $dir"; return; }
  f=$dir/${c##*/}
  hops=0
  while [ -L "$f" ]; do
    hops=$((hops + 1))
    [ "$hops" -le 8 ] || { echo "too many links"; return; }
    line=$(/bin/ls -ld -- "$f" 2>/dev/null) || { echo "cannot be read"; return; }
    to=${line#*" -> "}
    case "$to" in
      /*) ;;
      *) to=${f%/*}/$to ;;
    esac
    dir=$(real_dir "$to") || { echo "a link leads nowhere"; return; }
    closed "$dir" || { echo "others may write $dir"; return; }
    f=$dir/${to##*/}
  done
  [ -f "$f" ] || { echo "not a regular file"; return; }
  [ -x "$f" ] || { echo "not executable"; return; }
  closed "$f" || { echo "owned by someone else, or others may write it"; return; }
  if [ -n "$here" ] && [ "$here" != / ]; then
    case "$f" in "$here"/*) echo "inside the session's folder, which a project can write"; return ;; esac
  fi
  echo "ok $f"
}

sys=
for u in /usr/bin/uname /bin/uname; do
  [ -x "$u" ] && sys=$("$u" -s 2>/dev/null) && break
done
case "$sys" in
  Darwin) brew="/opt/homebrew/bin/derm /usr/local/bin/derm" ;;
  *) brew="/home/linuxbrew/.linuxbrew/bin/derm /usr/local/bin/derm" ;;
esac
# Whether you are in macOS's admin group, as `/usr/bin/id -G` lists your
# groups (Directory Services' full membership, Apple shell_cmds-329
# id/id.c:532-566); never on another system.
admin_gid="80"
admin=
if [ "$sys" = Darwin ] && [ -x /usr/bin/id ]; then
  case " $(/usr/bin/id -G 2>/dev/null) " in *" $admin_gid "*) admin=1 ;; esac
fi
local_bin=
case "${HOME-}" in /?*) local_bin=${HOME%/}/.local/bin/derm ;; esac

tried=
for c in $local_bin $brew /usr/bin/derm; do
  res=$(refuse "$c")
  case "$res" in
    "ok "/*) exec "${res#ok }" hook "$agent" "$event" ;;
    "not there") ;;
    *) tried="$tried; $c: $res" ;;
  esac
done
block "no derm this hook can trust${tried:+ (${tried#; })}: install derm in ~/.local/bin, Homebrew or /usr/bin (derm is never looked up on PATH, rules case 227)"
