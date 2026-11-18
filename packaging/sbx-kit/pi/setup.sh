#!/bin/sh
# derm's Pi package inside the sbx VM, the agent's half: the second install
# command of derm's v2 mixin, run as the agent's user after install.sh.
# Pi's own command adds the package, so it lands in the settings file this
# Pi reads (a personal install, never a project one: packages/derm-pi/README.md).
set -eu

fail() {
  echo "derm kit: $*" >&2
  exit 1
}

pkg=/opt/derm-kit/derm-pi

[ -f "$pkg/package.json" ] || fail "$pkg is missing; install.sh did not run"
command -v pi >/dev/null 2>&1 || fail "no pi on PATH in this image"

pi install "$pkg" >/dev/null 2>&1 || fail "pi install $pkg failed (pi $(pi --version 2>&1 | head -n 1))"
pi list 2>/dev/null | grep -q "derm-kit/derm-pi" || fail "pi did not list derm's package after installing it (pi $(pi --version 2>&1 | head -n 1))"

echo "derm kit: derm's gate is registered for pi (pi $(pi --version 2>&1 | head -n 1), node $(node --version 2>&1 | head -n 1))"
