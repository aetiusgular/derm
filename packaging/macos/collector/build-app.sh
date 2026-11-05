#!/bin/bash
# Builds derm Activity.app, the activity collector as an app bundle that
# registers its own launchd daemon through SMAppService (lane Y, wave 5).
#
#   packaging/macos/collector/build-app.sh <version> [keychain-profile]
#       On a Mac with Xcode's command line tools, both Apple Rust targets,
#       one "Developer ID Application" identity and a notarytool keychain
#       profile (default tk-notary): builds a universal collector, assembles
#       the bundle, signs it with the hardened runtime, notarizes it, staples
#       the ticket to the app and zips the stapled app.
#       Writes target/dist-macos-collector/derm-activity-<version>-macos.zip,
#       its sha256 line in SHA256SUMS.collector, and the notary log.
#
#   packaging/macos/collector/build-app.sh --layout <version> <binary> <out dir>
#       Assembles the unsigned bundle from a collector binary you built, on
#       any system, into <out dir>/derm Activity.app. For tests and for a
#       look; an unsigned bundle cannot pass the collector's caller check.
#
# Why a bundle: SMAppService takes "a property list in the calling app's
# Contents/Library/LaunchDaemons directory" (Apple), and Full Disk Access
# "has only ever been fully supported for bundled executables" (Kevin
# Elliott, Apple DTS, forum thread 806187). A bundle signed with a
# Developer ID keeps one designated requirement across updates (TN3127), so
# the grant survives a rebuild. Tickets staple to an app bundle, not to a
# bare binary or a ZIP (Apple, Customizing the notarization workflow).
#
# The identity is read from the keychain and passed to codesign; this script
# never prints it. It installs nothing and registers nothing: that is
# `derm-daemon collector-plan`'s list, for you to run.
set -euo pipefail

APP_NAME="derm Activity.app"
BINARY=derm-activity-collector
LABEL=io.github.aetiusgular.derm.activity-collector

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)

check_version() {
  [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || { echo "bad version: $1" >&2; exit 2; }
}

# assemble <version> <binary> <out dir>: the bundle, unsigned.
assemble() {
  local version=$1 binary=$2 out=$3
  check_version "$version"
  [[ -f $binary && ! -L $binary ]] || { echo "not a regular file: $binary" >&2; exit 2; }
  local app="$out/$APP_NAME"
  [[ ! -e $app ]] || { echo "already there, not replaced: $app" >&2; exit 2; }
  # CFBundleVersion is up to three period-separated integers: drop a
  # pre-release suffix there; CFBundleShortVersionString keeps it.
  local bundle_version=${version%%-*}
  mkdir -p "$app/Contents/MacOS" "$app/Contents/Library/LaunchDaemons"
  sed -e "s/@VERSION@/$version/" -e "s/@BUNDLE_VERSION@/$bundle_version/" \
    "$here/Info.plist" > "$app/Contents/Info.plist"
  install -m 0755 "$binary" "$app/Contents/MacOS/$BINARY"
  install -m 0644 "$root/macos/activity-collector/bundle/$LABEL.plist" \
    "$app/Contents/Library/LaunchDaemons/$LABEL.plist"
  printf 'APPL????' > "$app/Contents/PkgInfo"
  echo "$app"
}

if [[ ${1:-} == --layout ]]; then
  [[ $# == 4 ]] || { echo "usage: build-app.sh --layout <version> <binary> <out dir>" >&2; exit 2; }
  assemble "$2" "$3" "$4"
  exit 0
fi

version=${1:?usage: build-app.sh <version> [keychain-profile]}
profile=${2:-tk-notary}
check_version "$version"
[[ $(uname -s) == Darwin ]] || { echo "macOS only (use --layout elsewhere)" >&2; exit 2; }
cd "$root"

out=target/dist-macos-collector
stage=$out/stage
rm -rf "$out"
mkdir -p "$stage"

manifest=macos/activity-collector/Cargo.toml
for t in aarch64-apple-darwin x86_64-apple-darwin; do
  cargo build --release --locked --manifest-path "$manifest" --target "$t"
done
lipo -create -output "$stage/$BINARY" \
  "macos/activity-collector/target/aarch64-apple-darwin/release/$BINARY" \
  "macos/activity-collector/target/x86_64-apple-darwin/release/$BINARY"
lipo "$stage/$BINARY" -verify_arch arm64 x86_64

app=$(assemble "$version" "$stage/$BINARY" "$stage")

n=$(security find-identity -v -p codesigning | grep -c '"Developer ID Application: ' || true)
[[ $n == 1 ]] || { echo "want exactly one Developer ID Application identity, found $n" >&2; exit 1; }
identity=$(security find-identity -v -p codesigning | awk '/"Developer ID Application: / { print $2; exit }')
# The identifier comes from the bundle's CFBundleIdentifier. No entitlements:
# the collector starts /usr/bin/eslogger and needs Full Disk Access, which
# is a TCC grant you give, not an entitlement.
codesign --force --options runtime --timestamp --sign "$identity" "$app"
unset identity
codesign --verify --strict --deep --verbose=2 "$app"
# The collector derives its peer's requirement from this designated
# requirement (caller.rs checker_requirement): it must start with its
# identifier and name the team, as a Developer ID requirement does.
dr=$(codesign -d -r- "$app" 2>&1 | sed -n 's/^designated => //p')
case $dr in
  "identifier \"$LABEL\" and anchor apple generic and "*) ;;
  *) echo "unexpected designated requirement: $dr" >&2; exit 1 ;;
esac

zip=$out/derm-activity-$version-macos.zip
(cd "$stage" && ditto -c -k --norsrc --noextattr --keepParent "$APP_NAME" "../notarize.zip")
xcrun notarytool submit "$out/notarize.zip" --keychain-profile "$profile" --wait --output-format json > "$out/notary-submit.json"
sub=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$out/notary-submit.json")
status=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "$out/notary-submit.json")
xcrun notarytool log "$sub" --keychain-profile "$profile" "$out/notary-log.json"
echo "notarization $sub: $status"
[[ $status == Accepted ]] || exit 1
rm -f "$out/notarize.zip"

# "run stapler against each item that you added to the archive. Then create
# a new ZIP file containing the stapled items for distribution" (Apple).
xcrun stapler staple "$app"
xcrun stapler validate "$app"
(cd "$stage" && ditto -c -k --norsrc --noextattr --keepParent "$APP_NAME" "../$(basename "$zip")")

(cd "$out" && shasum -a 256 "$(basename "$zip")" > SHA256SUMS.collector)
cat "$out/SHA256SUMS.collector"
