# derm Activity.app

The macOS activity collector (`macos/activity-collector/`) as an app bundle,
so that macOS can run it as a launch daemon registered through
`SMAppService` and give it Full Disk Access that survives updates.

```
derm Activity.app/Contents/Info.plist                          this folder's Info.plist
derm Activity.app/Contents/MacOS/derm-activity-collector        universal (arm64, x86_64)
derm Activity.app/Contents/Library/LaunchDaemons/io.github.aetiusgular.derm.activity-collector.plist
                                                                macos/activity-collector/bundle/
```

Build, sign, notarize and staple, on the Mac with the Developer ID in the
login keychain and the `tk-notary` notarytool profile:

```
packaging/macos/collector/build-app.sh <version> [keychain-profile]
```

It writes `target/dist-macos-collector/derm-activity-<version>-macos.zip` and
`SHA256SUMS.collector`. `--layout <version> <binary> <out dir>` assembles the
unsigned bundle on any system (the daemon's tests run it).

Install: `derm-daemon collector-plan --binary "<path>/derm Activity.app"`
prints the commands and what each one checks. You run them. In short:

1. A root shell copies the app to `/Library/PrivilegedHelperTools/derm Activity.app`,
   makes it root's, checks the three files by the hashes the plan shows and
   the bundle's signature, and only then moves it into place.
2. As yourself: `"/Library/PrivilegedHelperTools/derm Activity.app/Contents/MacOS/derm-activity-collector" register`.
   macOS asks you to allow it (System Settings, General, Login Items & Extensions).
3. Give the app Full Disk Access (System Settings, Privacy & Security).
4. `... service-status` prints `enabled` once allowed.

Why each choice, with sources: `crates/derm-daemon/src/collector/app.rs`
(the route), `sm_app_service.rs` (the calls), and `plans/parallel/tk_lane_Y.md`
in the project (the research).

The collector answers only the `derm-daemon` of a release (signed
`io.github.aetiusgular.derm` by the same team). A daemon you built yourself
needs the terminal route: `collector-plan --binary <bare collector>`.
