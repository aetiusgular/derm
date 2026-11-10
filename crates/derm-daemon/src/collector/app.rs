//! The collector's app route (lane Y, wave 5): `derm-daemon collector-plan
//! --binary "<path>/derm Activity.app"` prints how to install the signed
//! app bundle and register its daemon through `SMAppService`. Nothing here
//! runs anything (rules section 5, item 2).
//!
//! What the route stands on:
//!
//! - The collector registers itself from inside its bundle
//!   (`macos/activity-collector/src/bundle.rs`, `sm_app_service.rs`): a bare
//!   `derm-daemon` has no bundle for `SMAppService` to read.
//! - launchd runs the job's `BundleProgram` in place, as root. So the app
//!   must sit where no process of yours can change it: the plan copies it
//!   into `/Library/PrivilegedHelperTools`, makes it root's, and only then
//!   checks it, by the hashes this plan shows and by its signature (the
//!   terminal route's rule, security reviews S1, T6, U8, V4). A copy in
//!   `/Applications` or `~/Downloads` is writable by an admin account's
//!   processes, an agent's included. That the job may run from outside
//!   `/Applications` rests on Apple's own sample, run from its build folder
//!   (forum thread 802443); the Mac test w5 confirms it on 26.x.
//! - Full Disk Access goes to the app, a bundled executable (forum thread
//!   806187); a Developer ID signature keeps its designated requirement
//!   across updates, so the grant survives a rebuild (TN3127).

use std::path::{Path, PathBuf};

use crate::activity::collector::{self, InstallPlan, Names};

/// The bundle's name, as `packaging/macos/collector/build-app.sh` makes it.
pub const APP_NAME: &str = "derm Activity.app";
/// Where the plan installs it: root's, as the terminal route's daemon.
pub const APP_HOME: &str = "/Library/PrivilegedHelperTools";

/// The parts of the bundle the plan checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppLayout {
    pub app: PathBuf,
    pub executable: PathBuf,
    pub info_plist: PathBuf,
    pub job_plist: PathBuf,
}

/// The app a path names: the `.app` folder itself, or the collector inside
/// its `Contents/MacOS`. `None` for anything else (a bare binary takes the
/// terminal route).
pub fn app_of(path: &Path) -> Option<PathBuf> {
    if path.extension().is_some_and(|e| e == "app") {
        return Some(path.to_path_buf());
    }
    let macos = path.parent()?;
    let contents = macos.parent()?;
    let app = contents.parent()?;
    (path.file_name()? == collector::BINARY_NAME
        && macos.file_name()? == "MacOS"
        && contents.file_name()? == "Contents"
        && app.extension().is_some_and(|e| e == "app"))
    .then(|| app.to_path_buf())
}

const MAX_PLIST: u64 = 64 * 1024;

fn plain_file(path: &Path, cap: u64) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.file_type().is_file() || meta.len() > cap {
        return Err(format!("{} is not a plain file", path.display()));
    }
    Ok(())
}

fn read_plist(path: &Path) -> Result<String, String> {
    plain_file(path, MAX_PLIST)?;
    std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

/// `<key>K</key>` then `<string>V</string>`; `None` when the key is absent,
/// twice, or not followed by a string. The files are ours, in this form.
fn string_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let marker = format!("<key>{key}</key>");
    let mut found = None;
    let mut rest = text;
    while let Some(at) = rest.find(&marker) {
        if found.is_some() {
            return None;
        }
        let value = rest[at + marker.len()..]
            .trim_start()
            .strip_prefix("<string>")?;
        let end = value.find("</string>")?;
        found = Some(&value[..end]);
        rest = &value[end..];
    }
    found
}

/// Checks that `app` is the collector's bundle for `names`, as
/// `build-app.sh` makes it: no links, the bundle id is the label, the
/// executable is the collector, and the one job plist runs it.
pub fn app_layout(app: &Path, names: &Names) -> Result<AppLayout, String> {
    if !app.is_absolute() {
        return Err("the app needs an absolute path".into());
    }
    let meta = std::fs::symlink_metadata(app).map_err(|e| format!("{}: {e}", app.display()))?;
    if !meta.file_type().is_dir() {
        return Err(format!("{} is not a folder", app.display()));
    }
    for dir in [
        "Contents",
        "Contents/MacOS",
        "Contents/Library",
        "Contents/Library/LaunchDaemons",
    ] {
        let p = app.join(dir);
        let m = std::fs::symlink_metadata(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        if !m.file_type().is_dir() {
            return Err(format!("{} is not a folder", p.display()));
        }
    }
    let info_plist = app.join("Contents/Info.plist");
    let info = read_plist(&info_plist)?;
    if string_value(&info, "CFBundleIdentifier") != Some(names.label.as_str()) {
        return Err(format!(
            "{}: its CFBundleIdentifier is not {}",
            info_plist.display(),
            names.label
        ));
    }
    if string_value(&info, "CFBundleExecutable") != Some(collector::BINARY_NAME) {
        return Err(format!(
            "{}: its CFBundleExecutable is not {}",
            info_plist.display(),
            collector::BINARY_NAME
        ));
    }
    let executable = app.join("Contents/MacOS").join(collector::BINARY_NAME);
    plain_file(&executable, u64::MAX)?;
    let daemons = app.join("Contents/Library/LaunchDaemons");
    let plists: Vec<String> = std::fs::read_dir(&daemons)
        .map_err(|e| format!("{}: {e}", daemons.display()))?
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n.ends_with(".plist"))
        .collect();
    let want = format!("{}.plist", names.label);
    if plists != [want.clone()] {
        return Err(format!(
            "{} must hold exactly {want}; it holds {plists:?}",
            daemons.display()
        ));
    }
    let job_plist = daemons.join(&want);
    let job = read_plist(&job_plist)?;
    let program = format!("Contents/MacOS/{}", collector::BINARY_NAME);
    if string_value(&job, "Label") != Some(names.label.as_str())
        || string_value(&job, "BundleProgram") != Some(program.as_str())
        || job.contains("<key>Program</key>")
        || job.contains("--dev-peer-path")
    {
        return Err(format!(
            "{}: not the collector's bundled job (Label {}, BundleProgram {program}, no Program, no dev peer)",
            job_plist.display(),
            names.label
        ));
    }
    Ok(AppLayout {
        app: app.to_path_buf(),
        executable,
        info_plist,
        job_plist,
    })
}

/// A path the root shell can hold inside double quotes, inside the single
/// quotes of `sh -c`: absolute, and none of `'"$\`` or a control character.
fn shell_safe(path: &str) -> bool {
    path.starts_with('/')
        && !path
            .chars()
            .any(|c| "'\"$`\\".contains(c) || c.is_control())
}

/// The installed app: `APP_HOME/APP_NAME`.
pub fn installed_app() -> PathBuf {
    Path::new(APP_HOME).join(APP_NAME)
}

/// What the plan sees on this Mac before it is shown: whether the terminal
/// route's plist and an installed app are there. Passed in, for tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Present {
    pub terminal_install: bool,
    pub installed_app: bool,
}

impl Present {
    pub fn now(names: &Names) -> Present {
        Present {
            terminal_install: Path::new(&names.plist_path).exists(),
            installed_app: std::fs::symlink_metadata(installed_app()).is_ok(),
        }
    }
}

/// The app route's plan: the commands, the hashes they check, and the words.
pub fn plan(source: &Path, names: &Names, present: Present) -> Result<InstallPlan, String> {
    let layout = app_layout(source, names)?;
    let src = source.to_string_lossy().into_owned();
    if !shell_safe(&src) {
        return Err(format!(
            "The app's path holds a character the install cannot show safely: {src:?}. Move it, for example to ~/Downloads."
        ));
    }
    let hash = |p: &Path| collector::file_sha256(p).map_err(|e| format!("{}: {e}", p.display()));
    let exe_sha = hash(&layout.executable)?;
    let info_sha = hash(&layout.info_plist)?;
    let job_sha = hash(&layout.job_plist)?;
    let job_text = read_plist(&layout.job_plist)?;

    let target = installed_app();
    let target = target.to_string_lossy();
    let label = &names.label;
    let bin = collector::BINARY_NAME;
    let exe = format!("{target}/Contents/MacOS/{bin}");
    let mut commands = Vec::new();
    if present.terminal_install {
        // The terminal route's job has the same label; launchd holds one.
        commands.extend(
            collector::removal_commands(names)
                .into_iter()
                .filter(|c| !c.starts_with('#')),
        );
    }
    if present.installed_app {
        // Stop the running job before its files are replaced.
        commands.push(format!("'{exe}' unregister"));
    }
    // One root shell: copy, make it root's, then check the three files by
    // hash and the bundle's signature, and only then move it into place.
    // Every tool by absolute path (security review T6).
    commands.push(format!(
        "/usr/bin/sudo /bin/sh -c 'N=\"{target}.new\"; A=\"{target}\"; /bin/rm -rf \"$N\" && /usr/bin/ditto \"{src}\" \"$N\" && /usr/sbin/chown -R root:wheel \"$N\" && /bin/chmod -R go-w \"$N\" || {{ echo \"could not copy the app, not installed\"; /bin/rm -rf \"$N\"; exit 1; }}; E=$(/usr/bin/shasum -a 256 \"$N/Contents/MacOS/{bin}\" | /usr/bin/cut -d \" \" -f 1); I=$(/usr/bin/shasum -a 256 \"$N/Contents/Info.plist\" | /usr/bin/cut -d \" \" -f 1); J=$(/usr/bin/shasum -a 256 \"$N/Contents/Library/LaunchDaemons/{label}.plist\" | /usr/bin/cut -d \" \" -f 1); if [ \"$E\" = \"{exe_sha}\" ] && [ \"$I\" = \"{info_sha}\" ] && [ \"$J\" = \"{job_sha}\" ] && /usr/bin/codesign --verify --strict --deep \"$N\"; then /bin/rm -rf \"$A\" && /bin/mv \"$N\" \"$A\" || {{ echo \"could not move the app into place, not installed\"; exit 1; }}; else echo \"hash or signature mismatch, not installed\"; /bin/rm -rf \"$N\"; exit 1; fi'"
    ));
    commands.push(format!(
        "/usr/bin/codesign --display --requirements - '{target}'"
    ));
    commands.push(format!(
        "/usr/sbin/spctl --assess --type execute --verbose=2 '{target}'"
    ));
    commands.push(format!("'{exe}' register"));
    commands.push(format!("'{exe}' service-status"));

    let explanation = vec![
        "The collector runs as root, outside any sandbox, and starts /usr/bin/eslogger. launchd starts it from inside the app, through SMAppService.".to_string(),
        "It records only: processes `derm run` started for a chat (the daemon names each one) and their children, and apps you granted for computer use while the grant holds. It records what they ran, the files they created, wrote, moved or deleted, and opens of sensitive files such as ~/.ssh. Command lines are kept.".to_string(),
        "It blocks nothing. It sends nothing anywhere. Its log is root-owned, kept 7 days, at most 1 GB.".to_string(),
        format!("It answers one caller: a program signed with the identifier {} by the same team as the app, which is the derm-daemon of a derm release. A derm-daemon you built yourself is refused; for that, use the terminal route (collector-plan --binary with a bare collector).", names.app_identifier),
        format!("The root shell command copies {src} to {target}, makes it root's and not writable by anyone else, and only then checks it: the collector SHA-256 {exe_sha}, the Info.plist {info_sha}, the launchd job {job_sha}, and its code signature. Anything else is removed and nothing starts."),
        "The app stays root's so that no process running as you, an agent's included, can change the program launchd runs as root. Do not run the copy you downloaded.".to_string(),
        "The register step runs as you, not with sudo. macOS then asks you to allow it (Background Items Added; System Settings, General, Login Items & Extensions).".to_string(),
        format!("Then give {target} Full Disk Access in System Settings, Privacy & Security, Full Disk Access (the + button, then Command-Shift-G for the path). Until then eslogger cannot start, and the collector's status says why."),
        "Check the signature lines before you register: the requirement names the identifier io.github.aetiusgular.derm.activity-collector and your team, and spctl says Notarized Developer ID.".to_string(),
        "This plan ran no command and wrote no file.".to_string(),
    ];
    Ok(InstallPlan {
        route: "smAppService".into(),
        explanation,
        plist: job_text,
        commands,
        staged_plist: None,
        daemon_path: exe,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("derm-app-{name}-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Runs `build-app.sh --layout` as the release would assemble the
    /// bundle, around a stand-in binary.
    fn built_app(name: &str) -> (PathBuf, PathBuf) {
        let dir = scratch(name);
        let bin = dir.join("collector-bin");
        std::fs::write(&bin, b"stand-in collector").unwrap();
        let out = dir.join("out");
        let status = std::process::Command::new("bash")
            .arg(repo().join("packaging/macos/collector/build-app.sh"))
            .args(["--layout", "0.2.0-rc.1"])
            .arg(&bin)
            .arg(&out)
            .status()
            .unwrap();
        assert!(status.success());
        (dir, out.join(APP_NAME))
    }

    #[test]
    fn the_bundle_files_agree_with_the_daemons_names() {
        // One label everywhere (case 40 asks the names to follow one
        // identifier): the bundle id, the job's file name and Label, the
        // daemon's `Names`, and the collector's own suffix rule.
        let names = Names::release();
        let info =
            std::fs::read_to_string(repo().join("packaging/macos/collector/Info.plist")).unwrap();
        assert_eq!(
            string_value(&info, "CFBundleIdentifier"),
            Some(names.label.as_str())
        );
        assert_eq!(
            string_value(&info, "CFBundleExecutable"),
            Some(collector::BINARY_NAME)
        );
        // SMAppService is macOS 13 and later.
        assert_eq!(string_value(&info, "LSMinimumSystemVersion"), Some("13.0"));
        let job = std::fs::read_to_string(
            repo()
                .join("macos/activity-collector/bundle")
                .join(format!("{}.plist", names.label)),
        )
        .unwrap();
        assert_eq!(string_value(&job, "Label"), Some(names.label.as_str()));
        assert_eq!(
            string_value(&job, "BundleProgram"),
            Some(format!("Contents/MacOS/{}", collector::BINARY_NAME).as_str())
        );
        assert_eq!(
            names.label,
            format!("{}.activity-collector", names.app_identifier)
        );
    }

    #[test]
    fn the_layout_build_gives_a_bundle_the_plan_takes() {
        let (dir, app) = built_app("layout");
        let names = Names::release();
        let layout = app_layout(&app, &names).unwrap();
        assert_eq!(app_of(&layout.executable), Some(app.clone()));
        assert_eq!(app_of(&app), Some(app.clone()));
        assert_eq!(
            app_of(Path::new("/usr/local/bin/derm-activity-collector")),
            None
        );
        let info = std::fs::read_to_string(&layout.info_plist).unwrap();
        assert_eq!(
            string_value(&info, "CFBundleShortVersionString"),
            Some("0.2.0-rc.1")
        );
        assert_eq!(string_value(&info, "CFBundleVersion"), Some("0.2.0"));
        assert!(!info.contains('@'), "every placeholder filled: {info}");

        let plan = plan(&app, &names, Present::default()).unwrap();
        assert_eq!(plan.route, "smAppService");
        let all = plan.commands.join("\n");
        for file in [&layout.executable, &layout.info_plist, &layout.job_plist] {
            let sha = collector::file_sha256(file).unwrap();
            assert!(all.contains(&sha), "{file:?} hash in the commands");
        }
        // Root's copy is made root's before it is checked, checked by hash
        // and signature before it moves, and removed on any mismatch.
        let root = plan
            .commands
            .iter()
            .find(|c| c.contains("/usr/bin/ditto"))
            .unwrap();
        let at = |s: &str| root.find(s).unwrap_or_else(|| panic!("{s} in {root}"));
        assert!(at("/usr/sbin/chown -R root:wheel") < at("/usr/bin/shasum"));
        assert!(at("/usr/bin/codesign --verify --strict --deep") < at("/bin/mv"));
        assert!(root.contains("hash or signature mismatch, not installed"));
        // It is one sh program in single quotes, and it parses.
        let inner = root
            .strip_prefix("/usr/bin/sudo /bin/sh -c '")
            .and_then(|r| r.strip_suffix('\''))
            .unwrap();
        assert!(!inner.contains('\''), "{inner}");
        let parsed = std::process::Command::new("sh")
            .args(["-n", "-c", inner])
            .status()
            .unwrap();
        assert!(parsed.success(), "{inner}");
        assert!(root.contains(&format!("{APP_HOME}/{APP_NAME}.new")));
        // Every root command names its tools by absolute path; register and
        // the status run as you; no dev peer anywhere.
        for c in &plan.commands {
            if c.contains("sudo") {
                assert!(c.starts_with("/usr/bin/sudo /"), "{c}");
            }
        }
        let register = plan
            .commands
            .iter()
            .find(|c| c.ends_with(" register"))
            .unwrap();
        assert!(!register.contains("sudo"), "{register}");
        assert!(register.starts_with(&format!("'{APP_HOME}/{APP_NAME}/Contents/MacOS/")));
        assert!(!all.contains("--dev-peer-path"));
        assert!(!plan.plist.contains("--dev-peer-path"));
        let words = plan.explanation.join("\n");
        for needed in [
            "Login Items",
            "Full Disk Access",
            "not with sudo",
            "root's",
            "ran no command",
        ] {
            assert!(words.contains(needed), "{needed}: {words}");
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Runs the root shell with the Mac's tools swapped for stand-ins and
    /// the target folder moved into a scratch folder: a good copy moves into
    /// place, and a changed file or a bad signature leaves nothing behind.
    fn run_root_shell(root: &str, home: &Path, signature_ok: bool) -> std::process::Output {
        let inner = root
            .strip_prefix("/usr/bin/sudo /bin/sh -c '")
            .and_then(|r| r.strip_suffix('\''))
            .unwrap();
        let shasum = if Path::new("/usr/bin/shasum").exists() {
            "/usr/bin/shasum -a 256"
        } else {
            "sha256sum"
        };
        let inner = inner
            .replace(APP_HOME, &home.to_string_lossy())
            .replace("/usr/bin/ditto", "cp -R")
            .replace("/usr/sbin/chown -R root:wheel", "true")
            .replace("/usr/bin/shasum -a 256", shasum)
            .replace(
                "/usr/bin/codesign --verify --strict --deep",
                if signature_ok { "true" } else { "false" },
            );
        std::process::Command::new("sh")
            .args(["-c", &inner])
            .output()
            .unwrap()
    }

    #[test]
    fn the_root_shell_moves_only_a_copy_that_checks_out() {
        let names = Names::release();
        for (case, spoil, signature_ok, installs) in [
            ("good", false, true, true),
            ("changed after the plan", true, true, false),
            ("bad signature", false, false, false),
        ] {
            let (dir, app) = built_app("shell");
            let plan = plan(&app, &names, Present::default()).unwrap();
            let root = plan.commands.iter().find(|c| c.contains("ditto")).unwrap();
            if spoil {
                std::fs::write(
                    app.join("Contents/MacOS").join(collector::BINARY_NAME),
                    b"swapped",
                )
                .unwrap();
            }
            let home = dir.join("home");
            std::fs::create_dir_all(&home).unwrap();
            let out = run_root_shell(root, &home, signature_ok);
            let installed = home.join(APP_NAME);
            assert_eq!(out.status.success(), installs, "{case}: {out:?}");
            assert_eq!(
                installed
                    .join("Contents/MacOS")
                    .join(collector::BINARY_NAME)
                    .exists(),
                installs,
                "{case}"
            );
            assert!(
                !home.join(format!("{APP_NAME}.new")).exists(),
                "{case}: no .new left"
            );
            if !installs {
                assert!(
                    String::from_utf8_lossy(&out.stdout).contains("not installed"),
                    "{case}"
                );
            }
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn an_earlier_install_is_stopped_first() {
        let (dir, app) = built_app("present");
        let names = Names::release();
        let plan = plan(
            &app,
            &names,
            Present {
                terminal_install: true,
                installed_app: true,
            },
        )
        .unwrap();
        let first_root_copy = plan
            .commands
            .iter()
            .position(|c| c.contains("ditto"))
            .unwrap();
        let bootout = plan
            .commands
            .iter()
            .position(|c| c.contains("launchctl bootout"))
            .unwrap();
        let unregister = plan
            .commands
            .iter()
            .position(|c| c.ends_with(" unregister"))
            .unwrap();
        assert!(bootout < first_root_copy && unregister < first_root_copy);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_bundle_that_is_not_the_collectors_is_refused_with_its_reason() {
        let names = Names::release();
        type Spoil<'a> = (&'a str, &'a dyn Fn(&Path));
        let cases: [Spoil; 6] = [
            ("CFBundleIdentifier", &|app| {
                let p = app.join("Contents/Info.plist");
                let t = std::fs::read_to_string(&p).unwrap();
                std::fs::write(&p, t.replace("derm.activity-collector<", "derm.other<")).unwrap();
            }),
            ("not a plain file", &|app| {
                let p = app.join("Contents/MacOS").join(collector::BINARY_NAME);
                std::fs::remove_file(&p).unwrap();
                std::os::unix::fs::symlink("/bin/sh", &p).unwrap();
            }),
            ("not the collector's bundled job", &|app| {
                let p = app.join(format!(
                    "Contents/Library/LaunchDaemons/{}.plist",
                    Names::release().label
                ));
                let t = std::fs::read_to_string(&p).unwrap();
                std::fs::write(
                    &p,
                    t.replace(
                        "<string>run</string>",
                        "<string>run</string><string>--dev-peer-path</string>",
                    ),
                )
                .unwrap();
            }),
            ("must hold exactly", &|app| {
                std::fs::write(app.join("Contents/Library/LaunchDaemons/x.plist"), "x").unwrap();
            }),
            ("not a folder", &|app| {
                let p = app.join("Contents/Library/LaunchDaemons");
                std::fs::rename(&p, app.join("elsewhere")).unwrap();
                std::os::unix::fs::symlink(app.join("elsewhere"), &p).unwrap();
            }),
            ("CFBundleExecutable", &|app| {
                let p = app.join("Contents/Info.plist");
                let t = std::fs::read_to_string(&p).unwrap();
                std::fs::write(
                    &p,
                    t.replace(
                        "<string>derm-activity-collector</string>",
                        "<string>other</string>",
                    ),
                )
                .unwrap();
            }),
        ];
        for (want, spoil) in cases {
            let (dir, app) = built_app("bad");
            spoil(&app);
            let err = plan(&app, &names, Present::default()).unwrap_err();
            assert!(err.contains(want), "{want}: {err}");
            std::fs::remove_dir_all(dir).unwrap();
        }
        // A path the root shell could not hold.
        let (dir, app) = built_app("quote");
        let odd = dir.join("a\"b");
        std::fs::create_dir_all(&odd).unwrap();
        let moved = odd.join(APP_NAME);
        std::fs::rename(&app, &moved).unwrap();
        assert!(plan(&moved, &names, Present::default())
            .unwrap_err()
            .contains("cannot show safely"));
        assert!(app_layout(Path::new("rel/derm Activity.app"), &names).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
