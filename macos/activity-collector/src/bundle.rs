//! The collector as an app bundle (lane Y, wave 5): where its launchd job
//! sits inside `derm Activity.app`, found from the running executable.
//!
//! Layout (`packaging/macos/collector/build-app.sh` makes it):
//!
//! ```text
//! derm Activity.app/Contents/Info.plist                 CFBundleIdentifier = <label>
//! derm Activity.app/Contents/MacOS/derm-activity-collector
//! derm Activity.app/Contents/Library/LaunchDaemons/<label>.plist
//! ```
//!
//! `SMAppService.daemon(plistName:)` takes "a property list in the calling
//! app's `Contents/Library/LaunchDaemons` directory" (Apple), and launchd
//! runs its `BundleProgram`, a path inside the bundle; `BundleProgram` "is
//! only supported if the job was installed via `SMAppService`" (Quinn,
//! Apple DTS, forum thread 771162). Nothing here names a label: the one
//! plist in the folder does, and it must be the collector's
//! (`<app>.activity-collector`, case 40) and run this very executable.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// The job the bundle carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleService {
    /// The `.app` folder.
    pub app: PathBuf,
    /// `<label>.plist`, the name `SMAppService` takes.
    pub plist_name: String,
    /// The launchd label, `<app identifier>.activity-collector`.
    pub label: String,
}

/// A launchd plist is small; anything larger is not one of ours.
const MAX_PLIST_BYTES: u64 = 64 * 1024;

/// `<key>K</key>` followed by `<string>V</string>` in the plist's text,
/// tabs or spaces between. The bundle's plist is ours and written in this
/// form (`macos/activity-collector/bundle/`), so a plain text read is
/// enough to check it names this executable; launchd parses it properly.
fn string_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let marker = format!("<key>{key}</key>");
    let mut found = None;
    let mut rest = text;
    while let Some(at) = rest.find(&marker) {
        if found.is_some() {
            return None; // a key twice: refuse
        }
        let after = rest[at + marker.len()..].trim_start();
        let value = after.strip_prefix("<string>")?;
        let end = value.find("</string>")?;
        found = Some(&value[..end]);
        rest = &value[end..];
    }
    found
}

/// The service the bundle around `exe` carries, or why there is none.
/// `exe` is the running executable's real path.
pub fn locate(exe: &Path) -> Result<BundleService, String> {
    let not_in_app = || {
        format!(
            "{} is not inside an app bundle's Contents/MacOS; run the copy inside derm Activity.app",
            exe.display()
        )
    };
    if !exe.is_absolute() {
        return Err(not_in_app());
    }
    let exe_name = exe
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(not_in_app)?;
    let macos = exe.parent().ok_or_else(not_in_app)?;
    let contents = macos.parent().ok_or_else(not_in_app)?;
    let app = contents.parent().ok_or_else(not_in_app)?;
    let named = |p: &Path, want: &str| p.file_name().is_some_and(|n| n == want);
    if !named(macos, "MacOS")
        || !named(contents, "Contents")
        || !app.extension().is_some_and(|e| e == "app")
    {
        return Err(not_in_app());
    }
    let daemons = contents.join("Library").join("LaunchDaemons");
    let mut plists = Vec::new();
    for entry in fs::read_dir(&daemons).map_err(|e| format!("{}: {e}", daemons.display()))? {
        let entry = entry.map_err(|e| format!("{}: {e}", daemons.display()))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(format!("{}: a name that is not UTF-8", daemons.display()));
        };
        if name.ends_with(".plist") {
            plists.push(name.to_string());
        }
    }
    let [plist_name] = plists.as_slice() else {
        return Err(format!(
            "{} must hold exactly one launchd plist; it holds {}",
            daemons.display(),
            plists.len()
        ));
    };
    let label = plist_name.trim_end_matches(".plist");
    if crate::caller::peer_identifier(label).is_none() {
        return Err(format!(
            "{plist_name} is not a collector's job (want <app identifier>{})",
            crate::caller::SUFFIX
        ));
    }
    let path = daemons.join(plist_name);
    let meta = fs::symlink_metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.file_type().is_file() || meta.len() > MAX_PLIST_BYTES {
        return Err(format!(
            "{} is not a plain plist file under {MAX_PLIST_BYTES} bytes",
            path.display()
        ));
    }
    let mut text = String::new();
    fs::File::open(&path)
        .and_then(|f| f.take(MAX_PLIST_BYTES).read_to_string(&mut text))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if string_value(&text, "Label") != Some(label) {
        return Err(format!("{plist_name}: its Label is not {label}"));
    }
    let program = format!("Contents/MacOS/{exe_name}");
    if string_value(&text, "BundleProgram") != Some(program.as_str()) {
        return Err(format!(
            "{plist_name}: its BundleProgram is not {program}, this executable"
        ));
    }
    if text.contains("<key>Program</key>") || text.contains("--dev-peer-path") {
        return Err(format!(
            "{plist_name}: a bundled job names no Program and no dev peer"
        ));
    }
    Ok(BundleService {
        app: app.to_path_buf(),
        plist_name: plist_name.clone(),
        label: label.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn temp_dir() -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "mc-bundle-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    const LABEL: &str = "io.github.aetiusgular.derm.activity-collector";

    /// The plist the repository ships, as the bundle carries it.
    fn shipped_plist() -> String {
        let file = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("bundle")
            .join(format!("{LABEL}.plist"));
        fs::read_to_string(file).unwrap()
    }

    fn app_in(root: &Path, plist: Option<(&str, &str)>) -> PathBuf {
        let app = root.join("derm Activity.app");
        let macos = app.join("Contents/MacOS");
        fs::create_dir_all(&macos).unwrap();
        fs::write(macos.join("derm-activity-collector"), b"x").unwrap();
        let daemons = app.join("Contents/Library/LaunchDaemons");
        fs::create_dir_all(&daemons).unwrap();
        if let Some((name, text)) = plist {
            fs::write(daemons.join(name), text).unwrap();
        }
        macos.join("derm-activity-collector")
    }

    #[test]
    fn the_shipped_bundle_plist_names_this_executable() {
        let root = temp_dir();
        let name = format!("{LABEL}.plist");
        let exe = app_in(&root, Some((&name, &shipped_plist())));
        let service = locate(&exe).unwrap();
        assert_eq!(service.label, LABEL);
        assert_eq!(service.plist_name, name);
        assert_eq!(service.app, root.join("derm Activity.app"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_label_follows_the_plist_not_a_literal() {
        // Case 40: a `.dev` bundle carries its own label and is found by it.
        let root = temp_dir();
        let dev = "io.github.aetiusgular.derm.dev.activity-collector";
        let text = shipped_plist().replace(LABEL, dev);
        let exe = app_in(&root, Some((&format!("{dev}.plist"), &text)));
        assert_eq!(locate(&exe).unwrap().label, dev);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn anything_else_is_refused_with_its_reason() {
        let plist = shipped_plist();
        let name = format!("{LABEL}.plist");
        // Not inside an app bundle.
        for exe in [
            "/usr/local/bin/derm-activity-collector",
            "relative/Contents/MacOS/derm-activity-collector",
            "/Applications/x/Contents/MacOS/derm-activity-collector",
            "/Applications/x.app/Contents/Helpers/derm-activity-collector",
        ] {
            assert!(
                locate(Path::new(exe)).unwrap_err().contains("not inside"),
                "{exe}"
            );
        }
        let cases: Vec<(&str, String, Option<String>)> = vec![
            ("no plist", name.clone(), None),
            (
                "not a collector's job",
                "io.github.aetiusgular.derm.plist".into(),
                Some(plist.replace(LABEL, "io.github.aetiusgular.derm")),
            ),
            (
                "its Label",
                name.clone(),
                Some(plist.replace(
                    &format!("<string>{LABEL}</string>"),
                    "<string>other.activity-collector</string>",
                )),
            ),
            (
                "its BundleProgram",
                name.clone(),
                Some(plist.replace(
                    "Contents/MacOS/derm-activity-collector",
                    "Contents/MacOS/other",
                )),
            ),
            (
                "no Program",
                name.clone(),
                Some(plist.replace(
                    "<key>RunAtLoad</key>",
                    "<key>Program</key>\n\t<string>/tmp/x</string>\n\t<key>RunAtLoad</key>",
                )),
            ),
            (
                "no Program and no dev peer",
                name.clone(),
                Some(plist.replace(
                    "<string>run</string>",
                    "<string>run</string>\n\t\t<string>--dev-peer-path</string>",
                )),
            ),
            (
                "its Label",
                name.clone(),
                Some(plist.replace(
                    "</dict>",
                    "\t<key>Label</key>\n\t<string>x</string>\n</dict>",
                )),
            ),
        ];
        for (want, file, text) in cases {
            let root = temp_dir();
            let exe = match &text {
                Some(body) => app_in(&root, Some((&file, body))),
                None => app_in(&root, None),
            };
            let err = locate(&exe).unwrap_err();
            assert!(
                err.contains(want) || (want == "no plist" && err.contains("exactly one")),
                "{want}: {err}"
            );
            fs::remove_dir_all(root).unwrap();
        }
        // Two plists, or one that is a link, are refused.
        let root = temp_dir();
        let exe = app_in(&root, Some((&name, &plist)));
        let daemons = root.join("derm Activity.app/Contents/Library/LaunchDaemons");
        fs::write(daemons.join("b.activity-collector.plist"), &plist).unwrap();
        assert!(locate(&exe).unwrap_err().contains("exactly one"));
        fs::remove_file(daemons.join("b.activity-collector.plist")).unwrap();
        fs::rename(daemons.join(&name), root.join("elsewhere.plist")).unwrap();
        std::os::unix::fs::symlink(root.join("elsewhere.plist"), daemons.join(&name)).unwrap();
        assert!(locate(&exe).unwrap_err().contains("plain plist"));
        fs::remove_dir_all(root).unwrap();
    }
}
