//! Tests of computer use on Linux (`direct.rs`, lane U) against a stand-in
//! for `cua-driver mcp --direct` at cua-driver-rs 0.38.0, and a fixture
//! `/proc`. The real driver was not run in the cloud (the lane's status doc).

use super::*;
use crate::computer_use::core::Core;
use crate::computer_use::facade::{Backend, CallOutcome};
use std::os::unix::fs::{symlink, PermissionsExt};

/// The stand-in: checks its arguments and environment, keeps the manifest it
/// read, answers one request at a time, logs, and exits on stdin EOF.
const FAKE_DRIVER: &str = r#"#!/bin/sh
dir="$(dirname "$0")"
log="$dir/driver.log"
say() { printf '%s\n' "$*" >> "$log"; }
[ "$*" = "mcp --direct" ] || { say "bad args: $*"; exit 64; }
[ "$CUA_DRIVER_PERMISSION_MODE" = bounded ] || { say "not bounded"; exit 65; }
[ "$CUA_DRIVER_DISABLE_UNRESTRICTED" = 1 ] || { say "unrestricted allowed"; exit 65; }
[ "$CUA_DRIVER_RS_TELEMETRY_ENABLED" = false ] || { say "telemetry on"; exit 65; }
[ "$CUA_DRIVER_CAPABILITY_MANIFEST_APPROVED" = 1 ] || { say "not approved"; exit 65; }
[ -f "$CUA_DRIVER_CAPABILITY_MANIFEST_FILE" ] || { say "no manifest"; exit 65; }
[ -z "$CUA_DRIVER_DANGEROUSLY_BYPASS_APPROVALS" ] || { say "bypass"; exit 65; }
[ -z "$ANTHROPIC_API_KEY" ] || { say "leaked key"; exit 65; }
cp "$CUA_DRIVER_CAPABILITY_MANIFEST_FILE" "$dir/read-manifest.yaml"
say "start display=$DISPLAY"
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  [ -z "$id" ] && continue
  case "$line" in
    *'"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"fake"}}}\n' "$id" ;;
    *'"tools/list"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"click"},{"name":"list_windows"}]}}\n' "$id" ;;
    *'"list_windows"'*|*'"list_apps"'*)
      # cua-driver-rs 0.38.0: an observation with no pid and no window_id is
      # a whole-display one (`cua-driver-core/src/tool.rs:2598-2632`), which
      # a manifest with `display: false` refuses (`session_manifest.rs:204`).
      case "$line" in
        *'"pid":'*)
          pid=$(printf '%s' "$line" | sed -n 's/.*"pid":\([0-9][0-9]*\).*/\1/p')
          say "call list_windows pid=$pid"
          printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"1 window"}],"structuredContent":{"windows":[{"app_name":"calc","pid":%s,"window_id":7,"z_index":1},{"app_name":"other","pid":999,"window_id":8,"z_index":2}]}}}\n' "$id" "$pid" ;;
        *)
          say "refused display"
          printf '{"jsonrpc":"2.0","id":%s,"result":{"isError":true,"content":[{"type":"text","text":"protected resource is outside the capability manifest: desktop display observation is outside the capability manifest"}]}}\n' "$id" ;;
      esac ;;
    *) say "call other"; printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"ok"}]}}\n' "$id" ;;
  esac
done
say eof
"#;

/// A folder whose every ancestor is writable only by its owner (the test
/// binary's own), for `find_driver`; `/tmp` is not.
fn root(name: &str) -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let base = exe
        .parent()
        .unwrap()
        .join(format!("cu-direct-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(&base)
        .unwrap();
    base
}

fn executable(path: &Path, text: &str) {
    fs::write(path, text).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// A fixture `/proc` with one process of ours running `program`.
fn proc_with(root: &Path, pid: u32, program: &Path, comm: &str) -> PathBuf {
    let proc_root = root.join("proc");
    let dir = proc_root.join(pid.to_string());
    fs::create_dir_all(&dir).unwrap();
    symlink(program, dir.join("exe")).unwrap();
    fs::write(dir.join("comm"), format!("{comm}\n")).unwrap();
    proc_root
}

fn launcher(root: &Path, proc_root: PathBuf, env: Vec<(String, String)>) -> DirectLauncher {
    let driver = root.join("bin").join("cua-driver");
    fs::create_dir_all(driver.parent().unwrap()).unwrap();
    executable(&driver, FAKE_DRIVER);
    let data = root.join("data");
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&data)
        .unwrap();
    DirectLauncher {
        driver: Some(driver),
        data: Some(data),
        env,
        home: root.to_path_buf(),
        proc_root,
    }
}

#[test]
fn the_driver_is_taken_only_from_a_file_no_one_else_can_change() {
    let base = root("find");
    let uid = current_uid();
    let good = base.join("good");
    fs::create_dir_all(&good).unwrap();
    fs::set_permissions(&good, fs::Permissions::from_mode(0o755)).unwrap();
    executable(&good.join("cua-driver"), "#!/bin/sh\n");
    // Every folder above must be root's or ours. Where the test runs inside
    // a folder another user owns (this cloud workspace runs as root under
    // /home/claude), the good driver is refused too, as the rule says, and
    // the positive half runs in CI.
    let chain_trusted = good
        .ancestors()
        .all(|d| fs::metadata(d).is_ok_and(|m| trusted_owner(&m, uid)));
    assert_eq!(
        find_driver(&[good.join("cua-driver")], uid),
        chain_trusted.then(|| fs::canonicalize(good.join("cua-driver")).unwrap())
    );
    // Group-writable file, group-writable folder, not executable, missing.
    let loose = base.join("loose");
    fs::create_dir_all(&loose).unwrap();
    executable(&loose.join("cua-driver"), "#!/bin/sh\n");
    fs::set_permissions(loose.join("cua-driver"), fs::Permissions::from_mode(0o775)).unwrap();
    let open = base.join("open");
    fs::create_dir_all(&open).unwrap();
    executable(&open.join("cua-driver"), "#!/bin/sh\n");
    fs::set_permissions(&open, fs::Permissions::from_mode(0o777)).unwrap();
    let plain = base.join("plain");
    fs::create_dir_all(&plain).unwrap();
    fs::write(plain.join("cua-driver"), "x").unwrap();
    for bad in [
        loose.join("cua-driver"),
        open.join("cua-driver"),
        plain.join("cua-driver"),
        base.join("missing"),
    ] {
        assert_eq!(
            find_driver(std::slice::from_ref(&bad), uid),
            None,
            "{}",
            bad.display()
        );
    }
    // A link is followed and its target checked.
    symlink(good.join("cua-driver"), base.join("link")).unwrap();
    assert_eq!(
        find_driver(&[open.join("cua-driver"), base.join("link")], uid).is_some(),
        chain_trusted
    );
    // A file owned by someone else is refused (root's files are trusted for
    // everyone).
    if uid != 0 {
        assert_eq!(
            find_driver(&[good.join("cua-driver")], uid.wrapping_add(4242)),
            None
        );
    }
    let _ = fs::set_permissions(&open, fs::Permissions::from_mode(0o755));
    let _ = fs::remove_dir_all(base);
}

#[test]
fn the_drivers_environment_is_cleared_bounded_and_keeps_only_the_display() {
    let daemon = vec![
        ("DISPLAY".to_string(), ":1".to_string()),
        ("WAYLAND_DISPLAY".to_string(), "wayland-0".to_string()),
        ("ANTHROPIC_API_KEY".to_string(), "sk-x".to_string()),
        (
            "CUA_DRIVER_PERMISSION_MODE".to_string(),
            "unrestricted".to_string(),
        ),
        (
            "CUA_DRIVER_DANGEROUSLY_BYPASS_APPROVALS".to_string(),
            "1".to_string(),
        ),
        ("DERM_CHAT_TOKEN".to_string(), "a".repeat(64)),
        ("LD_PRELOAD".to_string(), "/tmp/x.so".to_string()),
    ];
    let env = launch_env(&daemon, Path::new("/home/t"));
    let get = |k: &str| {
        env.iter()
            .filter(|(key, _)| key == k)
            .map(|(_, v)| v.as_str())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        get("CUA_DRIVER_PERMISSION_MODE"),
        vec!["bounded"],
        "only derm's"
    );
    assert_eq!(get("DISPLAY"), vec![":1"]);
    assert_eq!(get("WAYLAND_DISPLAY"), vec!["wayland-0"]);
    assert_eq!(get("CUA_DRIVER_DISABLE_UNRESTRICTED"), vec!["1"]);
    assert_eq!(get("CUA_DRIVER_RS_TELEMETRY_ENABLED"), vec!["false"]);
    assert_eq!(get("CUA_DRIVER_RS_UPDATE_CHECK"), vec!["false"]);
    for never in [
        "ANTHROPIC_API_KEY",
        "CUA_DRIVER_DANGEROUSLY_BYPASS_APPROVALS",
        "DERM_CHAT_TOKEN",
        "LD_PRELOAD",
    ] {
        assert!(get(never).is_empty(), "{never}");
    }
}

#[test]
fn a_running_program_is_found_by_name_and_named_by_its_executable() {
    let base = root("resolve");
    let app = base.join("apps").join("gnome-calculator");
    fs::create_dir_all(app.parent().unwrap()).unwrap();
    executable(&app, "#!/bin/sh\n");
    let other = base.join("other").join("gnome-calculator");
    fs::create_dir_all(other.parent().unwrap()).unwrap();
    executable(&other, "#!/bin/sh\n");
    let proc_root = proc_with(&base, 300, &app, "gnome-calculato");
    let found = running_program(&proc_root, current_uid(), "GNOME-Calculator").unwrap();
    assert_eq!(found, app);
    assert_eq!(
        running_program(&proc_root, current_uid(), "gnome-calculato"),
        Some(app.clone()),
        "by comm too"
    );
    assert_eq!(
        running_program(
            &proc_root,
            current_uid().wrapping_add(7),
            "gnome-calculator"
        ),
        None,
        "another user's"
    );
    // The engine's resolve, through the protocol.
    let core = Core::new(
        Box::new(launcher(&base, proc_root, vec![])),
        Box::new(|_| {}),
        true,
    );
    let info = core.resolve("gnome-calculator").unwrap();
    assert_eq!(info.bundle_id, "exe.gnome-calculator");
    assert_eq!(info.path.as_deref(), Some(app.to_str().unwrap()));
    // The same file name at another path gets its own id.
    let second = core.resolve(other.to_str().unwrap()).unwrap();
    assert!(
        second.bundle_id.starts_with("exe.gnome-calculator."),
        "{}",
        second.bundle_id
    );
    assert_ne!(second.bundle_id, info.bundle_id);
    let _ = fs::remove_dir_all(base);
}

#[test]
fn derms_own_programs_cua_driver_lockers_and_password_stores_are_never_resolved() {
    let base = root("never");
    let mut proc_root = PathBuf::new();
    for (proc_pid, name) in (400..).zip([
        "derm-daemon",
        "cua-driver",
        "keepassxc",
        "swaylock",
        "pinentry-curses",
        "derm-anything",
    ]) {
        let path = base.join("bin2").join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        executable(&path, "#!/bin/sh\n");
        proc_root = proc_with(&base, proc_pid, &path, name);
    }
    let core = Core::new(
        Box::new(launcher(&base, proc_root, vec![])),
        Box::new(|_| {}),
        true,
    );
    for name in [
        "derm-daemon",
        "cua-driver",
        "keepassxc",
        "swaylock",
        "pinentry-curses",
        "derm-anything",
    ] {
        assert!(core.resolve(name).is_none(), "{name}");
    }
    let _ = fs::remove_dir_all(base);
}

#[test]
fn a_runtime_starts_bounded_with_the_executable_in_its_manifest_and_ends_on_stop() {
    let base = root("e2e");
    let app = base.join("apps").join("calc");
    fs::create_dir_all(app.parent().unwrap()).unwrap();
    executable(&app, "#!/bin/sh\n");
    let proc_root = proc_with(&base, 500, &app, "calc");
    let env = vec![
        ("DISPLAY".to_string(), ":7".to_string()),
        ("ANTHROPIC_API_KEY".to_string(), "sk-x".to_string()),
        (
            "CUA_DRIVER_DANGEROUSLY_BYPASS_APPROVALS".to_string(),
            "1".to_string(),
        ),
    ];
    let core = Core::new(
        Box::new(launcher(&base, proc_root, env)),
        Box::new(|_| {}),
        true,
    );
    core.set_chat("c1", true);
    let id = core.resolve("calc").unwrap().bundle_id;
    core.grant("c1", "pi", &id, None, None).unwrap();
    let outcome = Backend::call(
        &*core,
        "c1",
        "list_windows",
        json!({"on_screen_only": true}),
    );
    let CallOutcome::Done(result) = outcome else {
        panic!(
            "{outcome:?}; log: {:?}",
            fs::read_to_string(base.join("bin/driver.log"))
        );
    };
    assert_eq!(
        result["structuredContent"]["windows"][0]["app_name"],
        "calc"
    );
    // Box test w5, BW5-19: the driver refuses an unfiltered listing under
    // derm's manifest, so the daemon lists per granted program's pid.
    assert_eq!(result["structuredContent"]["windows"][0]["pid"], 500);
    // Fix pass 1's review, F6: a window the driver returns for another pid
    // is not passed on.
    assert_eq!(
        result["structuredContent"]["windows"]
            .as_array()
            .map(Vec::len),
        Some(1),
        "{result}"
    );
    let apps = Backend::call(&*core, "c1", "list_apps", json!({}));
    let CallOutcome::Done(apps) = apps else {
        panic!("{apps:?}");
    };
    assert_eq!(apps["structuredContent"]["apps"][0]["pid"], 500, "{apps}");
    assert_eq!(
        apps["structuredContent"]["apps"][0]["name"], "calc",
        "{apps}"
    );
    let read = fs::read_to_string(base.join("bin/read-manifest.yaml")).unwrap();
    assert!(
        read.contains(&format!("- executable: \"{}\"", app.display())),
        "{read}"
    );
    assert!(!read.contains("bundle_id"), "{read}");
    assert!(read.contains("display: false"), "{read}");
    let log = fs::read_to_string(base.join("bin/driver.log")).unwrap();
    assert!(log.contains("start display=:7"), "{log}");
    assert!(
        !log.contains("bad args") && !log.contains("leaked") && !log.contains("bypass"),
        "{log}"
    );
    assert!(!log.contains("refused display"), "{log}");
    assert!(log.contains("call list_windows pid=500"), "{log}");
    // The manifest folder is gone once the driver is up.
    let leftovers: Vec<_> = fs::read_dir(base.join("data/computer-use"))
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("m-"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
    // A tool off the manifest's list is refused before the driver.
    let refused = Backend::call(&*core, "c1", "run_script", json!({}));
    assert!(matches!(refused, CallOutcome::Failed(_)), "{refused:?}");
    core.stop("c1");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !fs::read_to_string(base.join("bin/driver.log"))
        .unwrap()
        .contains("eof")
    {
        assert!(Instant::now() < deadline, "the driver saw stdin close");
        thread::sleep(Duration::from_millis(20));
    }
    let _ = fs::remove_dir_all(base);
}

#[test]
fn a_manifest_names_only_programs_this_side_resolved() {
    let base = root("rewrite");
    let server = Server {
        driver: base.join("cua-driver"),
        private: base.clone(),
        env: Vec::new(),
        proc_root: base.join("proc"),
        uid: current_uid(),
        own_exe: None,
        ids: Mutex::new(HashMap::from([(
            "exe.calc".to_string(),
            PathBuf::from("/usr/bin/calc"),
        )])),
        runtimes: Mutex::new(HashMap::new()),
        writer: Mutex::new(Box::new(std::io::sink())),
    };
    let manifest = "version: 3\nresources:\n  apps:\n    - bundle_id: \"exe.calc\"\n      launch: true\n  desktop:\n    display: false\n";
    let out = server.rewrite(manifest).unwrap();
    assert!(
        out.contains("    - executable: \"/usr/bin/calc\"\n"),
        "{out}"
    );
    assert!(server
        .rewrite(&manifest.replace("exe.calc", "exe.other"))
        .is_err());
    assert!(server
        .rewrite(&format!("{manifest}    - executable: \"/bin/sh\"\n"))
        .is_err());
    assert!(server.rewrite("version: 3\n").is_err(), "no app");
    let _ = fs::remove_dir_all(base);
}
