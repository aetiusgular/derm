//! Windows tests for `derm connect <agent> --gate` (`gate.rs`): what the
//! Unix suite (`gate_tests.rs`, shell-script fakes) cannot run here.
//! Integration w6, fix pass 10 (WW6R4-2, Windows test w6 retest 4).

use std::fs;
use std::path::Path;

use super::gate;
use super::presets::Env;
use super::write::tests::{scratch, Answer};
use super::{run, Ctx};

struct NoEnv;
impl Env for NoEnv {
    fn var(&self, _key: &str) -> Option<String> {
        None
    }
}

struct Run {
    code: u8,
    out: String,
    err: String,
}

fn go(home: &Path, args: &[&str]) -> Run {
    let mut a = Answer(true, None);
    let mut ctx = Ctx {
        home: home.to_path_buf(),
        cwd: home.join("proj"),
        macos: false,
        env: &NoEnv,
        confirm: &mut a,
        out: String::new(),
        err: String::new(),
        live: false,
    };
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let code = run(&args, &mut ctx);
    Run {
        code,
        out: ctx.out,
        err: ctx.err,
    }
}

fn read(p: &Path) -> String {
    fs::read_to_string(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn oc(home: &Path, file: &str) -> std::path::PathBuf {
    home.join(".config").join("opencode").join(file)
}

/// WW6R4-2 end to end on Windows: `derm connect opencode --gate --hook
/// <drive path> --write` writes the plugin entry as a `file:///C:/...` URL
/// and `derm-path` beside opencode.json; a junction on the way is refused,
/// naming the real path.
#[test]
fn ww6r4_2_opencode_connects_on_windows_by_a_drive_path() {
    let home = scratch("ww6r4-2-oc");
    let home = std::path::PathBuf::from(gate::without_verbatim(
        &fs::canonicalize(&home).unwrap().to_string_lossy(),
    ));
    let pkg = home
        .join("clone")
        .join("packages")
        .join("derm-opencode-plugin");
    fs::create_dir_all(&pkg).unwrap();
    fs::write(
        pkg.join("package.json"),
        "{\"name\": \"@aetiusgular/derm-opencode-plugin\", \"version\": \"0.0.0\"}\n",
    )
    .unwrap();
    let bin = home.join("bin");
    fs::create_dir_all(&bin).unwrap();
    let derm = bin.join("derm.exe");
    fs::write(&derm, "not run").unwrap();
    gate::TEST_SELF.with(|t| *t.borrow_mut() = Some(derm.clone()));
    fs::create_dir_all(oc(&home, "")).unwrap();
    let dir = pkg.display().to_string();
    let r = go(&home, &["opencode", "--gate", "--hook", &dir, "--write"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    let t = read(&oc(&home, "opencode.json"));
    let url = format!("file:///{}", dir.replace('\\', "/"));
    assert!(t.contains(&url), "{url} in {t}");
    assert!(!t.contains("file://C:"), "{t}");
    assert_eq!(
        read(&oc(&home, "derm-path")).trim_end(),
        gate::without_verbatim(&fs::canonicalize(&derm).unwrap().to_string_lossy())
    );
    // A junction to the same folder is refused, with the real path named.
    let j = home.join("j");
    let made = std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(&j)
        .arg(home.join("clone"))
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
    let via = j.join("packages").join("derm-opencode-plugin");
    let r = go(
        &home,
        &["opencode", "--gate", "--hook", &via.display().to_string()],
    );
    assert_ne!(r.code, 0, "{}{}", r.out, r.err);
    assert!(r.err.contains("its real path is"), "{}{}", r.out, r.err);
    gate::TEST_SELF.with(|t| *t.borrow_mut() = None);
}
