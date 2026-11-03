//! `derm watch --approve` refuses to start inside a chat. A `tk run` chat
//! left running from before the rename carries `TK_CHAT_*`, not `DERM_CHAT_*`
//! (rename review R2).

use std::process::Command;

fn approve_with(var: &str) -> (Option<i32>, String) {
    let dir = std::env::temp_dir().join(format!("derm-approve-{var}-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let out = Command::new(env!("CARGO_BIN_EXE_derm"))
        .args(["watch", "--approve"])
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", &dir)
        .env("XDG_RUNTIME_DIR", &dir)
        .env(var, "x")
        .output()
        .expect("derm runs");
    let _ = std::fs::remove_dir_all(&dir);
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn the_approver_refuses_a_chat_by_either_name() {
    for var in [
        "DERM_CHAT_ID",
        "DERM_CHAT_TOKEN_FILE",
        "TK_CHAT_ID",
        "TK_CHAT_TOKEN",
        "TK_CHAT_TOKEN_FILE",
    ] {
        let (code, err) = approve_with(var);
        assert_eq!(code, Some(2), "{var}: {err}");
        assert!(
            err.contains(&format!(
                "refused: this process is inside a derm chat ({var} is set)"
            )),
            "{var}: {err}"
        );
    }
}
