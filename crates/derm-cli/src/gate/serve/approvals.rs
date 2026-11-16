//! Cline's approval folder (T2.7; note BF section 4.4): `approvals.check`
//! judges it through the platform seam, so on Windows, where Node reads no
//! owner and a made-up mode, the folder is judged by its access list.
//!
//! The folder comes from the co-process's own environment
//! (`DERM_CLINE_APPROVAL_DIR`, set by the responder from the `--dir` that
//! `derm run cline` gave it), never from a request: the co-process reads no
//! path a request names (module doc of `serve`). The answer says only
//! whether the folder may be used, and why not.
//!
//! The rules are `folderProblem`'s in `packages/derm-cline/src/responder.ts`
//! (the same as the chat token file's): absolute, outside the session folder,
//! there, not a link, a folder, and yours alone. "Yours alone" is the seam's
//! `owned_private_dir`: Unix, owned by you and no group or other bits;
//! Windows, owned by you (or Administrators, as an elevated token owns what
//! it makes), no reparse point on its path, and no one else in its access
//! list but LocalSystem and Administrators.

use std::path::Path;

use serde_json::{json, Value};

use super::Ctx;
use crate::gate::daemon::{inside_folder, Env};

/// The co-process variable that names the approval folder.
pub const DIR_VAR: &str = "DERM_CLINE_APPROVAL_DIR";

/// Why the approval folder `env` names cannot be used from `cwd`, or `None`.
pub fn problem(env: &Env, cwd: &Path) -> Option<&'static str> {
    let Some(raw) = env.raw(DIR_VAR).filter(|v| !v.is_empty()) else {
        return Some("no approval folder was named to derm gate serve (DERM_CLINE_APPROVAL_DIR)");
    };
    let dir = Path::new(raw);
    if !dir.is_absolute() {
        return Some("the approval folder is not an absolute path");
    }
    if inside_folder(dir, cwd) {
        return Some("the approval folder is inside the session folder, which a project can set");
    }
    let meta = match std::fs::symlink_metadata(dir) {
        Ok(m) => m,
        Err(_) => return Some("the approval folder does not exist"),
    };
    if meta.file_type().is_symlink() {
        return Some("the approval folder is a link");
    }
    if !meta.is_dir() {
        return Some("the approval folder is not a folder");
    }
    if !derm_core::platform::owned_private_dir(dir, &derm_core::platform::effective_user()) {
        return Some(
            "the approval folder can be read or written by others, or is not yours (it must be yours alone)",
        );
    }
    None
}

/// `approvals.check`: `{"ok":true}`, or `{"ok":true,"problem":<why>}`.
pub fn op_check(ctx: &Ctx, id: &Value, _r: &Value) -> Value {
    match problem(&ctx.env, &ctx.cwd) {
        None => json!({"id": id, "ok": true}),
        Some(why) => json!({"id": id, "ok": true, "problem": why}),
    }
}
