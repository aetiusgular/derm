//! What the app bundle's service commands print (`main.rs`
//! `cmd_service`): kept here, free of macOS calls, so it is tested on any
//! host.

/// One of the bundle's service commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceOp {
    Register,
    Unregister,
    Status,
}

/// The line a service command prints: what the framework said, as data.
pub fn service_line(
    label: &str,
    status: crate::sm_app_service::Status,
    refusal: Option<&crate::sm_app_service::Refusal>,
) -> String {
    let mut line = serde_json::json!({ "service": label, "status": status.word() });
    if let Some(r) = refusal {
        line["error"] = serde_json::json!({
            "domain": r.domain, "code": r.code, "description": r.description
        });
    }
    line.to_string()
}

/// What to tell you after a command, from the status it left.
pub fn next_step(op: ServiceOp, status: crate::sm_app_service::Status) -> &'static str {
    use crate::sm_app_service::Status;
    match (op, status) {
        (ServiceOp::Register | ServiceOp::Status, Status::RequiresApproval) => {
            "Next: allow it in System Settings, General, Login Items & Extensions. Then give the app Full Disk Access (System Settings, Privacy & Security, Full Disk Access)."
        }
        (ServiceOp::Register | ServiceOp::Status, Status::Enabled) => {
            "It is allowed. It records only once the app has Full Disk Access (System Settings, Privacy & Security, Full Disk Access); `derm-daemon`'s report says whether eslogger runs."
        }
        (ServiceOp::Unregister, Status::NotRegistered | Status::NotFound) => {
            "Removed. Its log stays in /Library/Application Support/derm/activity until you delete it."
        }
        _ => "Not done; the line above has macOS's reason.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_service_command_prints_what_macos_said_as_one_line() {
        use crate::sm_app_service::{Refusal, Status};
        let label = "io.github.aetiusgular.derm.activity-collector";
        let line = service_line(label, Status::RequiresApproval, None);
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["service"], label);
        assert_eq!(v["status"], "requiresApproval");
        assert!(v.get("error").is_none());
        let refusal = Refusal {
            domain: "SMAppServiceErrorDomain".into(),
            code: 1,
            description: "Operation not permitted".into(),
        };
        let line = service_line(label, Status::NotRegistered, Some(&refusal));
        assert!(!line.contains('\n'));
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["error"]["code"], 1);
        // The next step names the two things you do, and nothing claims
        // success that did not happen.
        let step = next_step(ServiceOp::Register, Status::RequiresApproval);
        assert!(step.contains("Login Items") && step.contains("Full Disk Access"));
        let step = next_step(ServiceOp::Register, Status::NotFound);
        assert!(step.starts_with("Not done"));
        let step = next_step(ServiceOp::Unregister, Status::Enabled);
        assert!(step.starts_with("Not done"));
    }
}
