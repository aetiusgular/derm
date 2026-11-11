//! The `derm-sysmon` service binary (lane 5bE). The base's stub exits 2.

fn main() -> std::process::ExitCode {
    match derm_sysmon::serve() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(why) => {
            eprintln!("{why}");
            std::process::ExitCode::from(2)
        }
    }
}
