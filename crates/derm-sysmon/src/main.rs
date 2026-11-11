//! The `derm-sysmon` binary: `derm-sysmon decode` (any OS), or the service
//! when the service control manager starts it (Windows; `service` is the
//! argument the install gives it, `packaging/windows/sysmon-service/`).

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("decode") if args.len() == 1 => {
            let stdin = std::io::stdin();
            let stdout = std::io::stdout();
            match derm_sysmon::decode::run(stdin.lock(), stdout.lock()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("derm-sysmon decode: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Some("service") if args.len() == 1 => match derm_sysmon::serve() {
            Ok(()) => ExitCode::SUCCESS,
            Err(why) => {
                eprintln!("derm-sysmon: {why}");
                ExitCode::from(2)
            }
        },
        _ => {
            eprintln!("usage: derm-sysmon decode   (Sysmon event XML on stdin, one a line)");
            eprintln!("       derm-sysmon service  (started by Windows' service control manager)");
            ExitCode::from(2)
        }
    }
}
