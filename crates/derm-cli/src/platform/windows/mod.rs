//! `derm` on Windows (wave 5, lane Z): what only the CLI needs, beside the
//! seam's shared primitives in `derm_core::platform`. `exec` is the seam's
//! primitive 5 (the harness's process tree, stops, exit codes), with the
//! functions `run/exec.rs` gives on Unix; `shim` finds the program and reads
//! npm's `.cmd` shims (note AU section 4; proposed case AU-3).

pub mod exec;
pub mod shim;

use std::time::Duration;

/// `CREATE_NEW_PROCESS_GROUP`: a child that `terminate_group` can send
/// Ctrl-Break to alone (the Windows form of `process_group(0)`).
pub const NEW_GROUP: u32 = windows_sys::Win32::System::Threading::CREATE_NEW_PROCESS_GROUP;

/// The Windows form of SIGTERM then SIGKILL to a process group: Ctrl-Break
/// to the group `pid` leads (it was started with `NEW_GROUP`), then, after
/// `escalate`, the process itself is ended. Windows has no group kill; a
/// child it started outside the console group outlives this (I).
pub fn terminate_group(pid: u32, escalate: Duration) {
    use windows_sys::Win32::System::Console::{GenerateConsoleCtrlEvent, CTRL_BREAK_EVENT};
    // SAFETY: sends Ctrl-Break to one process group; a stale id fails.
    unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid) };
    std::thread::spawn(move || {
        std::thread::sleep(escalate);
        terminate(pid);
    });
}

fn terminate(pid: u32) {
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
    // SAFETY: a handle we close at once; a stale pid fails to open.
    unsafe {
        let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if !h.is_null() {
            TerminateProcess(h, 1);
            windows_sys::Win32::Foundation::CloseHandle(h);
        }
    }
}

/// The console's input buffer, opened by name (`CONIN$`) whatever stdin is:
/// the approver reads its answers there (fix pass 9), so its echo and its
/// typed-ahead input are that buffer's, not a redirected stdin's. Read and
/// write access: `SetConsoleMode` on an input buffer needs `GENERIC_READ`,
/// `FlushConsoleInputBuffer` needs `GENERIC_WRITE` (Microsoft, "SetConsoleMode
/// function", "FlushConsoleInputBuffer function"; "Console Handles").
fn console_input() -> Option<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("CONIN$")
        .ok()
}

/// The console's echo off or on (`ENABLE_ECHO_INPUT` on the console input),
/// the Windows form of clearing termios' `ECHO` for a password. Until fix
/// pass 9 this took the standard input handle, which is not the console
/// when stdin is redirected, so the echo stayed on there.
pub fn set_console_echo(on: bool) {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Console::{GetConsoleMode, SetConsoleMode, ENABLE_ECHO_INPUT};
    let Some(conin) = console_input() else {
        return;
    };
    // SAFETY: the handle is the open file's, alive for this block; the mode
    // is plain data, set only when it was read.
    unsafe {
        let h = conin.as_raw_handle() as _;
        let mut mode = 0u32;
        if GetConsoleMode(h, &mut mode) == 0 {
            return;
        }
        let mode = if on {
            mode | ENABLE_ECHO_INPUT
        } else {
            mode & !ENABLE_ECHO_INPUT
        };
        SetConsoleMode(h, mode);
    }
}

/// The console's echo state, when there is a console (for the test).
pub fn console_echo() -> Option<bool> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Console::{GetConsoleMode, ENABLE_ECHO_INPUT};
    let conin = console_input()?;
    let mut mode = 0u32;
    // SAFETY: as above.
    (unsafe { GetConsoleMode(conin.as_raw_handle() as _, &mut mode) } != 0)
        .then_some(mode & ENABLE_ECHO_INPUT != 0)
}

/// Drops typed-ahead console input (`FlushConsoleInputBuffer` on `CONIN$`),
/// the Windows form of `tcflush(TCIFLUSH)`.
pub fn flush_console_input() {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Console::FlushConsoleInputBuffer;
    let Some(conin) = console_input() else {
        return;
    };
    // SAFETY: the open file's handle; a failure is harmless.
    unsafe {
        FlushConsoleInputBuffer(conin.as_raw_handle() as _);
    }
}

#[cfg(test)]
mod tests {
    /// Fix pass 9 (note BG section 3): the approver reads `CONIN$`, so its
    /// echo is that console's, even with stdin redirected (as under cargo
    /// test or a script). Where the process has no console there is nothing
    /// to turn off and nothing to read, so nothing is asserted there.
    #[test]
    fn fp9_echo_is_the_consoles_even_with_stdin_redirected() {
        let Some(before) = super::console_echo() else {
            eprintln!("no console here: CONIN$ did not open");
            return;
        };
        super::set_console_echo(false);
        let off = super::console_echo();
        super::set_console_echo(true);
        let on = super::console_echo();
        super::set_console_echo(before);
        assert_eq!((off, on), (Some(false), Some(true)));
    }
}
