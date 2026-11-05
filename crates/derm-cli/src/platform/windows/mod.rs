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

/// The console's echo off or on (`ENABLE_ECHO_INPUT` on the console input),
/// the Windows form of clearing termios' `ECHO` for a password.
pub fn set_console_echo(on: bool) {
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_ECHO_INPUT, STD_INPUT_HANDLE,
    };
    // SAFETY: the standard input handle needs no closing; the mode is plain
    // data, set only when it was read.
    unsafe {
        let h = GetStdHandle(STD_INPUT_HANDLE);
        let mut mode = 0u32;
        if h.is_null() || GetConsoleMode(h, &mut mode) == 0 {
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

/// Drops typed-ahead console input (`FlushConsoleInputBuffer`), the Windows
/// form of `tcflush(TCIFLUSH)`.
pub fn flush_console_input() {
    use windows_sys::Win32::System::Console::{
        FlushConsoleInputBuffer, GetStdHandle, STD_INPUT_HANDLE,
    };
    // SAFETY: as above; a handle that is not a console fails harmlessly.
    unsafe {
        let h = GetStdHandle(STD_INPUT_HANDLE);
        if !h.is_null() {
            FlushConsoleInputBuffer(h);
        }
    }
}
