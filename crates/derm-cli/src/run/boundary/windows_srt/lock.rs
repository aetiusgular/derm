//! One srt chat at a time on the machine (case 230): a named mutex in the
//! global namespace, held by `derm run` for the chat's life.
//!
//! - Any user can make a mutex there: only file-mapping and symbolic-link
//!   objects need `SeCreateGlobalPrivilege` (Microsoft Learn, "Kernel object
//!   namespaces"). Run as a user, not only as an administrator, on the box
//!   (Windows test step; CI runs as an administrator).
//! - A mutex goes when its last handle closes, so a `derm run` that dies
//!   leaves nothing behind; a mutex whose owner died is "abandoned" and the
//!   next wait takes it (`WaitForSingleObject`, `WAIT_ABANDONED`).
//! - Another user's mutex cannot be opened by us under its default access
//!   list (`CreateMutexW` asks for `MUTEX_ALL_ACCESS` on an existing one):
//!   "access denied" means another user's srt chat holds it, or someone
//!   made the name first to keep srt off this machine. Either way srt does
//!   not start, and the reason says both.

/// The reason a second chat is refused.
pub(crate) const HELD: &str = "another srt chat is running on this machine (any Windows user's): srt on Windows runs every chat as one sandbox account, which cannot keep two chats apart, so derm runs one at a time. Wait for it to end, or use --boundary sbx, or none";

/// The mutex's name.
pub(crate) const NAME: &str = "Global\\derm-srt-windows-chat";

#[cfg(windows)]
mod imp {
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_ACCESS_DENIED, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};

    /// The machine's srt chat lock, held until dropped.
    pub(crate) struct Lock(HANDLE);

    // SAFETY: the handle is a kernel object handle, usable from any thread;
    // only the thread that took the mutex can release it, and a failed
    // release is followed by the close, which abandons it.
    unsafe impl Send for Lock {}

    pub(crate) fn take() -> Result<Lock, String> {
        let name: Vec<u16> = super::NAME.encode_utf16().chain(Some(0)).collect();
        // SAFETY: `name` is NUL-terminated; no security attributes.
        let h = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        if h.is_null() {
            // SAFETY: plain call.
            let e = unsafe { GetLastError() };
            if e == ERROR_ACCESS_DENIED {
                return Err(format!(
                    "{} (or another program holds the name {} to keep srt off this machine)",
                    super::HELD,
                    super::NAME
                ));
            }
            return Err(format!(
                "could not make the srt chat lock: {}",
                std::io::Error::from_raw_os_error(e as i32)
            ));
        }
        // SAFETY: `h` is the mutex just opened.
        match unsafe { WaitForSingleObject(h, 0) } {
            WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(Lock(h)),
            _ => {
                // SAFETY: ours to close.
                unsafe { CloseHandle(h) };
                Err(super::HELD.to_string())
            }
        }
    }

    impl Drop for Lock {
        fn drop(&mut self) {
            // SAFETY: the handle is ours; a release from another thread fails
            // and the close abandons the mutex, which the next wait takes.
            unsafe {
                ReleaseMutex(self.0);
                CloseHandle(self.0);
            }
        }
    }
}

#[cfg(not(windows))]
mod imp {
    /// No such lock off Windows: srt there runs each chat as the user.
    pub(crate) struct Lock;

    pub(crate) fn take() -> Result<Lock, String> {
        Err("internal: the srt chat lock is Windows' only".into())
    }
}

pub(crate) use imp::take;
#[cfg(windows)]
pub(crate) use imp::Lock;

/// Whether another chat holds the lock now (the default choice and the
/// preflight ask before starting srt).
pub(crate) fn held_elsewhere() -> bool {
    cfg!(windows) && take().is_err()
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    /// One test, not two: the mutex is one per machine, so two tests taking
    /// it at once would see each other.
    #[test]
    fn one_holder_at_a_time_and_a_dead_holder_frees_it() {
        let first = take().expect("the lock is free on a fresh runner");
        let other = std::thread::spawn(|| take().map(|_| ()).unwrap_err())
            .join()
            .unwrap();
        assert!(other.contains("another srt chat"), "{other}");
        assert!(std::thread::spawn(held_elsewhere).join().unwrap());
        drop(first);
        assert!(std::thread::spawn(|| take().is_ok()).join().unwrap());
        // A holder that ends without releasing (its handle leaked) leaves the
        // mutex abandoned, and the next wait takes it.
        std::thread::spawn(|| std::mem::forget(take().unwrap()))
            .join()
            .unwrap();
        assert!(take().is_ok());
    }
}
