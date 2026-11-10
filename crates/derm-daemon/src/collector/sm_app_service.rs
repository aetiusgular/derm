//! `SMAppService` for the collector's app bundle (lane Y, wave 5).
//!
//! One file, two users. The collector binary includes it with `#[path]`
//! (`macos/activity-collector/src/main.rs`) for its `register`,
//! `unregister` and `service-status` commands, run from inside
//! `derm Activity.app`. The daemon crate includes it only under `cfg(test)`,
//! so that CI's `rust-macos` job compiles and runs it: CI does not build the
//! collector's own workspace. Nothing in the daemon calls it.
//!
//! Why the collector registers itself: `SMAppService.daemon(plistName:)`
//! takes "a property list in the calling app's `Contents/Library/
//! LaunchDaemons` directory" (Apple, `daemon(plistName:)`), and the
//! calling app is the process's main bundle, which CoreFoundation derives
//! from the executable's own path (swift-corelibs-foundation
//! `CFBundle_Main.c`, `_CFBundleCopyBundleURLForExecutableURL`; inference
//! for Apple's CoreFoundation, a Mac test step). `derm-daemon` is a bare
//! binary with no bundle, so it cannot. Status values are the SDK's
//! (`objc2-service-management` 0.3.2, generated from the header:
//! not registered 0, enabled 1, requires approval 2, not found 3).
//!
//! No dependency: the Objective-C runtime's own C functions
//! (`objc_getClass`, `sel_registerName`, `objc_msgSend` cast per call),
//! with scalar and pointer arguments and returns only, so no `_stret` form
//! is needed on x86_64.

/// `SMAppService.Status`, by its raw value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    NotRegistered,
    Enabled,
    RequiresApproval,
    NotFound,
    /// A value the SDK does not define today.
    Other(isize),
}

impl Status {
    pub fn from_raw(raw: isize) -> Status {
        match raw {
            0 => Status::NotRegistered,
            1 => Status::Enabled,
            2 => Status::RequiresApproval,
            3 => Status::NotFound,
            n => Status::Other(n),
        }
    }

    /// The word the collector prints and the daemon reads.
    pub fn word(self) -> String {
        match self {
            Status::NotRegistered => "notRegistered".into(),
            Status::Enabled => "enabled".into(),
            Status::RequiresApproval => "requiresApproval".into(),
            Status::NotFound => "notFound".into(),
            Status::Other(n) => format!("unknown({n})"),
        }
    }
}

/// A refusal from the framework: `NSError`'s domain, code and description,
/// capped and with control characters dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub domain: String,
    pub code: isize,
    pub description: String,
}

/// Text from the framework, printable and capped (it reaches a terminal).
pub fn printable(text: &str, cap: usize) -> String {
    text.chars().filter(|c| !c.is_control()).take(cap).collect()
}

#[cfg(target_os = "macos")]
pub mod ffi {
    //! The calls. Each returns what the framework said; nothing is retried.

    use super::{printable, Refusal, Status};
    use std::ffi::{c_char, c_void, CStr, CString};

    type Id = *mut c_void;
    type Sel = *const c_void;

    #[link(name = "objc", kind = "dylib")]
    extern "C" {
        fn objc_getClass(name: *const c_char) -> Id;
        fn sel_registerName(name: *const c_char) -> Sel;
        fn objc_msgSend();
        fn objc_autoreleasePoolPush() -> *mut c_void;
        fn objc_autoreleasePoolPop(pool: *mut c_void);
    }

    #[link(name = "Foundation", kind = "framework")]
    extern "C" {}

    #[link(name = "ServiceManagement", kind = "framework")]
    extern "C" {}

    fn sel(name: &CStr) -> Sel {
        // SAFETY: a NUL-terminated selector name; the runtime interns it.
        unsafe { sel_registerName(name.as_ptr()) }
    }

    fn class(name: &CStr) -> Id {
        // SAFETY: a NUL-terminated class name; null when the class is absent.
        unsafe { objc_getClass(name.as_ptr()) }
    }

    /// An autorelease pool for the length of one call.
    struct Pool(*mut c_void);
    impl Pool {
        fn new() -> Pool {
            // SAFETY: pushes a pool the matching drop pops, on this thread.
            Pool(unsafe { objc_autoreleasePoolPush() })
        }
    }
    impl Drop for Pool {
        fn drop(&mut self) {
            // SAFETY: the pool this value pushed, popped once.
            unsafe { objc_autoreleasePoolPop(self.0) }
        }
    }

    fn ns_string(text: &str) -> Option<Id> {
        let c = CString::new(text).ok()?;
        let f: unsafe extern "C" fn(Id, Sel, *const c_char) -> Id =
            // SAFETY: objc_msgSend called with the signature of
            // +[NSString stringWithUTF8String:].
            unsafe { std::mem::transmute(objc_msgSend as unsafe extern "C" fn()) };
        let s = unsafe {
            f(
                class(c"NSString"),
                sel(c"stringWithUTF8String:"),
                c.as_ptr(),
            )
        };
        (!s.is_null()).then_some(s)
    }

    fn rust_string(ns: Id) -> String {
        if ns.is_null() {
            return String::new();
        }
        let f: unsafe extern "C" fn(Id, Sel) -> *const c_char =
            // SAFETY: -[NSString UTF8String], an inner pointer valid while
            // the string and the pool live.
            unsafe { std::mem::transmute(objc_msgSend as unsafe extern "C" fn()) };
        let p = unsafe { f(ns, sel(c"UTF8String")) };
        if p.is_null() {
            return String::new();
        }
        // SAFETY: UTF8String returns a NUL-terminated C string.
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }

    /// `+[SMAppService daemonServiceWithPlistName:]`, or `None` before
    /// macOS 13 (no such class).
    fn service(plist_name: &str) -> Option<Id> {
        let cls = class(c"SMAppService");
        if cls.is_null() {
            return None;
        }
        let name = ns_string(plist_name)?;
        let f: unsafe extern "C" fn(Id, Sel, Id) -> Id =
            // SAFETY: the class method takes an NSString and returns an
            // autoreleased SMAppService.
            unsafe { std::mem::transmute(objc_msgSend as unsafe extern "C" fn()) };
        let s = unsafe { f(cls, sel(c"daemonServiceWithPlistName:"), name) };
        (!s.is_null()).then_some(s)
    }

    fn status_of(service: Id) -> Status {
        let f: unsafe extern "C" fn(Id, Sel) -> isize =
            // SAFETY: `status` is an NSInteger property.
            unsafe { std::mem::transmute(objc_msgSend as unsafe extern "C" fn()) };
        Status::from_raw(unsafe { f(service, sel(c"status")) })
    }

    fn refusal(error: Id) -> Refusal {
        if error.is_null() {
            return Refusal {
                domain: String::new(),
                code: 0,
                description: "no error given".into(),
            };
        }
        let id_of: unsafe extern "C" fn(Id, Sel) -> Id =
            // SAFETY: -[NSError domain] and -[NSError localizedDescription]
            // return NSStrings.
            unsafe { std::mem::transmute(objc_msgSend as unsafe extern "C" fn()) };
        let int_of: unsafe extern "C" fn(Id, Sel) -> isize =
            // SAFETY: -[NSError code] is an NSInteger.
            unsafe { std::mem::transmute(objc_msgSend as unsafe extern "C" fn()) };
        Refusal {
            domain: printable(&rust_string(unsafe { id_of(error, sel(c"domain")) }), 120),
            code: unsafe { int_of(error, sel(c"code")) },
            description: printable(
                &rust_string(unsafe { id_of(error, sel(c"localizedDescription")) }),
                300,
            ),
        }
    }

    /// The service's status. `None` when the framework is absent.
    pub fn status(plist_name: &str) -> Option<Status> {
        let _pool = Pool::new();
        service(plist_name).map(status_of)
    }

    /// `register` or `unregister`: `Ok` with the status after, or the
    /// framework's refusal with the status after.
    fn change(plist_name: &str, selector: &CStr) -> Result<Status, (Refusal, Status)> {
        let _pool = Pool::new();
        let Some(service) = service(plist_name) else {
            return Err((
                Refusal {
                    domain: String::new(),
                    code: 0,
                    description: "SMAppService is not available (macOS 13 or later)".into(),
                },
                Status::NotFound,
            ));
        };
        let mut error: Id = std::ptr::null_mut();
        let f: unsafe extern "C" fn(Id, Sel, *mut Id) -> i8 =
            // SAFETY: -[SMAppService registerAndReturnError:] and
            // unregisterAndReturnError: take an NSError** and return BOOL
            // (a 1-byte value on both Apple architectures).
            unsafe { std::mem::transmute(objc_msgSend as unsafe extern "C" fn()) };
        let ok = unsafe { f(service, sel(selector), &mut error) } != 0;
        let after = status_of(service);
        if ok {
            Ok(after)
        } else {
            Err((refusal(error), after))
        }
    }

    pub fn register(plist_name: &str) -> Result<Status, (Refusal, Status)> {
        change(plist_name, c"registerAndReturnError:")
    }

    pub fn unregister(plist_name: &str) -> Result<Status, (Refusal, Status)> {
        change(plist_name, c"unregisterAndReturnError:")
    }

    /// `+[SMAppService openSystemSettingsLoginItems]`.
    pub fn open_login_items() {
        let _pool = Pool::new();
        let cls = class(c"SMAppService");
        if cls.is_null() {
            return;
        }
        let f: unsafe extern "C" fn(Id, Sel) =
            // SAFETY: a class method with no arguments and no result.
            unsafe { std::mem::transmute(objc_msgSend as unsafe extern "C" fn()) };
        unsafe { f(cls, sel(c"openSystemSettingsLoginItems")) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_read_as_the_sdk_defines_them() {
        assert_eq!(Status::from_raw(0), Status::NotRegistered);
        assert_eq!(Status::from_raw(1), Status::Enabled);
        assert_eq!(Status::from_raw(2), Status::RequiresApproval);
        assert_eq!(Status::from_raw(3), Status::NotFound);
        assert_eq!(Status::from_raw(9).word(), "unknown(9)");
        assert_eq!(Status::RequiresApproval.word(), "requiresApproval");
    }

    #[test]
    fn framework_text_is_printable_and_capped() {
        assert_eq!(printable("a\nb\u{1b}[31mc", 10), "ab[31mc");
        assert_eq!(printable(&"x".repeat(500), 300).len(), 300);
    }

    /// On macOS (CI's `rust-macos` job): the calls link and answer. A test
    /// binary has no bundle, so a plist name it does not carry is not an
    /// enabled service. Read-only: `register` is never called here.
    #[cfg(target_os = "macos")]
    #[test]
    fn status_answers_for_a_plist_this_process_does_not_carry() {
        let status = ffi::status("io.github.aetiusgular.derm.no-such-service.plist");
        assert!(status.is_some(), "SMAppService is present on macOS 13+");
        assert_ne!(status, Some(Status::Enabled));
    }
}
