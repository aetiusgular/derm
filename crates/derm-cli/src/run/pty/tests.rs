//! Lane PD's tests: the reader on its own (every OS), then the pty session
//! with a pty of the test's own standing in for the person's terminal, and
//! `screen.put` against the real daemon (Unix).

use super::put::Publisher;
use super::*;
use derm_core::project::screen::MAX_TEXT_BYTES;

fn lines_of(r: &mut Reader, n: Option<u32>) -> Vec<String> {
    r.text(n).text.split('\n').map(str::to_string).collect()
}

#[test]
fn rows_are_joined_one_per_terminal_row_even_when_a_line_wraps() {
    let mut r = Reader::new(3, 10);
    r.feed(b"abcdefghijKLM");
    assert_eq!(lines_of(&mut r, None), ["abcdefghij", "KLM", ""]);
}

#[test]
fn scrollback_comes_above_the_screen_up_to_what_a_read_asks() {
    let mut r = Reader::new(24, 80);
    for n in 0..3000 {
        r.feed(format!("line {n}\r\n").as_bytes());
    }
    // The screen: lines 2977 to 2999 and the empty row under the cursor.
    let screen = lines_of(&mut r, None);
    assert_eq!(screen.len(), 24);
    assert_eq!(screen[0], "line 2977");
    assert_eq!(screen[22], "line 2999");
    let five = lines_of(&mut r, Some(5));
    assert_eq!(five.len(), 29);
    assert_eq!(five[0], "line 2972");
    assert_eq!(five[5], "line 2977");
    // Kept: SCROLLBACK_ROWS above the screen, the oldest dropped.
    let all = lines_of(&mut r, Some(MAX_READ_LINES));
    assert_eq!(all.len(), SCROLLBACK_ROWS + 24);
    assert_eq!(all[0], "line 977");
    // More than a read may ask is a read of the most.
    assert_eq!(lines_of(&mut r, Some(u32::MAX)), all);
    let put = r.render();
    assert_eq!((put.rows, put.cols), (24, 80));
    assert_eq!(put.scrollback_lines as usize, SCROLLBACK_ROWS);
    assert!(!put.truncated);
    // Reading scrollback leaves the live screen where it was.
    assert_eq!(lines_of(&mut r, None), screen);
    r.feed(b"next");
    assert_eq!(lines_of(&mut r, None)[23], "next");
}

#[test]
fn the_alternate_screen_has_no_scrollback_and_the_main_one_comes_back() {
    let mut r = Reader::new(4, 20);
    for n in 0..10 {
        r.feed(format!("main {n}\r\n").as_bytes());
    }
    r.feed(b"\x1b[?1049h\x1b[Halt view");
    let t = r.text(Some(100)).text;
    assert!(t.contains("alt view") && !t.contains("main"), "{t:?}");
    assert_eq!(t.split('\n').count(), 4);
    r.feed(b"\x1b[?1049l");
    let t = r.text(Some(100)).text;
    assert!(t.contains("main 9") && !t.contains("alt view"), "{t:?}");
}

#[test]
fn a_render_too_big_for_one_put_is_cut_from_the_top_and_keeps_the_screen() {
    let mut r = Reader::new(10, 500);
    for n in 0..2600 {
        r.feed(format!("{n:04}{}\r\n", "x".repeat(495)).as_bytes());
    }
    let put = r.render();
    assert!(put.truncated);
    assert!(put.text.len() <= MAX_TEXT_BYTES, "{}", put.text.len());
    assert!((put.scrollback_lines as usize) < SCROLLBACK_ROWS);
    let last: Vec<&str> = put.text.split('\n').collect();
    assert_eq!(last.len(), put.scrollback_lines as usize + 10);
    assert!(
        last[last.len() - 2].starts_with("2599"),
        "{:?}",
        &last[last.len() - 2][..8]
    );
}

#[test]
fn sizes_are_kept_inside_what_the_reader_renders() {
    assert_eq!(Reader::new(0, 0).size(), (DEFAULT_ROWS, DEFAULT_COLS));
    assert_eq!(Reader::new(u16::MAX, u16::MAX).size(), (MAX_ROWS, MAX_COLS));
    let mut r = Reader::new(24, 80);
    r.resize(30, 100);
    assert_eq!(r.size(), (30, 100));
    r.resize(0, 7);
    assert_eq!(r.size(), (DEFAULT_ROWS, 7));
}

#[test]
fn the_reader_answers_no_query_and_keeps_no_clipboard() {
    // vt100 has no writer: a reader is a sink. Its text keeps only what a
    // terminal shows (the corpus test covers the rest).
    let mut r = Reader::new(4, 40);
    r.feed(b"\x1b[6n\x1b[c\x1bP$qm\x1b\\\x1b]52;c;?\x07\x1b]52;c;ZXZpbA==\x07shown");
    assert_eq!(lines_of(&mut r, None)[0], "shown");
}

#[test]
fn the_put_line_is_the_daemons_own_screen_put() {
    let r = Rendered {
        rows: 24,
        cols: 80,
        text: "$ cargo test\nok".into(),
        scrollback_lines: 0,
        truncated: false,
    };
    let line = put::line("c-a1", &r, 1795250000000);
    // The fixture's line (contracts/fixtures/project/exchange.jsonl, line 7).
    let want: serde_json::Value = serde_json::from_str(
        r#"{"op": "screen.put", "chat": "c-a1", "rows": 24, "cols": 80, "text": "$ cargo test\nok", "scrollbackLines": 0, "at": 1795250000000}"#,
    )
    .unwrap();
    assert_eq!(line, want);
    let parsed: derm_daemon::protocol::Request = serde_json::from_value(line).unwrap();
    assert!(matches!(
        parsed,
        derm_daemon::protocol::Request::ScreenPut(_)
    ));
}

#[test]
fn a_publisher_with_no_daemon_counts_failures_and_finishes() {
    let p = Publisher::start(
        std::env::temp_dir().join(format!("pd-none-{}/daemon.sock", std::process::id())),
        "0".repeat(64),
        "c-none".into(),
    );
    for n in 0..3 {
        p.offer(Rendered {
            rows: 1,
            cols: 1,
            text: n.to_string(),
            scrollback_lines: 0,
            truncated: false,
        });
    }
    let t = std::time::Instant::now();
    let s = p.finish(std::time::Duration::from_secs(10));
    assert!(t.elapsed() < std::time::Duration::from_secs(10));
    assert_eq!(s.sent, 0);
    assert!(s.failed >= 1, "{s:?}");
    assert!(s.failed + s.replaced >= 1);
    // The daemon's token is never in what the publisher reports.
    let why = s.last_error.unwrap_or_default();
    assert!(!why.contains(&"0".repeat(64)), "{why}");
}

#[cfg(unix)]
mod session_tests {
    use super::super::put::Publisher;
    use super::super::session::{self, open_pty, Terminal};
    use super::super::Reader;
    use crate::run::plan::Plan;
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    /// Signal handlers are the process's: one session at a time.
    static ONE: Mutex<()> = Mutex::new(());

    /// A pty of the test's own as the person's terminal: the test types on
    /// its master and reads what the person would see there.
    struct Person {
        master: OwnedFd,
        slave: OwnedFd,
        seen: Arc<Mutex<Vec<u8>>>,
    }

    fn winsize(rows: u16, cols: u16) -> libc::winsize {
        libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        }
    }

    impl Person {
        fn new() -> Person {
            let (master, slave) = open_pty().unwrap();
            // SAFETY: TIOCSWINSZ with a live winsize on our own pty.
            unsafe {
                libc::ioctl(slave.as_raw_fd(), libc::TIOCSWINSZ, &winsize(24, 80));
            }
            let seen = Arc::new(Mutex::new(Vec::new()));
            let theirs = seen.clone();
            let reading = master.try_clone().unwrap();
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    // SAFETY: read into a live buffer from our own descriptor.
                    let n = unsafe {
                        libc::read(reading.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len())
                    };
                    if n <= 0 {
                        if n < 0
                            && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
                        {
                            continue;
                        }
                        return;
                    }
                    theirs.lock().unwrap().extend_from_slice(&buf[..n as usize]);
                }
            });
            Person {
                master,
                slave,
                seen,
            }
        }

        fn terminal(&self) -> Terminal {
            Terminal {
                input: self.slave.as_raw_fd(),
                output: self.slave.as_raw_fd(),
            }
        }

        fn typed(&self, keys: &[u8]) {
            // SAFETY: write from a live buffer to our own descriptor.
            let n =
                unsafe { libc::write(self.master.as_raw_fd(), keys.as_ptr().cast(), keys.len()) };
            assert_eq!(n as usize, keys.len());
        }

        fn seen(&self) -> String {
            String::from_utf8_lossy(&self.seen.lock().unwrap()).into_owned()
        }

        fn wait_for(&self, needle: &str) {
            let t = Instant::now();
            while !self.seen().contains(needle) {
                assert!(
                    t.elapsed() < Duration::from_secs(10),
                    "{needle:?} not seen in {:?}",
                    self.seen()
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        fn termios(&self) -> libc::termios {
            // SAFETY: tcgetattr into a zeroed termios on our own pty.
            unsafe {
                let mut t: libc::termios = std::mem::zeroed();
                assert_eq!(libc::tcgetattr(self.slave.as_raw_fd(), &mut t), 0);
                t
            }
        }
    }

    fn sh(script: &str) -> Plan {
        Plan {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            ..Plan::default()
        }
    }

    fn cwd() -> String {
        std::env::temp_dir().display().to_string()
    }

    /// Starts `script` under a session on `p` and waits for it on another
    /// thread.
    fn run(
        p: &Person,
        script: &str,
        publisher: Option<Publisher>,
    ) -> std::thread::JoinHandle<(
        std::process::ExitStatus,
        session::Session,
        Option<Publisher>,
    )> {
        let mut s = session::spawn(&sh(script), &cwd(), p.terminal()).unwrap();
        std::thread::spawn(move || {
            let st = s.wait(publisher.as_ref()).unwrap();
            (st, s, publisher)
        })
    }

    fn kill_self(sig: libc::c_int) {
        // SAFETY: a process-directed signal to this test process; the
        // session's handler is installed and catches it.
        unsafe {
            libc::kill(libc::getpid(), sig);
        }
    }

    #[test]
    fn output_reaches_the_person_unchanged_and_the_reader_renders_it() {
        let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
        let p = Person::new();
        let (st, mut s, _) = run(&p, r"printf 'a\033[31mb\033[0m\n'", None)
            .join()
            .unwrap();
        assert!(st.success());
        p.wait_for("\r\n");
        // ONLCR on the harness's own pty (the person's settings, copied)
        // made the \r; the person's side, raw, passed it as it came.
        assert!(p.seen().contains("a\x1b[31mb\x1b[0m\r\n"), "{:?}", p.seen());
        assert_eq!(s.reader().text(None).text.split('\n').next(), Some("ab"));
    }

    #[test]
    fn the_harness_has_its_own_terminal_and_the_persons_is_raw_then_given_back() {
        let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
        let p = Person::new();
        let before = p.termios();
        let h = run(
            &p,
            "test -t 0 && test -t 1 && echo TTY; echo hi > /dev/tty && echo CTTY; \
             stty raw -echo; stty -a | grep -q -- -icanon && echo RAWOK; echo ready; sleep 1",
            None,
        );
        p.wait_for("ready");
        let during = p.termios();
        assert_eq!(during.c_lflag & (libc::ICANON | libc::ECHO | libc::ISIG), 0);
        assert_eq!(during.c_oflag & libc::OPOST, 0);
        let (st, _, _) = h.join().unwrap();
        assert!(st.success());
        let seen = p.seen();
        for want in ["TTY", "CTTY", "RAWOK"] {
            assert!(seen.contains(want), "{want} not in {seen:?}");
        }
        let after = p.termios();
        // PENDIN is the kernel's state, not a setting: XNU sets it whenever
        // a tcsetattr turns ICANON back on ("retype pending input",
        // `bsd/sys/termios.h:259`; `bsd/kern/tty.c:1358-1361` and `1391`,
        // apple-oss-distributions/xnu `main`), as derm's restore does; CI's
        // macOS job showed 0x20000000 there and nothing else changed.
        let settings =
            |t: &libc::termios| (t.c_iflag, t.c_oflag, t.c_lflag & !libc::PENDIN, t.c_cflag);
        assert_eq!(settings(&after), settings(&before));
    }

    const COUNT_INTS: &str = "n=0; trap 'n=$((n+1)); echo GOT$n' INT; echo ready; i=0; \
         while [ $i -lt 30 ]; do sleep 0.05; i=$((i+1)); done; echo done$n";

    #[test]
    fn a_typed_ctrl_c_reaches_the_harness_once() {
        let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
        let p = Person::new();
        let h = run(&p, COUNT_INTS, None);
        p.wait_for("ready");
        p.typed(b"\x03");
        let (st, _, _) = h.join().unwrap();
        assert!(st.success());
        let seen = p.seen();
        assert!(seen.contains("done1"), "{seen:?}");
        assert!(!seen.contains("GOT2"), "{seen:?}");
    }

    #[test]
    fn sigint_sigterm_and_sighup_sent_to_derm_reach_the_harness() {
        let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
        let p = Person::new();
        let h = run(&p, COUNT_INTS, None);
        p.wait_for("ready");
        kill_self(libc::SIGINT);
        let (st, _, _) = h.join().unwrap();
        assert!(st.success());
        assert!(p.seen().contains("done1"), "{:?}", p.seen());

        let p = Person::new();
        let h = run(
            &p,
            "trap 'echo TERMED; exit 7' TERM; echo ready; while :; do sleep 0.05; done",
            None,
        );
        p.wait_for("ready");
        kill_self(libc::SIGTERM);
        let (st, _, _) = h.join().unwrap();
        assert_eq!(st.code(), Some(7));
        assert!(p.seen().contains("TERMED"), "{:?}", p.seen());

        let p = Person::new();
        let h = run(
            &p,
            "trap 'echo HUNG; exit 8' HUP; echo ready; while :; do sleep 0.05; done",
            None,
        );
        p.wait_for("ready");
        kill_self(libc::SIGHUP);
        let (st, _, _) = h.join().unwrap();
        assert_eq!(st.code(), Some(8));
        assert!(p.seen().contains("HUNG"), "{:?}", p.seen());
    }

    #[test]
    fn a_resize_reaches_the_harness_and_the_reader() {
        let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
        let p = Person::new();
        let h = run(
            &p,
            "stty size; echo ready; read x; stty size; echo end",
            None,
        );
        p.wait_for("ready");
        assert!(p.seen().contains("24 80"), "{:?}", p.seen());
        // SAFETY: TIOCSWINSZ with a live winsize on our own pty.
        unsafe {
            libc::ioctl(p.slave.as_raw_fd(), libc::TIOCSWINSZ, &winsize(40, 100));
        }
        kill_self(libc::SIGWINCH);
        std::thread::sleep(Duration::from_millis(300));
        p.typed(b"\r");
        let (st, mut s, _) = h.join().unwrap();
        assert!(st.success());
        assert!(p.seen().contains("40 100"), "{:?}", p.seen());
        assert_eq!(s.reader().size(), (40, 100));
    }

    #[test]
    fn nothing_from_derm_reaches_the_harness_input() {
        // P-C5: the harness asks its terminal four questions; the person's
        // terminal here (the test) never answers, so anything the harness
        // reads would have come from derm.
        let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
        let p = Person::new();
        let (st, mut s, _) = run(
            &p,
            r"printf '\033[6n\033[c\033P$qm\033\\\033]52;c;?\007'; sleep 0.3; \
              stty -icanon -echo min 0 time 5; printf X; od -An -c | tr -d ' \n'; echo YEND",
            None,
        )
        .join()
        .unwrap();
        assert!(st.success());
        let t = s.reader().text(None).text;
        assert!(t.contains("XYEND"), "{t:?}");
    }

    #[test]
    fn exit_codes_and_signals_pass_through() {
        let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
        use std::os::unix::process::ExitStatusExt;
        let p = Person::new();
        let (st, _, _) = run(&p, "exit 5", None).join().unwrap();
        assert_eq!(st.code(), Some(5));
        let (st, _, _) = run(&p, "kill -9 $$", None).join().unwrap();
        assert_eq!(st.signal(), Some(9));
    }

    #[test]
    fn a_process_left_holding_the_pty_does_not_hold_derm() {
        let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
        let p = Person::new();
        let t = Instant::now();
        let (st, _, _) = run(&p, "(sleep 5; echo late) & echo bye", None)
            .join()
            .unwrap();
        assert!(st.success());
        assert!(
            t.elapsed() < session::DRAIN_MAX + Duration::from_secs(2),
            "{:?}",
            t.elapsed()
        );
        p.wait_for("bye");
    }

    #[test]
    fn a_harness_that_cannot_start_leaves_the_terminal_and_handlers_as_they_were() {
        let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
        let p = Person::new();
        let before = p.termios();
        let plan = Plan {
            program: "/nonexistent/derm-pd-harness".into(),
            ..Plan::default()
        };
        assert!(session::spawn(&plan, &cwd(), p.terminal()).is_err());
        let after = p.termios();
        assert_eq!(after.c_lflag, before.c_lflag);
        // SAFETY: sigaction read-only query into a zeroed struct.
        let cur = unsafe {
            let mut cur: libc::sigaction = std::mem::zeroed();
            libc::sigaction(libc::SIGWINCH, std::ptr::null(), &mut cur);
            cur
        };
        assert_eq!(cur.sa_sigaction, libc::SIG_DFL);
    }

    #[test]
    fn usable_refuses_pipes() {
        assert!(session::usable(true).is_err());
    }

    /// Case 112: `screen.put` against lane B's real daemon, started in this
    /// test process on a temporary socket, as `watch/live_tests.rs` does.
    /// Until lane PE builds the screens the daemon answers `not built`; the
    /// line still had to parse as the daemon's own op to get that far.
    #[test]
    fn screens_reach_the_real_daemon_with_its_token() {
        use std::os::unix::fs::PermissionsExt;
        let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
        const TOKEN: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let root = std::env::temp_dir().join(format!(
            "pd-{}-{}",
            std::process::id(),
            &derm_core::token::mint().unwrap()[..8]
        ));
        std::fs::create_dir_all(&root).unwrap();
        let data = root.join("data");
        let log: &'static derm_daemon::activity::store::ActivityLog = Box::leak(Box::new(
            derm_daemon::activity::store::ActivityLog::start(data.join("activity")),
        ));
        let daemon = derm_daemon::daemon::Daemon::new(TOKEN, log, &data, false).unwrap();
        let socket = root.join("run/derm/daemon.sock");
        let listener = derm_daemon::socket::bind(&socket).unwrap();
        let tok = socket.parent().unwrap().join("daemon.token");
        std::fs::write(&tok, format!("{TOKEN}\n")).unwrap();
        std::fs::set_permissions(&tok, std::fs::Permissions::from_mode(0o600)).unwrap();
        let serving = daemon.clone();
        std::thread::spawn(move || derm_daemon::socket::serve(listener, serving));

        let p = Person::new();
        let publisher = Publisher::start(socket.clone(), TOKEN.into(), "c-pd1".into());
        let (st, _, publisher) = run(&p, "echo hello pd", Some(publisher)).join().unwrap();
        assert!(st.success());
        let stats = publisher.unwrap().finish(Duration::from_secs(10));
        assert_eq!(stats.failed, 0, "{stats:?}");
        assert!(stats.sent + stats.refused >= 1, "{stats:?}");
        if stats.refused > 0 {
            let why = stats.last_error.clone().unwrap_or_default();
            assert!(why.contains("not built"), "{stats:?}");
        }
        drop(daemon);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// End to end with real full-screen programs (rules 9.13): vim on the
    /// alternate screen, and Claude Code's TUI with a scratch HOME and a
    /// fake key (its first screen; nothing reaches Anthropic, the proxy
    /// refuses). Needs `vim` and `claude` on PATH, so run by hand:
    /// `cargo test -p derm-cli --bin derm -- --ignored pd_e2e`.
    #[test]
    #[ignore = "needs vim and Claude Code on PATH; run by hand"]
    fn pd_e2e_vim_and_claude_codes_tui_render_with_no_control_bytes() {
        let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("pd-e2e-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("note.txt"),
            "first line of the note\nsecond line\n",
        )
        .unwrap();
        let p = Person::new();
        let plan = Plan {
            program: "vim".into(),
            env_set: vec![("TERM".into(), "xterm-256color".into())],
            args: ["-u", "NONE", "-N", "-n", "note.txt"]
                .map(String::from)
                .to_vec(),
            ..Plan::default()
        };
        let mut s = session::spawn(&plan, &dir.display().to_string(), p.terminal()).unwrap();
        let h = std::thread::spawn(move || {
            let st = s.wait(None).unwrap();
            (st, s)
        });
        std::thread::sleep(Duration::from_millis(1500));
        // What the person sees now, through a reader fed the same bytes.
        let mid = {
            let mut r = Reader::new(24, 80);
            r.feed(&p.seen.lock().unwrap());
            r.text(None).text
        };
        assert!(mid.contains("first line of the note"), "{mid:?}");
        assert!(
            !mid.chars().any(derm_core::project::screen::removes),
            "{mid:?}"
        );
        p.typed(b"\x1b:q!\r");
        let (st, mut s) = h.join().unwrap();
        assert!(st.success());
        assert!(
            p.seen().contains("\x1b[?1049h"),
            "vim used the alternate screen"
        );
        let t = s.reader().text(Some(50)).text;
        assert!(!t.chars().any(derm_core::project::screen::removes), "{t:?}");

        let home = dir.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let p = Person::new();
        let plan = Plan {
            program: "claude".into(),
            args: vec![],
            env_set: vec![
                ("HOME".into(), home.display().to_string()),
                (
                    "ANTHROPIC_API_KEY".into(),
                    "sk-ant-api03-FAKE-pd-e2e".into(),
                ),
                ("DISABLE_AUTOUPDATER".into(), "1".into()),
                ("TERM".into(), "xterm-256color".into()),
            ],
            env_remove: [
                "ANTHROPIC_AUTH_TOKEN",
                "CLAUDE_CODE_OAUTH_TOKEN",
                "ANTHROPIC_BASE_URL",
            ]
            .map(String::from)
            .to_vec(),
            ..Plan::default()
        };
        let mut s = session::spawn(&plan, &dir.display().to_string(), p.terminal()).unwrap();
        let h = std::thread::spawn(move || {
            let st = s.wait(None).unwrap();
            (st, s)
        });
        std::thread::sleep(Duration::from_secs(8));
        let shown = {
            let mut r = Reader::new(24, 80);
            r.feed(&p.seen.lock().unwrap());
            r.render().text
        };
        assert!(
            !shown.chars().any(derm_core::project::screen::removes),
            "{shown:?}"
        );
        for _ in 0..3 {
            p.typed(b"\x03");
            std::thread::sleep(Duration::from_millis(400));
        }
        let (_, mut s) = h.join().unwrap();
        let t = s.reader().render().text;
        eprintln!("PD-E2E claude, while it ran:\n{shown}\nPD-E2E claude, at the end:\n{t}");
        assert!(!t.chars().any(derm_core::project::screen::removes), "{t:?}");
        assert!(t.chars().any(char::is_alphanumeric), "{t:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
