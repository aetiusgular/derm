//! `daemon.test.ts`'s and `owner.test.ts`'s gate cases (the hook core at
//! `e29ce27`), ported with the client: which token a gate presents, which
//! paths it takes from its environment, a decision's id (BW2), and the VM
//! route (P4-R2, W5C-S2, W5R-7).

use super::*;

#[cfg(unix)]
mod unix {
    use super::*;
    use crate::gate::fake_daemon::{Approve, FakeDaemon, CHAT_TOKEN, DAEMON_TOKEN};
    use std::os::unix::fs::{symlink, PermissionsExt};

    struct Tree {
        root: PathBuf,
        safe: PathBuf,
        project: PathBuf,
        token_file: PathBuf,
        // Every test with a tree holds the owners lock for its whole run:
        // `trusted_owners` is process-wide, and two tests here set it, so a
        // test that reads a token or a policy while they ran saw another
        // user's owners (the wave 6 base, finding W6B-1: 5 of 40 runs of
        // this module failed at 8 threads on `main` at 4dbb2fa).
        _owners: std::sync::MutexGuard<'static, ()>,
    }
    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
    fn mode(p: &Path, m: u32) {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    }
    fn tree() -> Tree {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "derm-tok-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let safe = root.join("safe");
        let project = root.join("project");
        std::fs::create_dir_all(&safe).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        for p in [&root, &safe, &project] {
            mode(p, 0o700);
        }
        let token_file = safe.join("token");
        std::fs::write(&token_file, format!("{}\n", "a".repeat(64))).unwrap();
        mode(&token_file, 0o600);
        Tree {
            root,
            safe,
            project,
            token_file,
            _owners: lock(),
        }
    }
    fn opts<'a>(env: &'a Env, cwd: &'a Path) -> Opts<'a> {
        Opts {
            env,
            client: "t".into(),
            reply_timeout: Duration::from_millis(500),
            cwd,
        }
    }
    fn lock() -> std::sync::MutexGuard<'static, ()> {
        derm_core::owner::TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }
    fn me() -> u32 {
        derm_core::runtime::current_uid()
    }

    #[test]
    fn never_falls_back_to_daemon_token_beside_the_socket() {
        let t = tree();
        let d = FakeDaemon::start(Approve::Yes, None);
        let env = Env::of(&[("DERM_DAEMON_SOCKET", &d.socket.display().to_string())]);
        assert_eq!(chat_token(&env, &t.project), None);
        let r = exchange(
            &[json!({"op": "event", "event": {"id": "x"}})],
            &opts(&env, &t.project),
        );
        assert!(r.unwrap_err().contains("no chat token"));
        assert!(d.lines().is_empty());
    }

    #[test]
    fn takes_derm_chat_token_first_and_reads_a_private_file() {
        let t = tree();
        let file = t.token_file.display().to_string();
        let b = "b".repeat(64);
        assert_eq!(
            chat_token(
                &Env::of(&[("DERM_CHAT_TOKEN", &b), ("DERM_CHAT_TOKEN_FILE", &file)]),
                &t.project
            ),
            Some(b)
        );
        assert_eq!(
            chat_token(&Env::of(&[("DERM_CHAT_TOKEN_FILE", &file)]), &t.project),
            Some("a".repeat(64))
        );
    }

    #[test]
    fn refuses_a_token_file_that_is_relative_loose_a_link_malformed_or_in_the_project() {
        let t = tree();
        let loose = t.safe.join("loose");
        std::fs::write(&loose, "a".repeat(64)).unwrap();
        mode(&loose, 0o644);
        let link = t.safe.join("link");
        symlink(&t.token_file, &link).unwrap();
        let bad = t.safe.join("bad");
        std::fs::write(&bad, "not-a-token").unwrap();
        mode(&bad, 0o600);
        let planted = t.project.join("token");
        std::fs::write(&planted, "a".repeat(64)).unwrap();
        mode(&planted, 0o600);
        for f in [PathBuf::from("token"), loose, link, bad, planted] {
            let env = Env::of(&[("DERM_CHAT_TOKEN_FILE", &f.display().to_string())]);
            assert_eq!(chat_token(&env, &t.project), None, "{}", f.display());
        }
    }

    #[test]
    fn a_daemon_scope_token_is_never_presented() {
        let t = tree();
        let d = FakeDaemon::start(Approve::Yes, None);
        let sock = d.socket.display().to_string();
        let env = Env::of(&[
            ("DERM_DAEMON_SOCKET", &sock),
            (
                "DERM_CHAT_TOKEN_FILE",
                &d.dir.join("daemon.token").display().to_string(),
            ),
        ]);
        assert_eq!(chat_token(&env, &t.project), None);
        let r = exchange(
            &[json!({"op": "event", "event": {"id": "x"}})],
            &opts(&env, &t.project),
        );
        assert!(r.unwrap_err().contains("no chat token"));
        assert!(d.lines().is_empty());
        let copy = t.safe.join("copied-token");
        std::fs::write(&copy, format!("{DAEMON_TOKEN}\n")).unwrap();
        mode(&copy, 0o600);
        let env = Env::of(&[
            ("DERM_DAEMON_SOCKET", &sock),
            ("DERM_CHAT_TOKEN_FILE", &copy.display().to_string()),
        ]);
        let r = exchange(
            &[json!({"op": "approve", "request": {"id": "ap-1"}})],
            &opts(&env, &t.project),
        );
        assert!(r.unwrap_err().contains("daemon scope"));
        assert!(d.lines().iter().all(|(_, l)| l["op"] == "hello"));
        let env = Env::of(&[
            ("DERM_DAEMON_SOCKET", &sock),
            ("DERM_CHAT_TOKEN", DAEMON_TOKEN),
        ]);
        let r = exchange(
            &[json!({"op": "approve", "request": {"id": "ap-2"}})],
            &opts(&env, &t.project),
        );
        assert!(r.unwrap_err().contains("daemon scope"));
    }

    #[test]
    fn inside_folder_follows_links_and_handles_missing_files() {
        let t = tree();
        assert!(inside_folder(
            &t.project.join("a").join("b.json"),
            &t.project
        ));
        assert!(!inside_folder(&t.safe.join("p.json"), &t.project));
        assert!(inside_folder(&t.project, &t.project));
        let via = t.root.join("via-link");
        symlink(&t.project, &via).unwrap();
        assert!(inside_folder(&via.join("p.json"), &t.project));
        assert!(!inside_folder(
            &t.project.join("..").join("safe").join("p.json"),
            &t.project
        ));
    }

    #[test]
    fn refuses_a_daemon_socket_inside_the_project_or_relative() {
        let t = tree();
        let env = Env::of(&[
            (
                "DERM_DAEMON_SOCKET",
                &t.project.join("daemon.sock").display().to_string(),
            ),
            ("DERM_CHAT_TOKEN", CHAT_TOKEN),
        ]);
        let r = exchange(
            &[json!({"op": "event", "event": {"id": "x"}})],
            &opts(&env, &t.project),
        );
        assert!(r.unwrap_err().contains("inside the session folder"));
        if cfg!(target_os = "macos") {
            return;
        }
        for runtime in [
            t.project.join("run").display().to_string(),
            "relative/run".to_string(),
        ] {
            let env = Env::of(&[
                ("XDG_RUNTIME_DIR", &runtime),
                ("DERM_CHAT_TOKEN", CHAT_TOKEN),
            ]);
            let e = exchange(
                &[json!({"op": "event", "event": {"id": "x"}})],
                &opts(&env, &t.project),
            )
            .unwrap_err();
            assert!(
                e.contains("inside the session folder") || e.contains("not an absolute path"),
                "{runtime}: {e}"
            );
        }
    }

    #[test]
    fn a_chat_token_reaches_the_daemon_and_an_event_is_posted() {
        let t = tree();
        let d = FakeDaemon::start(Approve::None, None);
        let env = Env(d.env(true).into_iter().collect());
        let e = AdapterEvent {
            id: "e1".into(),
            chat_id: "c".into(),
            harness: "codex".into(),
            kind: "approval".into(),
            summary: "x".repeat(300),
            detail: serde_json::Map::new(),
        };
        assert!(post_event(&e, &env, &t.project));
        let ev = d.events();
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0]["source"], "adapter");
        assert_eq!(ev[0]["detail"]["trust"], "client");
        assert_eq!(ev[0]["summary"].as_str().unwrap().len(), 200);
    }

    #[test]
    fn approve_takes_only_an_approvers_yes() {
        let t = tree();
        let d = FakeDaemon::start(Approve::Yes, None);
        let env = Env(d.env(true).into_iter().collect());
        let r = ApproveRequest {
            id: "ap".into(),
            chat: "c".into(),
            harness: "codex".into(),
            tool: "bash".into(),
            summary: "bash: ls".into(),
            timeout_seconds: 1,
        };
        assert_eq!(
            approve(&r, &env, &t.project),
            ApproveOutcome::Answer {
                yes: true,
                by: By::Approver
            }
        );
        d.set_approve(Approve::None);
        assert_eq!(
            approve(&r, &env, &t.project),
            ApproveOutcome::Answer {
                yes: false,
                by: By::None
            }
        );
        d.set_approve(Approve::Timeout);
        assert_eq!(
            approve(&r, &env, &t.project),
            ApproveOutcome::Answer {
                yes: false,
                by: By::Timeout
            }
        );
        d.set_approve(Approve::Refuse);
        assert!(
            matches!(approve(&r, &env, &t.project), ApproveOutcome::Unreachable(w) if w.contains("refused"))
        );
        d.set_approve(Approve::Hang);
        let t0 = std::time::Instant::now();
        assert!(
            matches!(approve(&r, &env, &t.project), ApproveOutcome::Unreachable(w) if w.contains("timed out"))
        );
        assert!(t0.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn under_an_agents_user_the_persons_files_are_trusted_and_the_agents_are_not() {
        let t = tree();
        mode(&t.root, 0o711);
        let token = t.root.join("chat.token");
        std::fs::write(&token, format!("{}\n", "a".repeat(64))).unwrap();
        mode(&token, 0o644);
        let sock_dir = t.root.join("sock");
        std::fs::create_dir(&sock_dir).unwrap();
        mode(&sock_dir, 0o755);
        let sock = sock_dir.join("daemon.sock");
        let _server = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let env = Env::of(&[("DERM_CHAT_TOKEN_FILE", &token.display().to_string())]);
        let elsewhere = t.safe.clone();
        let o = |uids: Vec<u32>, agent: bool, problem: Option<&str>| {
            derm_core::owner::set_owners_for_test(Some(derm_core::owner::Owners {
                uids,
                agent,
                problem: problem.map(str::to_string),
            }))
        };
        o(vec![me()], true, None);
        assert_eq!(socket_looks_owned(&sock), None);
        assert_eq!(chat_token(&env, &elsewhere), Some("a".repeat(64)));
        o(vec![me() + 1], true, None);
        assert_eq!(
            socket_looks_owned(&sock).as_deref(),
            Some("socket owned by another user")
        );
        assert_eq!(chat_token(&env, &elsewhere), None);
        o(vec![me()], false, None);
        assert_eq!(
            chat_token(&env, &elsewhere),
            None,
            "0644 is too loose for the person's own token"
        );
        derm_core::owner::set_owners_for_test(None);
    }

    #[test]
    fn a_policy_owned_by_the_agent_is_refused_and_the_persons_is_read() {
        let t = tree();
        let policy = t.safe.join("policy.json");
        std::fs::write(&policy, r#"{"version":1,"rules":[]}"#).unwrap();
        mode(&policy, 0o644);
        let env = Env::of(&[("DERM_POLICY", &policy.display().to_string())]);
        let set = |uids: Vec<u32>| {
            derm_core::owner::set_owners_for_test(Some(derm_core::owner::Owners {
                uids,
                agent: true,
                problem: None,
            }))
        };
        set(vec![me()]);
        assert_eq!(crate::gate::policy::load_for_hook(&env, &t.project).1, None);
        set(vec![me() + 1]);
        assert!(crate::gate::policy::load_for_hook(&env, &t.project)
            .1
            .is_some());
        set(vec![]);
        assert!(crate::gate::policy::load_for_hook(&env, &t.project)
            .1
            .is_some());
        derm_core::owner::set_owners_for_test(None);
        // Inside the project: refused whoever owns it.
        let inside = t.project.join(".derm-policy.json");
        std::fs::write(&inside, r#"{"version":1,"rules":[]}"#).unwrap();
        mode(&inside, 0o600);
        let env = Env::of(&[("DERM_POLICY", &inside.display().to_string())]);
        assert!(crate::gate::policy::load_for_hook(&env, &t.project)
            .1
            .unwrap()
            .contains("inside the chat's folder"));
        let env = Env::of(&[("DERM_POLICY", "relative.json")]);
        assert!(crate::gate::policy::load_for_hook(&env, &t.project)
            .1
            .unwrap()
            .contains("not an absolute path"));
    }

    fn vm_env(absent: &Path, extra: &[(&str, &str)]) -> Env {
        let mut e = Env::of(&[
            ("DERM_BOUNDARY", "sbx"),
            ("DERM_OTLP_ENDPOINT", "http://host.docker.internal:4318"),
            ("DERM_DAEMON_SOCKET", &absent.display().to_string()),
        ]);
        for (k, v) in extra {
            e = e.with(k, v);
        }
        e
    }

    #[test]
    fn the_vm_route_is_taken_only_for_sbx_a_plain_url_and_no_socket() {
        let t = tree();
        let absent = t.root.join("no-such-folder").join("daemon.sock");
        let marked = || None;
        let only = || vec![absent.clone()];
        assert_eq!(
            vm_endpoint(&vm_env(&absent, &[]), &marked, Some(1000), &only).map(|u| u.port),
            Some(4318)
        );
        let token = t.token_file.display().to_string();
        for extra in [
            ("DERM_BOUNDARY", "srt"),
            ("DERM_BOUNDARY", ""),
            ("DERM_OTLP_ENDPOINT", "http://127.0.0.1:4318"),
            ("DERM_OTLP_ENDPOINT", "https://host.docker.internal:4318"),
            (
                "DERM_OTLP_ENDPOINT",
                "http://host.docker.internal.evil.example:4318",
            ),
            ("DERM_OTLP_ENDPOINT", "http://host.docker.internal"),
            ("DERM_OTLP_ENDPOINT", "http://u:p@host.docker.internal:4318"),
            (
                "DERM_OTLP_ENDPOINT",
                "http://host.docker.internal:4318/v1/logs",
            ),
            (
                "DERM_OTLP_ENDPOINT",
                "http://host.docker.internal:4318/?x=1",
            ),
            ("DERM_OTLP_ENDPOINT", "not a url"),
            ("DERM_DAEMON_SOCKET", token.as_str()),
        ] {
            let env = vm_env(&absent, &[extra]);
            let cands = || {
                socket_candidates(&env)
                    .into_iter()
                    .filter(|p| p != &absent)
                    .chain([PathBuf::from(env.raw("DERM_DAEMON_SOCKET").unwrap())])
                    .collect()
            };
            assert_eq!(
                vm_endpoint(&env, &marked, Some(1000), &cands),
                None,
                "{extra:?}"
            );
        }
        // Never on the variables alone, and never as root.
        assert_eq!(
            vm_endpoint(
                &vm_env(&absent, &[]),
                &|| Some("no VM marker".into()),
                Some(1000),
                &only
            ),
            None
        );
        assert_eq!(
            vm_endpoint(&vm_env(&absent, &[]), &marked, Some(0), &only),
            None
        );
        assert_eq!(VM_MARKER, "/opt/derm-kit/sbx-vm");
        assert!(vm_marker(Path::new(VM_MARKER), true, &lstat).is_some());
    }

    #[test]
    fn the_marker_holds_only_for_a_plain_file_and_folder_that_are_roots_alone_on_linux() {
        let mk = |f: (u32, u32, u64, bool, bool), d: (u32, u32, bool)| {
            move |p: &Path| -> Option<MarkerStat> {
                Some(if p == Path::new("/k/sbx-vm") {
                    MarkerStat {
                        uid: f.0,
                        mode: f.1,
                        nlink: f.2,
                        file: f.3,
                        dir: f.4,
                    }
                } else {
                    MarkerStat {
                        uid: d.0,
                        mode: d.1,
                        nlink: 1,
                        file: false,
                        dir: d.2,
                    }
                })
            }
        };
        let good_f = (0, 0o100644, 1, true, false);
        let good_d = (0, 0o40755, true);
        assert_eq!(
            vm_marker(Path::new("/k/sbx-vm"), true, &mk(good_f, good_d)),
            None
        );
        for (f, d) in [
            ((1000, 0o100644, 1, true, false), good_d),
            ((0, 0o100664, 1, true, false), good_d),
            ((0, 0o100646, 1, true, false), good_d),
            ((0, 0o100644, 2, true, false), good_d),
            ((0, 0o100644, 1, false, false), good_d),
            (good_f, (1000, 0o40755, true)),
            (good_f, (0, 0o40775, true)),
            (good_f, (0, 0o40755, false)),
        ] {
            assert!(
                vm_marker(Path::new("/k/sbx-vm"), true, &mk(f, d)).is_some(),
                "{f:?} {d:?}"
            );
        }
        assert!(vm_marker(Path::new("/k/sbx-vm"), false, &mk(good_f, good_d)).is_some());
        let t = tree();
        assert!(vm_marker(&t.safe.join("none").join("sbx-vm"), true, &lstat)
            .unwrap()
            .contains("no VM marker"));
    }

    #[test]
    fn a_socket_where_the_default_would_be_ends_the_vm_route() {
        let t = tree();
        let absent = t.root.join("no-such-folder").join("daemon.sock");
        let runtime = t.root.join("runtime");
        let home = t.root.join("home");
        let env = vm_env(
            &absent,
            &[
                ("XDG_RUNTIME_DIR", &runtime.display().to_string()),
                ("HOME", &home.display().to_string()),
            ],
        );
        // Where this OS's default socket is for that environment (macOS:
        // under HOME's Library; elsewhere: under XDG_RUNTIME_DIR).
        let default = socket_path(&env.with("DERM_DAEMON_SOCKET", ""));
        std::fs::create_dir_all(default.parent().unwrap()).unwrap();
        std::fs::write(&default, "").unwrap();
        assert_eq!(
            vm_endpoint(&env, &|| None, Some(1000), &|| socket_candidates(&env)),
            None
        );
        assert!(socket_candidates(&Env::default())
            .iter()
            .any(|p| p.ends_with(".derm/run/derm/daemon.sock")
                || p.ends_with("Library/Application Support/derm/daemon.sock")));
    }

    #[test]
    fn a_project_on_the_host_that_sets_the_variables_never_reaches_its_own_listener() {
        let t = tree();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let absent = t.root.join("no-such-folder").join("daemon.sock");
        let env = vm_env(
            &absent,
            &[
                (
                    "DERM_OTLP_ENDPOINT",
                    &format!("http://host.docker.internal:{port}"),
                ),
                ("DERM_CHAT_TOKEN_FILE", &t.token_file.display().to_string()),
            ],
        );
        let r = exchange(
            &[json!({"op": "approve", "request": {"id": "ap"}})],
            &opts(&env, &t.project),
        );
        assert_eq!(r.unwrap_err(), "no daemon socket");
        assert!(listener.accept().is_err(), "the listener was never asked");
    }

    /// A one-shot HTTP server for two requests. Its thread drops the
    /// listener when it ends; a test that then needs "nothing listening"
    /// joins it first (the wave 6 base, finding W6B-2: a third connection
    /// made before the thread ended sat in the listener's backlog and got
    /// "daemon reply failed", 4 of 40 runs on `main` at 4dbb2fa).
    fn http_server(
        status: u16,
    ) -> (
        u16,
        std::sync::mpsc::Receiver<(String, String, String)>,
        std::thread::JoinHandle<()>,
    ) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            for s in listener.incoming().take(2) {
                let Ok(mut s) = s else { return };
                // Read the head, then the body by its Content-Length.
                let mut got = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let n = std::io::Read::read(&mut s, &mut chunk).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    got.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&got);
                    if let Some((head, body)) = text.split_once("\r\n\r\n") {
                        let len: usize = head
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length: ")
                                    .map(|v| v.trim().parse().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        if body.len() >= len {
                            break;
                        }
                    }
                }
                let req = String::from_utf8_lossy(&got).to_string();
                let path = req.split_whitespace().nth(1).unwrap_or("").to_string();
                let token = req
                    .lines()
                    .find_map(|l| l.strip_prefix("x-derm-token: "))
                    .unwrap_or("")
                    .to_string();
                let body = req.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
                let reply = if path == "/derm/v1/approve" {
                    r#"{"ok":true,"id":"ap","answer":"yes","by":"approver"}"#
                } else {
                    r#"{"ok":true,"id":"e1"}"#
                };
                let _ = s.write_all(
                    format!("HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}", reply.len()).as_bytes(),
                );
                let _ = tx.send((path, token, body));
            }
        });
        (port, rx, server)
    }

    #[test]
    fn post_vm_sends_each_op_to_its_route_with_the_chat_token() {
        let (port, rx, server) = http_server(200);
        let url = VmUrl {
            host: "127.0.0.1".into(),
            port,
        };
        let chat = "a".repeat(64);
        assert_eq!(
            post_vm(
                &url,
                &chat,
                &json!({"op": "event", "event": {"id": "e1"}}),
                Duration::from_secs(1)
            )
            .unwrap(),
            json!({"ok": true, "id": "e1"})
        );
        let ap = post_vm(
            &url,
            &chat,
            &json!({"op": "approve", "request": {"id": "ap"}}),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(ap["answer"], "yes");
        let seen: Vec<_> = rx.iter().take(2).collect();
        assert_eq!(seen[0].0, "/derm/v1/event");
        assert_eq!(seen[0].1, chat);
        assert_eq!(
            serde_json::from_str::<Value>(&seen[0].2).unwrap(),
            json!({"event": {"id": "e1"}})
        );
        assert_eq!(seen[1].0, "/derm/v1/approve");
        assert_eq!(
            serde_json::from_str::<Value>(&seen[1].2).unwrap(),
            json!({"request": {"id": "ap"}})
        );
        assert_eq!(
            post_vm(&url, &chat, &json!({"op": "tail"}), Duration::from_secs(1)).unwrap_err(),
            "no route for tail from a VM"
        );
        // Nothing listening any more, once the server's thread has ended.
        server.join().unwrap();
        let dead = post_vm(
            &url,
            &chat,
            &json!({"op": "event", "event": {}}),
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(
            dead.contains("unreachable") || dead.contains("timed out"),
            "{dead}"
        );
    }

    #[test]
    fn a_status_other_than_200_is_not_a_reply() {
        let (port, _rx, _server) = http_server(401);
        let url = VmUrl {
            host: "127.0.0.1".into(),
            port,
        };
        assert_eq!(
            post_vm(
                &url,
                &"a".repeat(64),
                &json!({"op": "approve", "request": {}}),
                Duration::from_secs(1)
            )
            .unwrap_err(),
            "daemon answered HTTP 401"
        );
    }

    #[test]
    fn with_no_chat_token_the_vm_route_is_not_tried() {
        let t = tree();
        let absent = t.root.join("no-such-folder").join("daemon.sock");
        let r = exchange(
            &[json!({"op": "event", "event": {}})],
            &opts(&vm_env(&absent, &[]), &t.project),
        );
        assert_eq!(
            r.unwrap_err(),
            "no chat token (start the harness with derm run)"
        );
    }
}

#[test]
fn a_decision_id_cannot_be_known_from_the_call_id() {
    let a = decision_id("opencode", Some("call_17"));
    let b = decision_id("opencode", Some("call_17"));
    assert_ne!(a, b);
    for id in [&a, &b] {
        let nonce = id.strip_prefix("opencode-call_17-decision-").expect(id);
        assert_eq!(nonce.len(), 32);
        assert!(nonce
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
    }
}

#[test]
fn a_decision_id_names_an_unknown_call_and_stays_under_the_cap() {
    assert!(decision_id("claude-code", None).starts_with("claude-code-unknown-decision-"));
    let long = decision_id("claude-code", Some(&"x".repeat(400)));
    assert!(long.len() <= 128);
    assert!(long.contains("-decision-"));
    assert!(decision_id("hermes", Some("a\nb c/d")).starts_with("hermes-a_b_c_d-decision-"));
}
