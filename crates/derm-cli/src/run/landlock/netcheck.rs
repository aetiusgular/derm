//! The agent account's own network, checked as the account before every
//! chat (lane L2's request to L1, applied by integration): lane L2's table
//! (`packaging/linux/agent-user/accounts.py` `check_probe`) must still
//! refuse what it refused at install. The table can be flushed by hand, by
//! `nftables.service`'s reload (`flush ruleset` in Ubuntu's
//! `/etc/nftables.conf`, nftables 1.0.9-1ubuntu0.1, read by L2), or never
//! loaded after a boot; the static check cannot see that, and an
//! unrefused chat would reach the network directly.
//!
//! The four sends and the answers they must get are L2's, by run on Linux
//! 6.18 with nftables 1.0.9 (acct_L2, Research, V): with the table, a
//! datagram's `sendto` gets EPERM (the output hook's verdict) and a TCP
//! `connect` gets EHOSTUNREACH at once (`reject with icmpx
//! admin-prohibited`); loopback is let through. Anything else, a quick
//! ECONNREFUSED or ENETUNREACH from the network included, is not the
//! table's answer. TEST-NET-1 and 2001:db8::/32 (RFC 5737, RFC 3849) answer
//! nothing, so a send that is let through reaches no one.

use std::io::ErrorKind;
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

/// What one send got.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Got {
    /// It went through (a datagram sent, a connect made).
    Ok,
    /// The kernel's errno.
    Errno(i32),
    /// No answer before the timeout.
    Timeout,
    /// The socket family is not there (no IPv6 in this kernel).
    Unsupported,
}

/// One case: what was sent, what came back, and how long it took.
#[derive(Clone, Debug)]
pub(crate) struct Outcome {
    pub name: &'static str,
    pub got: Got,
    pub took: Duration,
}

/// The cases, as `accounts.py` `check_probe` names them.
pub(crate) const LOOPBACK: &str = "loopback";
pub(crate) const UDP: &str = "outbound UDP";
pub(crate) const TCP: &str = "outbound TCP";
pub(crate) const DNS: &str = "DNS on loopback";
pub(crate) const UDP6: &str = "outbound UDP over IPv6";

/// Why the table does not hold, or `Ok` when every case got the table's
/// answer. `v6_route`: whether this machine has a default IPv6 route off
/// `lo` (`/proc/net/ipv6_route`), so an ENETUNREACH there is no table's.
pub(crate) fn judge(out: &[Outcome], v6_route: bool) -> Result<(), String> {
    let quick = Duration::from_secs(1);
    for o in out {
        let refused = match o.name {
            LOOPBACK => {
                if o.got == Got::Ok {
                    continue;
                }
                return Err(format!(
                    "the account cannot reach 127.0.0.1 ({:?}): the table refuses loopback",
                    o.got
                ));
            }
            UDP | DNS => matches!(o.got, Got::Errno(libc::EPERM)),
            TCP => matches!(o.got, Got::Errno(libc::EHOSTUNREACH | libc::EPERM)),
            UDP6 => {
                let no_v6 = o.got == Got::Unsupported
                    || (!v6_route
                        && matches!(o.got, Got::Errno(libc::ENETUNREACH | libc::EADDRNOTAVAIL)));
                if no_v6 {
                    continue;
                }
                matches!(o.got, Got::Errno(libc::EPERM))
            }
            _ => false,
        };
        if !(refused && o.took < quick) {
            return Err(format!(
                "{} was not refused by the account's firewall table ({:?} after {:.1}s): \
                 the table is not loaded; sudo systemctl restart derm-agents-nft, then \
                 python3 -I /usr/local/lib/derm/agents.py check",
                o.name,
                o.got,
                o.took.as_secs_f64()
            ));
        }
    }
    Ok(())
}

fn errno(e: &std::io::Error) -> Got {
    match (e.raw_os_error(), e.kind()) {
        (Some(libc::EAFNOSUPPORT), _) => Got::Unsupported,
        (Some(n), _) => Got::Errno(n),
        (None, ErrorKind::TimedOut | ErrorKind::WouldBlock) => Got::Timeout,
        (None, _) => Got::Errno(-1),
    }
}

fn udp(bind: &str, to: SocketAddr) -> Got {
    match UdpSocket::bind(bind) {
        Err(e) => errno(&e),
        Ok(s) => match s.send_to(b"derm-probe", to) {
            Ok(_) => Got::Ok,
            Err(e) => errno(&e),
        },
    }
}

fn tcp(to: SocketAddr) -> Got {
    match TcpStream::connect_timeout(&to, Duration::from_secs(3)) {
        Ok(_) => Got::Ok,
        Err(e) if e.kind() == ErrorKind::TimedOut => Got::Timeout,
        Err(e) => errno(&e),
    }
}

fn timed(name: &'static str, f: impl FnOnce() -> Got) -> Outcome {
    let t = Instant::now();
    let got = f();
    Outcome {
        name,
        got,
        took: t.elapsed(),
    }
}

/// Loopback: a datagram to a socket of this process's own on 127.0.0.1
/// arrives.
fn loopback() -> Got {
    let Ok(rx) = UdpSocket::bind("127.0.0.1:0") else {
        return Got::Errno(-1);
    };
    let _ = rx.set_read_timeout(Some(Duration::from_secs(2)));
    let Ok(at) = rx.local_addr() else {
        return Got::Errno(-1);
    };
    match udp("127.0.0.1:0", at) {
        Got::Ok => {}
        other => return other,
    }
    let mut buf = [0u8; 16];
    match rx.recv(&mut buf) {
        Ok(n) if &buf[..n] == b"derm-probe" => Got::Ok,
        Ok(_) => Got::Errno(-1),
        Err(e) => errno(&e),
    }
}

/// The four sends and the loopback check, as this process's own uid.
pub(crate) fn run() -> Vec<Outcome> {
    let v4: SocketAddr = "192.0.2.1:9".parse().expect("a literal address");
    let v6: SocketAddr = "[2001:db8::1]:9".parse().expect("a literal address");
    let dns: SocketAddr = "127.0.0.53:53".parse().expect("a literal address");
    vec![
        timed(LOOPBACK, loopback),
        timed(UDP, || udp("0.0.0.0:0", v4)),
        timed(TCP, || tcp(v4)),
        timed(DNS, || udp("127.0.0.1:0", dns)),
        timed(UDP6, || udp("[::]:0", v6)),
    ]
}

/// A default IPv6 route off `lo` (`accounts.py` `has_v6_route`).
pub(crate) fn v6_route() -> bool {
    std::fs::read_to_string("/proc/net/ipv6_route").is_ok_and(|t| {
        t.lines().any(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            f.len() > 9 && f[0] == "0".repeat(32) && f[9] != "lo"
        })
    })
}

/// [`run`] and [`judge`].
pub(crate) fn check() -> Result<(), String> {
    judge(&run(), v6_route())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn o(name: &'static str, got: Got) -> Outcome {
        Outcome {
            name,
            got,
            took: Duration::from_millis(5),
        }
    }

    fn held() -> Vec<Outcome> {
        vec![
            o(LOOPBACK, Got::Ok),
            o(UDP, Got::Errno(libc::EPERM)),
            o(TCP, Got::Errno(libc::EHOSTUNREACH)),
            o(DNS, Got::Errno(libc::EPERM)),
            o(UDP6, Got::Errno(libc::EPERM)),
        ]
    }

    /// The answers L2 ran with the table loaded pass; every way a send gets
    /// another answer, or the table's answer late, fails and names the fix.
    #[test]
    fn only_the_tables_own_answers_pass() {
        assert_eq!(judge(&held(), true), Ok(()));
        let mut no_v6 = held();
        no_v6[4] = o(UDP6, Got::Unsupported);
        assert_eq!(judge(&no_v6, false), Ok(()));
        no_v6[4] = o(UDP6, Got::Errno(libc::ENETUNREACH));
        assert_eq!(judge(&no_v6, false), Ok(()));
        for (i, got) in [
            (0, Got::Errno(libc::EPERM)),
            (1, Got::Ok),
            (1, Got::Errno(libc::ENETUNREACH)),
            (2, Got::Timeout),
            (2, Got::Errno(libc::ECONNREFUSED)),
            (3, Got::Ok),
            (4, Got::Ok),
        ] {
            let mut c = held();
            c[i].got = got.clone();
            let e = judge(&c, true).unwrap_err();
            assert!(
                e.contains(c[i].name) && (i == 0 || e.contains("derm-agents-nft")),
                "{i} {got:?}: {e}"
            );
        }
        // An IPv6 ENETUNREACH with a route off lo is no table's answer.
        let mut c = held();
        c[4].got = Got::Errno(libc::ENETUNREACH);
        assert!(judge(&c, true).is_err());
        // The table's answer after a timeout is a hang, not a refusal.
        let mut c = held();
        c[2].took = Duration::from_secs(4);
        assert!(judge(&c, true).is_err());
    }

    /// The real sends, as this test's uid: no derm table holds them here, so
    /// the check refuses, and a chat would not start. (In CI and in this
    /// workspace nothing refuses a datagram to TEST-NET-1; on a machine with
    /// a derm table and this uid in it, this would pass, which no test
    /// machine has.)
    #[test]
    fn with_no_table_the_check_refuses() {
        let out = run();
        assert_eq!(out[0].got, Got::Ok, "loopback reached: {out:?}");
        let e = check().unwrap_err();
        assert!(e.contains("was not refused"), "{e}");
    }
}
