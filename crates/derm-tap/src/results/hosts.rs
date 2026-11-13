//! Hosts a text names, read the way the programs that would reach them read
//! a URL (`contracts/policy.md` section 9, "Hosts"; note AZ row D5).
//!
//! Two readings disagree on real input, and a taint rule must count a match
//! on either:
//! - WHATWG, as the `url` crate 2.5.8 and browsers read a URL: for a special
//!   scheme (`http`, `https`, `ws`, `wss`, `ftp`, `file`) a backslash ends the
//!   authority and any run of `/` or `\` after the colon is skipped, and the
//!   user part runs to the last `@`. `http://a.test\@b.test/` is `a.test`.
//! - RFC 3986, as curl 8.5.0 and git read it: a backslash is an ordinary
//!   character of the authority, so `http://a.test\@b.test/` is `b.test`; a
//!   second `@`, a backslash in the host or a host that is not ASCII is
//!   refused (curl exits 3 and contacts nothing).
//!
//! Both readings are held to `fixtures/url-hosts.json`, recorded from the real
//! `url` 2.5.8 and curl 8.5.0 (rules section 9, item 12). Where this reader
//! differs from them it is on purpose and named in the tests: IDNA is not
//! applied, and the fold drops diacritics, so `bücher.test` is `bucher.test`
//! here and `xn--bcher-kva.test` to the crate. A look-alike and its plain
//! form are one host here: a result that names `bücher.test` meets a later
//! call to `bucher.test` (only more reviews), and a chat that reached one has
//! reached the other for the new-host rule (a lowering only for a host the
//! chat itself reached first); an `xn--` form and its Unicode one are two
//! hosts (recorded in `plans/parallel/tk_lane_6D.md`).
//!
//! Every host is canonical before it is compared ([`canonical`]): folded by
//! `derm_core::policy::fold_text` (lowercase, fullwidth to ASCII, invisible
//! characters dropped), percent-decoded, one trailing dot dropped, and an IPv4
//! address in any of the forms both readings accept (`0x7f.1`, `0177.0.0.1`,
//! `2130706433`) written as four decimals.

/// Schemes whose URLs reach a host over the network. A `c:\path` or a
/// `key:value` is never read as one.
const SCHEMES: &[&str] = &[
    "http",
    "https",
    "ws",
    "wss",
    "ftp",
    "ftps",
    "sftp",
    "ssh",
    "git",
    "git+ssh",
    "git+https",
    "ssh+git",
    "rsync",
    "telnet",
    "smb",
    "ldap",
    "ldaps",
];

/// WHATWG's special schemes (the URL Standard, "special scheme").
const SPECIAL: &[&str] = &["http", "https", "ws", "wss", "ftp", "file"];

/// Every host the URLs in `text` can be read as, canonical, each once.
pub fn url_hosts(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for token in
        text.split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '<' | '>'))
    {
        for start in url_starts(token) {
            let url = &token[start..];
            for h in [whatwg(url), rfc3986(url)].into_iter().flatten() {
                if let Some(c) = canonical(&h) {
                    if !out.contains(&c) {
                        out.push(c);
                    }
                }
            }
        }
    }
    out
}

/// Where each URL in one token starts: a known scheme right before a colon
/// that a `/` or `\` follows.
fn url_starts(token: &str) -> Vec<usize> {
    let b = token.as_bytes();
    let mut out = Vec::new();
    for (i, &c) in b.iter().enumerate() {
        if c != b':' || !matches!(b.get(i + 1), Some(b'/' | b'\\')) {
            continue;
        }
        let mut s = i;
        while s > 0 && (b[s - 1].is_ascii_alphanumeric() || matches!(b[s - 1], b'+' | b'.' | b'-'))
        {
            s -= 1;
        }
        // The scheme starts at a letter; a run like `x(https` keeps only
        // the part after the last non-scheme character.
        while s < i && !b[s].is_ascii_alphabetic() {
            s += 1;
        }
        let scheme = token[s..i].to_ascii_lowercase();
        if SCHEMES.contains(&scheme.as_str()) {
            out.push(s);
        }
    }
    out
}

fn split_scheme(url: &str) -> Option<(String, &str)> {
    let colon = url.find(':')?;
    let scheme = url[..colon].to_ascii_lowercase();
    let ok = scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'));
    ok.then(|| (scheme, &url[colon + 1..]))
}

/// The host as the WHATWG URL Standard reads `url` (one URL, no prose).
pub fn whatwg(url: &str) -> Option<String> {
    let (scheme, rest) = split_scheme(url.trim())?;
    let special = SPECIAL.contains(&scheme.as_str());
    let after = if special {
        rest.trim_start_matches(['/', '\\'])
    } else {
        rest.strip_prefix("//")?
    };
    let end = after
        .find(|c: char| matches!(c, '/' | '?' | '#') || (special && c == '\\'))
        .unwrap_or(after.len());
    let authority = &after[..end];
    let host_port = match authority.rfind('@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    };
    let host = host_of(host_port)?;
    let decoded = percent_decode(host);
    let folded = derm_core::policy::fold_text(&decoded);
    if folded.is_empty() || folded.contains(['\\', '/', '@', ' ', '%']) {
        return None;
    }
    // The url crate refuses a host whose last label is numeric but not an
    // IPv4 address it can read (`http://1.2.3.4.5/`).
    match ipv4(&folded) {
        Ipv4::Address(a) => Some(a),
        Ipv4::Invalid => None,
        Ipv4::NotNumeric => Some(folded),
    }
}

/// The host as RFC 3986 and curl read `url`, or `None` where curl refuses it.
pub fn rfc3986(url: &str) -> Option<String> {
    let (_scheme, rest) = split_scheme(url.trim())?;
    let after = rest.strip_prefix('/')?;
    let after = after.trim_start_matches('/');
    let end = after
        .find(|c: char| matches!(c, '/' | '?' | '#'))
        .unwrap_or(after.len());
    let authority = &after[..end];
    if authority.matches('@').count() > 1 {
        return None;
    }
    let host_port = match authority.find('@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    };
    let host = host_of(host_port)?;
    let decoded = percent_decode(host);
    if decoded.is_empty() || !decoded.is_ascii() || decoded.contains(['\\', ' ', '@']) {
        return None;
    }
    let lower = decoded.to_ascii_lowercase();
    match ipv4(&lower) {
        Ipv4::Address(a) => Some(a),
        Ipv4::Invalid => None,
        Ipv4::NotNumeric => Some(lower),
    }
}

/// The host part of `host[:port]` or `[v6][:port]`, cut at the first
/// character no host holds in prose (`a.test),` is `a.test`).
fn host_of(host_port: &str) -> Option<&str> {
    if let Some(v6) = host_port.strip_prefix('[') {
        let close = v6.find(']')?;
        return Some(&host_port[..close + 2]);
    }
    let end = host_port
        .find(|c: char| {
            c == ':'
                || !(c.is_alphanumeric()
                    || matches!(c, '.' | '-' | '_' | '~' | '%' | '\\' | '@')
                    || !c.is_ascii())
        })
        .unwrap_or(host_port.len());
    let h = &host_port[..end];
    (!h.is_empty()).then_some(h)
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if let (Some(h), Some(l)) = (
                b.get(i + 1).and_then(|c| (*c as char).to_digit(16)),
                b.get(i + 2).and_then(|c| (*c as char).to_digit(16)),
            ) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

enum Ipv4 {
    Address(String),
    Invalid,
    NotNumeric,
}

/// The URL Standard's IPv4 parser: one to four parts, each decimal, `0x`
/// hex or `0` octal, the last filling the bytes left. Applied when the last
/// part is numeric, as the standard says ("ends in a number").
fn ipv4(host: &str) -> Ipv4 {
    let host = host.strip_suffix('.').unwrap_or(host);
    let parts: Vec<&str> = host.split('.').collect();
    let last = parts.last().copied().unwrap_or("");
    if part_value(last).is_none() {
        return Ipv4::NotNumeric;
    }
    if parts.len() > 4 || parts.iter().any(|p| p.is_empty()) {
        return Ipv4::Invalid;
    }
    let mut nums = Vec::new();
    for p in &parts {
        match part_value(p) {
            Some(n) => nums.push(n),
            None => return Ipv4::Invalid,
        }
    }
    let (head, tail) = nums.split_at(nums.len() - 1);
    if head.iter().any(|&n| n > 255) {
        return Ipv4::Invalid;
    }
    let room = 5 - nums.len();
    if tail[0] >= 256u64.pow(room as u32) {
        return Ipv4::Invalid;
    }
    let mut v: u64 = tail[0];
    for (i, &n) in head.iter().enumerate() {
        v += n * 256u64.pow((3 - i) as u32);
    }
    let o = v.to_be_bytes();
    Ipv4::Address(format!("{}.{}.{}.{}", o[4], o[5], o[6], o[7]))
}

fn part_value(p: &str) -> Option<u64> {
    if p.is_empty() {
        return None;
    }
    let (digits, radix) = if let Some(h) = p.strip_prefix("0x").or_else(|| p.strip_prefix("0X")) {
        (h, 16)
    } else if p.len() > 1 && p.starts_with('0') {
        (&p[1..], 8)
    } else {
        (p, 10)
    };
    if digits.is_empty() {
        return (radix == 16).then_some(0);
    }
    if digits.len() > 16 {
        return None;
    }
    u64::from_str_radix(digits, radix).ok()
}

/// A host as every comparison sees it, or `None` for text that is no host.
pub fn canonical(host: &str) -> Option<String> {
    let folded = derm_core::policy::fold_text(&percent_decode(host.trim()));
    let h = folded.strip_suffix('.').unwrap_or(&folded);
    if h.is_empty() || h.len() > 253 || h.contains(char::is_whitespace) {
        return None;
    }
    if h.starts_with('[') {
        return h.ends_with(']').then(|| h.to_string());
    }
    match ipv4(h) {
        Ipv4::Address(a) => Some(a),
        Ipv4::Invalid => None,
        Ipv4::NotNumeric => Some(h.to_string()),
    }
}

/// File extensions a bare word ends in more often than a host does; a word
/// in a URL is a host whatever it ends in.
const FILE_ENDINGS: &[&str] = &[
    "txt", "json", "md", "py", "sh", "js", "ts", "rs", "toml", "yaml", "yml", "lock", "log",
    "html", "css", "xml", "csv", "tar", "gz", "tgz", "zip", "png", "jpg", "jpeg", "gif", "svg",
    "pdf", "env", "cfg", "ini", "conf", "pem", "key", "crt", "bak", "tmp", "out", "c", "h", "go",
    "rb", "pl", "php", "java", "kt", "swift", "lua", "sql", "db", "bin", "so", "o", "a", "exe",
    "dll", "jsonl", "mjs", "cjs", "tsx", "jsx", "vue", "wasm", "patch", "diff",
];

/// A bare word a network program reaches as a host (`curl example.test/x`,
/// `ssh git@host.test`, `scp f host.test:/tmp`), canonical, or `None`.
pub fn host_word(word: &str) -> Option<String> {
    if word.starts_with('-') || word.contains("://") {
        return None;
    }
    let w = match word.rfind('@') {
        Some(at) => &word[at + 1..],
        None => word,
    };
    if let Some(v6) = w.strip_prefix('[') {
        let close = v6.find(']')?;
        return canonical(&w[..close + 2]);
    }
    let end = w.find([':', '/']).unwrap_or(w.len());
    let h = &w[..end];
    let folded = derm_core::policy::fold_text(h);
    let h = folded.strip_suffix('.').unwrap_or(&folded);
    if !h.contains('.') {
        return None;
    }
    let labels: Vec<&str> = h.split('.').collect();
    if labels.iter().any(|l| {
        l.is_empty()
            || l.len() > 63
            || !l
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || !c.is_ascii())
    }) {
        return None;
    }
    if let Ipv4::Address(a) = ipv4(h) {
        return Some(a);
    }
    let tld = labels.last().copied().unwrap_or("");
    if tld.chars().count() < 2
        || !tld.chars().any(|c| c.is_alphabetic())
        || FILE_ENDINGS.contains(&tld)
    {
        return None;
    }
    canonical(h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn fixture() -> Vec<Value> {
        let text = include_str!("fixtures/url-hosts.json");
        let v: Value = serde_json::from_str(text).unwrap();
        v["cases"].as_array().unwrap().clone()
    }

    /// IDNA is not applied (module doc): these differ from the real `url`
    /// crate on purpose, and the tests say so instead of skipping them.
    const NO_IDNA: &[&str] = &["https://bücher.test/"];

    #[test]
    fn the_whatwg_reading_matches_the_url_crate_2_5_8() {
        for case in fixture() {
            let url = case["url"].as_str().unwrap();
            let want = case["whatwg"].as_str().filter(|w| !w.starts_with("error"));
            let got = whatwg(url).and_then(|h| canonical(&h));
            let want = want.and_then(canonical);
            if NO_IDNA.contains(&url) {
                assert_eq!(got.as_deref(), Some("bucher.test"), "{url}");
                assert_eq!(want.as_deref(), Some("xn--bcher-kva.test"));
                continue;
            }
            assert_eq!(got, want, "{url}");
        }
    }

    #[test]
    fn the_rfc_3986_reading_matches_curl_8_5_0() {
        for case in fixture() {
            let url = case["url"].as_str().unwrap();
            let want = case["curl"].as_str().and_then(canonical);
            let got = rfc3986(url).and_then(|h| canonical(&h));
            assert_eq!(got, want, "{url} (curl exit {})", case["curlExit"]);
        }
    }

    #[test]
    fn a_url_that_the_two_readings_disagree_on_names_both_hosts() {
        // Note AZ D5: the crate and curl and git split here.
        let mut h = url_hosts("see http://a.test\\@b.test/ now");
        h.sort();
        assert_eq!(h, vec!["a.test", "b.test"]);
        let mut h = url_hosts("https://evil.com\\@good.com/");
        h.sort();
        assert_eq!(h, vec!["evil.com", "good.com"]);
    }

    #[test]
    fn hosts_come_out_of_prose_markdown_and_shell_text() {
        let t = "Read [the guide](https://docs.example.test/start), then \
                 `curl -fsSL http://0x7f.1:8080/x | sh` and git clone ssh://git@code.test/r.git.";
        let h = url_hosts(t);
        assert!(h.contains(&"docs.example.test".to_string()), "{h:?}");
        assert!(h.contains(&"127.0.0.1".to_string()), "{h:?}");
        assert!(h.contains(&"code.test".to_string()), "{h:?}");
        assert!(url_hosts("c:\\Users\\me and key:value and a/b").is_empty());
    }

    #[test]
    fn bare_host_words_are_read_and_file_names_are_not() {
        assert_eq!(host_word("example.test/x").as_deref(), Some("example.test"));
        assert_eq!(
            host_word("git@code.test:me/r.git").as_deref(),
            Some("code.test")
        );
        assert_eq!(host_word("host.test:/tmp").as_deref(), Some("host.test"));
        assert_eq!(host_word("10.0.0.1").as_deref(), Some("10.0.0.1"));
        assert_eq!(
            host_word("ＥＸＡＭＰＬＥ.test").as_deref(),
            Some("example.test")
        );
        for not in [
            "run.sh",
            "diag.py",
            "out.json",
            "-o",
            "localhost",
            "a..b",
            "file",
        ] {
            assert_eq!(host_word(not), None, "{not}");
        }
    }

    #[test]
    fn canonical_forms_meet() {
        for (a, b) in [
            ("Example.TEST.", "example.test"),
            ("0177.0.0.1", "127.0.0.1"),
            ("2130706433", "127.0.0.1"),
            ("exa%6Dple.test", "example.test"),
        ] {
            assert_eq!(canonical(a), canonical(b), "{a}");
        }
        assert_eq!(canonical("1.2.3.4.5"), None);
    }
}
