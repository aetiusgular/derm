//! Reading one Windows event in its XML form (what `EvtRender` with
//! `EvtRenderEventXml` gives): `<System>`'s `EventID` and `TimeCreated`, and
//! `<EventData>`'s `<Data Name='...'>value</Data>` pairs. Not a general XML
//! reader: the event schema is fixed (`http://schemas.microsoft.com/win/
//! 2004/08/events/event`), and anything this does not understand is left out,
//! never guessed. No dependency.

use std::collections::BTreeMap;

/// One event's parts the feed reads.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WinEvent {
    pub provider: String,
    pub event_id: u32,
    /// `TimeCreated`'s `SystemTime`, as written (`2026-11-05T09:30:01.1234567Z`).
    pub system_time: String,
    pub record_id: Option<u64>,
    pub data: BTreeMap<String, String>,
}

/// The largest event read; Sysmon's events are a few KiB.
pub const MAX_EVENT: usize = 256 * 1024;

pub fn parse(xml: &str) -> Option<WinEvent> {
    if xml.len() > MAX_EVENT {
        return None;
    }
    let system = between(xml, "<System>", "</System>")?;
    let event_id = element_text(system, "EventID")?.trim().parse().ok()?;
    let provider = tag(system, "Provider")
        .and_then(|t| attr(t, "Name"))
        .unwrap_or_default();
    let system_time = tag(system, "TimeCreated")
        .and_then(|t| attr(t, "SystemTime"))
        .unwrap_or_default();
    let record_id = element_text(system, "EventRecordID").and_then(|t| t.trim().parse().ok());
    let mut data = BTreeMap::new();
    if let Some(body) = between(xml, "<EventData>", "</EventData>") {
        let mut rest = body;
        while let Some(start) = rest.find("<Data") {
            rest = &rest[start + "<Data".len()..];
            let end = rest.find('>')?;
            let head = &rest[..end];
            let name = attr(head, "Name")?;
            if head.ends_with('/') {
                data.insert(name, String::new());
                rest = &rest[end + 1..];
                continue;
            }
            let body_end = rest.find("</Data>")?;
            let value = unescape(&rest[end + 1..body_end])?;
            data.insert(name, value);
            rest = &rest[body_end + "</Data>".len()..];
        }
    }
    Some(WinEvent {
        provider,
        event_id,
        system_time,
        record_id,
        data,
    })
}

fn between<'a>(s: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let a = s.find(open)? + open.len();
    let b = s[a..].find(close)? + a;
    Some(&s[a..b])
}

/// The text of `<name>text</name>` or `<name attr='x'>text</name>`.
fn element_text<'a>(s: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}");
    let mut from = 0;
    while let Some(i) = s[from..].find(&open) {
        let at = from + i + open.len();
        // `<EventID` must not match `<EventIDx`.
        let next = s[at..].chars().next()?;
        if next == '>' || next == ' ' {
            let gt = s[at..].find('>')? + at;
            let close = format!("</{name}>");
            let end = s[gt..].find(&close)? + gt;
            return Some(&s[gt + 1..end]);
        }
        from = at;
    }
    None
}

/// The inside of `<name .../>` or `<name ...>`.
fn tag<'a>(s: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name} ");
    let i = s.find(&open)? + open.len();
    let end = s[i..].find('>')? + i;
    Some(&s[i..end])
}

/// An attribute's value, in single or double quotes, unescaped.
fn attr(head: &str, name: &str) -> Option<String> {
    for q in ['\'', '"'] {
        let key = format!("{name}={q}");
        let mut from = 0;
        while let Some(i) = head[from..].find(&key) {
            let at = from + i;
            // A whole attribute name: start of text or after a space.
            if at == 0 || head.as_bytes()[at - 1] == b' ' {
                let v = at + key.len();
                let end = head[v..].find(q)? + v;
                return unescape(&head[v..end]);
            }
            from = at + key.len();
        }
    }
    None
}

/// The five named entities and numeric references; anything else (a stray
/// `&`, an unknown name) makes the value unreadable rather than guessed.
pub fn unescape(s: &str) -> Option<String> {
    if !s.contains('&') {
        return Some(s.to_string());
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        let semi = after.find(';')?;
        let ent = &after[..semi];
        let c = match ent {
            "lt" => '<',
            "gt" => '>',
            "amp" => '&',
            "quot" => '"',
            "apos" => '\'',
            _ if ent.starts_with("#x") || ent.starts_with("#X") => {
                char::from_u32(u32::from_str_radix(&ent[2..], 16).ok()?)?
            }
            _ if ent.starts_with('#') => char::from_u32(ent[1..].parse().ok()?)?,
            _ => return None,
        };
        out.push(c);
        rest = &after[semi + 1..];
    }
    out.push_str(rest);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE: &str = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/><EventID>11</EventID><Version>2</Version><TimeCreated SystemTime='2026-11-05T09:30:01.1234567Z'/><EventRecordID>4242</EventRecordID></System><EventData><Data Name='RuleName'>-</Data><Data Name='TargetFilename'>C:\\Users\\me\\a &amp; b &lt;x&gt;.txt</Data><Data Name='Empty'/><Data Name='Quote'>&#x41;&#66;&quot;</Data></EventData></Event>";

    #[test]
    fn an_event_reads_its_id_time_and_data() {
        let e = parse(ONE).unwrap();
        assert_eq!(e.provider, "Microsoft-Windows-Sysmon");
        assert_eq!(e.event_id, 11);
        assert_eq!(e.system_time, "2026-11-05T09:30:01.1234567Z");
        assert_eq!(e.record_id, Some(4242));
        assert_eq!(e.data["TargetFilename"], "C:\\Users\\me\\a & b <x>.txt");
        assert_eq!(e.data["Empty"], "");
        assert_eq!(e.data["Quote"], "AB\"");
        assert_eq!(e.data["RuleName"], "-");
    }

    #[test]
    fn double_quotes_and_attributes_on_eventid_read_too() {
        let x = r#"<Event><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID Qualifiers="0">1</EventID><TimeCreated SystemTime="2026-11-05T09:30:01Z"/></System><EventData><Data Name="ProcessId">42</Data></EventData></Event>"#;
        let e = parse(x).unwrap();
        assert_eq!(e.event_id, 1);
        assert_eq!(e.data["ProcessId"], "42");
    }

    #[test]
    fn what_is_not_understood_is_left_out() {
        assert!(parse("").is_none());
        assert!(parse("<Event><System><EventID>x</EventID></System></Event>").is_none());
        let bad = ONE.replace("&amp;", "&bogus;");
        assert!(parse(&bad).is_none(), "an unknown entity is not guessed");
        assert!(parse(&"x".repeat(MAX_EVENT + 1)).is_none());
        assert_eq!(unescape("a&b"), None);
    }
}
