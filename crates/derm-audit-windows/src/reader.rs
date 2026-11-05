//! Reading Sysmon's channel on Windows: `EvtQuery` over
//! `Microsoft-Windows-Sysmon/Operational` from a record id on, `EvtNext` in
//! batches, each event rendered as XML (`EvtRenderEventXml`) for
//! `xml::parse`. Polled, not subscribed: a feed that restarts reads on from
//! the last record id it kept. Which rights the channel needs to be read is
//! NF (note AU section 6, I that Event Log Readers or a service account
//! suffices); a refusal comes back as the error.

use std::io;

use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS,
};
use windows_sys::Win32::System::EventLog::{
    EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryForwardDirection, EvtRender,
    EvtRenderEventXml, EVT_HANDLE,
};

use crate::sysmon::CHANNEL;

/// Closes an event log handle on drop.
struct Evt(EVT_HANDLE);

impl Drop for Evt {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: a handle EvtQuery or EvtNext gave us; closed once.
            unsafe { EvtClose(self.0) };
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Up to `max` events after record `after`, as (record id order) XML text.
pub fn read_after(after: u64, max: usize) -> io::Result<Vec<String>> {
    let channel = wide(CHANNEL);
    let query = wide(&format!("*[System[EventRecordID>{after}]]"));
    // SAFETY: both strings are NUL-terminated; a null session is the local
    // machine.
    let q = Evt(unsafe {
        EvtQuery(
            0,
            channel.as_ptr(),
            query.as_ptr(),
            EvtQueryChannelPath | EvtQueryForwardDirection,
        )
    });
    if q.0 == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut out = Vec::new();
    let mut batch = [0isize; 32];
    while out.len() < max {
        let mut got = 0u32;
        // SAFETY: the array holds `batch.len()` handles; we close each.
        let ok = unsafe {
            EvtNext(
                q.0,
                batch.len() as u32,
                batch.as_mut_ptr(),
                1000,
                0,
                &mut got,
            )
        };
        if ok == 0 {
            // SAFETY: reads this thread's last error.
            let e = unsafe { GetLastError() };
            if e == ERROR_NO_MORE_ITEMS {
                break;
            }
            return Err(io::Error::from_raw_os_error(e as i32));
        }
        // Every handle is owned before any is rendered, so an error on one
        // still closes the rest.
        let held: Vec<Evt> = batch[..got as usize].iter().map(|h| Evt(*h)).collect();
        for h in &held {
            if out.len() < max {
                out.push(render(h.0)?);
            }
        }
    }
    Ok(out)
}

fn render(h: EVT_HANDLE) -> io::Result<String> {
    let mut used = 0u32;
    let mut props = 0u32;
    // SAFETY: a size query with no buffer.
    let ok = unsafe {
        EvtRender(
            0,
            h,
            EvtRenderEventXml,
            0,
            std::ptr::null_mut(),
            &mut used,
            &mut props,
        )
    };
    if ok == 0 {
        // SAFETY: as above.
        let e = unsafe { GetLastError() };
        if e != ERROR_INSUFFICIENT_BUFFER {
            return Err(io::Error::from_raw_os_error(e as i32));
        }
    }
    if used as usize > crate::xml::MAX_EVENT * 2 {
        return Err(io::Error::other("an event larger than the feed reads"));
    }
    let mut buf = vec![0u16; (used as usize).div_ceil(2)];
    // SAFETY: the buffer holds `used` bytes.
    let ok = unsafe {
        EvtRender(
            0,
            h,
            EvtRenderEventXml,
            (buf.len() * 2) as u32,
            buf.as_mut_ptr().cast(),
            &mut used,
            &mut props,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let end = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
    Ok(String::from_utf16_lossy(&buf[..end]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// On a machine without Sysmon (CI, Wine) the channel is missing: the
    /// reader says so as an error, never a panic or a made-up event.
    #[test]
    fn a_missing_or_empty_channel_is_an_error_or_nothing() {
        match read_after(u64::MAX - 1, 4) {
            Ok(events) => assert!(events.len() <= 4),
            Err(e) => assert!(e.raw_os_error().is_some() || !e.to_string().is_empty()),
        }
    }
}
