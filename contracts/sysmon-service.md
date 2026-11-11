# `derm-sysmon`: the Sysmon reader service and its pipe

Written by the wave 5b base on 10 Nov 2026 (`plans/toolkit_wave5b_plan.md` lane 5bE, proposed cases 232 and 233; request Z-4). Evidence: note BC sections 6 and 11, `plans/parallel/tk_w5b_base.md` "Part 2 results" (run on the box's Windows 11, Sysmon built-in 10.0.26100.8521, schema 4.91), and note AU. Marks: **V** read or run, **I** inference, **NF** not found. Fixtures: `fixtures/sysmon-service/exchange.jsonl` and the recorded events in `tests/windows/fixtures/sysmon/chat.xml`.

## 1. What Windows gives (V)

- A virtual service account (`NT SERVICE\derm-sysmon`) reads `Microsoft-Windows-Sysmon/Operational` once it is in Event Log Readers (`EvtQuery` 5 before, 5 events after); `sysmon -c` with the same config leaves the channel's SDDL as it was (part 2, run).
- Every event on the box's Sysmon (1, 3, 5, 11, 22, 23, 26) carries `User` (Windows test 5.1; BC section 6); derm reads it for event 1 only today (`crates/derm-audit-windows/src/sysmon.rs:73-80`).
- A pipe server reads its client's pid with `GetNamedPipeClientProcessId` (spoofable alone); `OpenProcess` on that pid fails 5 from a virtual account; `NtQuerySystemInformation` class 88 (`SystemProcessIdInformation`) names its image without opening it; `ImpersonateNamedPipeClient` fails 1368 until the server has read from the pipe, then gives the client's SID (part 2, run). derm's daemon already impersonates and checks image and start time on its own pipe (`derm-core/src/platform/windows/peer.rs`).

## 2. The service (lane 5bE; I until built and run)

- `derm-sysmon.exe` from a folder only administrators can write, run as `NT SERVICE\derm-sysmon`, a member of Event Log Readers and of nothing else; `derm setup` shows the install (as administrator), its undo, and asks (rules section 5, item 2).
- It reads the channel by record id (lane Z's `reader.rs`), keeps one cursor per client, and never lets one client acknowledge another's events (case 232).
- Its pipe has a random name, kept in a pointer file only administrators and the service can write (`%ProgramData%\derm\sysmon.pipe`), created as the pipe's first instance (case 136's rule); a client refuses a pipe whose server is not the service's account.
- A client is served only when its image (class 88) is `derm-daemon.exe` in an administrators-only folder and its SID (after the first read) is a real user's; the service then sends that user's events only (case 233): `User` where the event carries it, else joined by `ProcessGuid` to a process event that did; an srt chat's sandbox-account processes go to the user whose daemon claimed them (section 3, `claim`).
- Against an agent running as that user it holds nothing (BBR-2): the agent can run or inject into the user's own daemon program. `derm status` says so.

## 3. The wire

JSON lines both ways on the pipe, at most 1 MiB a line. The daemon speaks first.

| From | Line | Answer |
|---|---|---|
| daemon | `{"op":"hello","protocol":1}` | `{"ok":true,"protocol":1,"user":"<the client's SID>","cursor":<last acknowledged record id or null>}`, or `{"ok":false,"error"}` and the pipe closes (not the daemon program, not an administrators-only folder) |
| daemon | `{"op":"claim","processGuid":"{...}","chat":"<chat id>"}` | `{"ok":true}`: the process and its descendants are this user's (an srt chat's sandbox-account processes); refused for a process another client claimed or one of another real user |
| service | `{"op":"events","records":[{"recordId":<u64>,"xml":"<Event ...>"}]}` | the daemon parses each as `derm_audit_windows::xml::parse` and `sysmon::read` do, shapes argv (case 168) and ingests it as auditd's and eslogger's events |
| daemon | `{"op":"ack","recordId":<u64>}` | none; the service moves this client's cursor |
| service | `{"op":"gap","from":<u64>,"to":<u64>,"reason":"..."}` | none; the report names it for every chat it overlaps (case 209) |

The daemon's side lives in `crates/derm-daemon/src/platform/windows/sysmon_feed/` (lane 5bE). `report.osFeed` says `attached`, `stopped` or `none` for it as for the Linux feed (case 176).

## 4. `derm-sysmon decode`

`derm-sysmon decode` reads Sysmon event XML on stdin, one event a line, and prints each as the JSON the daemon would ingest (`{"recordId","event":<derm_core::event::Event>}`), shaped as the feed shapes it; it opens no pipe and needs no rights. The contract test runs it on `tests/windows/fixtures/sysmon/chat.xml` on every OS.
