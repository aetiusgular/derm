# Lane 5bE research (rules section 9; items 10 to 20)

Lane 5bE, 10 Nov 2026, cloud. Every outside premise the service, the pipe and
the daemon's feed rest on, at the version in use. **V** read in a primary
source or run, **I** inference, **NF** not found. The base's research is note
BC sections 6 and 11 and `plans/parallel/tk_w5b_base.md` ("Part 2 results").

## Pins

| Thing | Version | Where read |
|---|---|---|
| Sysmon | built-in 10.0.26100.8521, schema 4.91 (the box's Windows 11) | Windows test w5 5.1 |
| windows-sys | 0.61.2 (Cargo.lock) | crates.io source in the cargo registry |
| phnt headers | `winsiderss/phnt` at `53fbbdc` | `ntexapi.h` |
| System Informer | `winsiderss/systeminformer` at `09d3b9a` | `phlib/nativeprocess.c` |
| Win32-OpenSSH | `PowerShell/openssh-portable` at `0172cc6` | `contrib/win32/win32compat/ssh-agent/agent.c` |
| windows-service | 0.8.1 (read, not used) | crates.io `.crate` |
| srt | 0.0.82 (box); account `srt-sandbox` | Windows test w5 4.2 (0.0.81), note BC |

## Premises

| # | Premise | Mark | Source |
|---|---|---|---|
| R1 | Every Sysmon event the feed reads (1, 3, 5, 11, 22, 23, 26) carries `User`; event 1 also `ParentUser` | V | Windows test w5 5.1 (captured, chat `w61`) |
| R2 | The channel grants read to Event Log Readers (`S-1-5-32-573`), and a virtual service account in that group reads it | V | Windows test w5 5.1 (`wevtutil gl`); note BC section 11 (run) |
| R3 | `SystemProcessIdInformation` is class 88, `{HANDLE ProcessId; UNICODE_STRING ImageName}`; on `STATUS_INFO_LENGTH_MISMATCH` the size needed is in `ImageName.MaximumLength`; the name is an NT path | V | `ntexapi.h:2353-2361, 3892-3896`; `nativeprocess.c` `PhGetProcessImageFileNameById`; run from a virtual account by the base |
| R4 | `ImpersonateNamedPipeClient` fails 1368 before the server's first read, then gives the client's SID | V | note BC section 11 (run) |
| R5 | `FILE_APPEND_DATA` is `FILE_CREATE_PIPE_INSTANCE` on a pipe, so clients get individual rights, not `FILE_GENERIC_WRITE` | V | Microsoft Learn, "Named Pipe Security and Access Rights" |
| R6 | `GetFinalPathNameByHandleW` with `VOLUME_NAME_NT` gives `\Device\HarddiskVolumeN\...`, the form R3 gives | V | Microsoft Learn, the function's page |
| R7 | A command line splits by the C runtime's rules (the table in `cmdline.rs`) | V | Microsoft Learn, "Parsing C command-line arguments" |
| R8 | windows-sys 0.61.2 has `NtQuerySystemInformation` under `Wdk_System_SystemInformation` and no constant for class 88 | V | `src/Windows/Wdk/System/SystemInformation/mod.rs` |
| R9 | The service dispatcher: `StartServiceCtrlDispatcherW`, `RegisterServiceCtrlHandlerExW`, `SetServiceStatus` | V | windows-service 0.8.1 `service_dispatcher.rs:108`, `service_control_handler.rs:26, 119` (prior art) |
| R10 | srt runs its command as `srt-sandbox` through `CreateProcessWithLogonW`; whether Sysmon's `ParentProcessGuid` for that process is srt's launcher (yours) or the Secondary Logon service | NF | note AU section 3.2 (the two hops, V); the parent: box test step 3 |
| R11 | The text form of `User` (`DOMAIN\name`) | NF; not needed | Resolved by `LookupAccountNameW`; an account that does not resolve is no one's |
| R12 | Record ids in a channel are contiguous and start again after a clear | I | A hole or a lower newest id is named as a gap, never filled |
| R13 | Who may set an object's owner: the page says WRITE_OWNER lets "any valid user or group SID" be set | V (page), contradicts the usual rule | Microsoft Learn, "Owner of a New Object": the pipe's owner is not used as proof of the server; the service control manager's pid is |
| R14 | Signed-in users can `QueryServiceStatusEx` once the service's descriptor grants `LC` to `AU` | I | `install.ps1` sets it; box test step 2 |
| R15 | `GetNamedPipeServerProcessId` can be spoofed as the client pid can | NF | Project Zero (Sept 2019) is about the client pid; derm-core's `peer.rs` notes it. The server check also needs the pointer file |
| R16 | The virtual account's token user SID is `NT SERVICE\derm-sysmon`'s SID | I | the pointer's trust list and the pipe's ACL use what `LookupAccountNameW` and the token give; a mismatch refuses (box test step 1) |
| R17 | `sc.exe create ... obj= "NT SERVICE\<name>"` makes a virtual-account service | I | the base installed one (note BC section 11, its command not recorded); box test step 1 |

## Prior art

- The pipe's access list: Win32-OpenSSH's agent, `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;AU)` (`agent.c:111`); derm's is `D:P(A;;GA;;;SY)(A;;GA;;;<service>)(A;;0x12008b;;;AU)`, read and write data only.
- Who the client is: the same agent reads the client's token through `OpenProcess` (`agent.c:305-308`); it runs as SYSTEM. A virtual account cannot open the client (R4's run), so derm impersonates after the first read and names the image by class 88 (R3).
- The image by pid without opening the process: System Informer, R3.
- A feed that keeps its place by record id and names gaps: derm-audit-linux's resume (case 209).

## Corrections

- The base's contract says the fixture `tests/windows/fixtures/sysmon/chat.xml` is recorded; its README says lane Z wrote it by hand and the Windows test w5 kept the capture on the Mac unscrubbed. Tests that read it say `handwritten` in their names (rules 9.12).
EOF
echo ok