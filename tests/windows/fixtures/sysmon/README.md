# Sysmon fixtures (lane Z)

`chat.xml`: one event per line, in Windows' event XML (the shape `EvtRender`
with `EvtRenderEventXml` gives), for one chat whose harness is pid 4100. Written
by hand from the published Sysmon schema sample (event version 6.00, schema
3.30) and the field names on Microsoft's Sysmon page (v15.22, read 5 Nov 2026).
Not captured from a running Sysmon: the Windows test w5 replaces them with
captured events (`tk_lane_Z.md`, Windows test steps).

Records: 101 the harness (node, child of derm.exe), 102 its shell, 103 a
create inside the chat's folder, 104 one outside, 105 an outbound connect,
106 an inbound one (ignored), 107 a DNS query, 108 an unrelated process, 109
the shell's exit, 110 an unrelated process that reuses the shell's pid, 111
that process deleting a file (not the chat's), 112 a delete by the harness
with another spelling of the folder, 113 another provider's event (ignored).
