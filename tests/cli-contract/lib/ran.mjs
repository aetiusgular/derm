// BW5B-R4 (box test w5b retest, item 6): whether a tool result shows that a
// shell call printed `marker`, read the way each agent returns it.
// A tool result that shows the marker ran: the line the shell printed, with
// its newline (as written or escaped) or at the end. BW5B-R4: Hermes's
// terminal tool returns `{"output": "<stripped text>", "exit_code": 0, ...}`
// (Hermes v0.22.5 tools/terminal_tool_result.py:241, 258; the reply in
// checks/5bB/fixtures/hermes-terminal-0.22.5.json, recorded on the box), so the marker
// is a line of its `output` field there.
export const ranText = (x, marker) => {
  if (x.includes(`${marker}\n`) || x.includes(`${marker}\\n`) || x.trim().endsWith(marker)) return true;
  try {
    const v = JSON.parse(x);
    return typeof v?.output === "string" && v.output.split("\n").some((l) => l.trim() === marker);
  } catch {
    return false;
  }
};
