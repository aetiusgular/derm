// The audit feed's user units (box test w5 retest 2, BW5R2-5). Step 0's unit
// on the box had PartOf= and WantedBy=default.target only, so a stop and a
// start of derm-daemon left the feed down until someone started it by hand.
// systemd.unit(5): PartOf= is "a one-way dependency" that propagates stopping
// and restarting only; a unit enabled with WantedBy=X is linked into X's
// .wants/ folder, "implicitly added as dependencies of type Wants=".
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const root = new URL("../", import.meta.url);
const text = (p: string) => readFileSync(new URL(p, root), "utf8");

function section(unit: string, name: string): string[] {
  const out: string[] = [];
  let inside = false;
  for (const raw of unit.split("\n")) {
    const line = raw.trim();
    if (line.startsWith("#") || line === "") continue;
    if (line.startsWith("[")) {
      inside = line === `[${name}]`;
      continue;
    }
    if (inside) out.push(line);
  }
  return out;
}

describe.each([
  ["packaging/deb/derm-audit-feed.service", "ExecStart=/usr/bin/derm-audit-feed run"],
  ["crates/derm-audit-linux/units/derm-audit-feed.service", "ExecStart=%h/.local/bin/derm-audit-feed run"],
])("%s", (path, exec) => {
  const unit = text(path);

  it("starts with every start of derm-daemon and nowhere else", () => {
    expect(section(unit, "Install")).toEqual(["WantedBy=derm-daemon.service"]);
  });

  it("stops and restarts with derm-daemon, after it", () => {
    const u = section(unit, "Unit");
    expect(u).toContain("PartOf=derm-daemon.service");
    expect(u).toContain("After=derm-daemon.service");
  });

  it("runs the feed, restarting on failure, with no added rights", () => {
    const s = section(unit, "Service");
    expect(s).toContain(exec);
    expect(s).toContain("Restart=on-failure");
    expect(s).toContain("NoNewPrivileges=yes");
    expect(s).toContain("UMask=0077");
  });
});
