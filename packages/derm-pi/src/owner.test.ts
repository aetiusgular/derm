// derm-pi's port of the core's owner.ts (lane V, request V-3): the same
// answers, and the policy store trusts the person's file under an agents' user.

import { afterEach, describe, expect, it } from "vitest";
import { _setOwnersForTest, ownersFor, policyOwnerUid } from "./owner.ts";
import * as core from "../../derm-claude-plugin/src/core/owner.ts";

const entry = (uid: number, ownerUid: number) =>
  JSON.stringify({ version: 1, agents: [{ user: "derm-agent", uid, owner: "tony", ownerUid, path: "/usr/bin", how: "sudo" }] });

afterEach(() => _setOwnersForTest(undefined));

describe("owner.ts in derm-pi", () => {
  it("answers as the core does", () => {
    for (const [uid, text] of [
      [1000, undefined],
      [998, entry(998, 1000)],
      [1000, entry(998, 1000)],
      [998, "{"],
      [998, entry(998, 998)],
    ] as const) {
      expect(ownersFor(uid, text), String(text)).toEqual(core.ownersFor(uid, text));
    }
  });
  it.skipIf(typeof process.getuid !== "function")("gives the policy store the person's uid, or one no file has", () => {
    _setOwnersForTest({ uids: [1000], agent: true });
    expect(policyOwnerUid()).toBe(1000);
    _setOwnersForTest({ uids: [], agent: false, problem: "broken" });
    expect(policyOwnerUid()).toBe(-1);
  });
});
