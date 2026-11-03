// The "Report an entry" issue form (.github/ISSUE_TEMPLATE/abuse-report.yml)
// against GitHub's documented form rules, read 2 Nov 2026: a form begins with
// `name`, `description` and `body` (syntax-for-issue-forms); each `id` "Must
// be unique in the form definition" and "Can only use alpha-numeric
// characters, `-`, and `_`"; the types are checkboxes, dropdown, input,
// markdown, textarea and upload (syntax-for-githubs-form-schema).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parse } from "yaml";
import { describe, expect, it } from "vitest";
import { REPO_ROOT } from "../validate/schemas.ts";
import { LOG_HEADER } from "./takedown.ts";

const text = readFileSync(join(REPO_ROOT, ".github", "ISSUE_TEMPLATE", "abuse-report.yml"), "utf8");
const form = parse(text) as { name: string; description: string; body: { type: string; id?: string; attributes: Record<string, unknown> }[] };

describe("the report form", () => {
  it("has GitHub's three required keys first and only documented element types", () => {
    expect(Object.keys(form).slice(0, 3)).toEqual(["name", "description", "body"]);
    for (const el of form.body) expect(["checkboxes", "dropdown", "input", "markdown", "textarea", "upload"]).toContain(el.type);
  });

  it("gives every field a unique id in GitHub's character set and a label", () => {
    const ids = form.body.filter((el) => el.type !== "markdown").map((el) => el.id);
    for (const id of ids) expect(id).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(new Set(ids).size).toBe(ids.length);
    for (const el of form.body) {
      if (el.type === "markdown") expect(typeof el.attributes["value"]).toBe("string");
      else expect(typeof el.attributes["label"]).toBe("string");
    }
  });

  it("states the same response window as the public log", () => {
    const window = /We answer within (\d+) days/;
    expect(window.exec(text)?.[1]).toBe(window.exec(LOG_HEADER)?.[1]);
  });
});
