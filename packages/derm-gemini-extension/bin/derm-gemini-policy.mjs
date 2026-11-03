#!/usr/bin/env node
// Prints your derm policy (~/.derm/policy.json, or $DERM_POLICY) as Gemini CLI
// policy rules for the user tier. Save the output as
// ~/.gemini/policies/derm.toml yourself; this script writes nothing.
//   node bin/derm-gemini-policy.mjs > ~/.gemini/policies/derm.toml.new
if (!process.features || !process.features.typescript) {
  process.stderr.write(`this Node (${process.version}) cannot run derm: it needs type stripping (Node 22.18 or later)\n`);
  process.exit(1);
}
const { loadPolicyFrom } = await import(new URL("../src/core/policy.ts", import.meta.url).href);
const { policyToToml } = await import(new URL("../src/policyToml.ts", import.meta.url).href);
process.stdout.write(policyToToml(loadPolicyFrom(process.env)));
