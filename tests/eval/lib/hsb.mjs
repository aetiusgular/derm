// HarnessSecurity-Bench runner (plan 6F (e)). HSB's released repo (`d4510a9`) states
// NO repository licence (note AZ, F5), so by rules section 5, item 2 and the wave 6
// plan's section 6, item 8, it is not run until Tony confirms the authors' answer.
// This module refuses to run without that confirmation, so no later session runs HSB
// by accident. E1 passes DERM_HSB_LICENCE_OK=1 only after Tony's yes.
export function hsbGate() {
  if (process.env.DERM_HSB_LICENCE_OK !== "1") {
    throw new Error(
      "HSB has no repository licence (note AZ, F5). Do not run it until Tony confirms the authors' answer (rules section 5, item 2). Set DERM_HSB_LICENCE_OK=1 only then.",
    );
  }
}
