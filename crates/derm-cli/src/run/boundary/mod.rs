//! `derm run`'s boundary choice (wave 5, lane T; `plans/toolkit_universal_plan.md`
//! lane T, rules cases 117, 118, 128, 129). The wave 5 base cut this seam:
//! `run_io` calls [`choose`] on the raw argv before it is parsed, and adds
//! the returned record to `run.start` as `detail.boundaryChoice`
//! (`contracts/events.md` section 5).
//!
//! Lane T owns this folder. The base's stub changes nothing: the argv goes on
//! as given (so `--boundary` is still required, lane D's decision, until lane
//! T replaces it with case 129's default and question) and there is no
//! record.

use serde_json::Value;

/// What the choice gives `run_io`: the argv to parse, and the record for
/// `run.start` when a choice was made.
#[derive(Debug, PartialEq)]
pub(crate) struct Choice {
    pub argv: Vec<String>,
    pub record: Option<Value>,
}

/// The wave 5 base's stub: the argv unchanged, no record.
pub(crate) fn choose(argv: &[String]) -> Result<Choice, (u8, String)> {
    Ok(Choice {
        argv: argv.to_vec(),
        record: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stub_passes_the_argv_on_and_records_nothing() {
        let argv: Vec<String> = ["pi", "--boundary", "srt", "--", "-p", "x"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            choose(&argv).unwrap(),
            Choice {
                argv: argv.clone(),
                record: None
            }
        );
        let bare: Vec<String> = vec!["pi".into()];
        assert_eq!(choose(&bare).unwrap().argv, bare, "no boundary added yet");
    }
}
