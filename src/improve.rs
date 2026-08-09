use crate::input::Input;
use crate::llm::Llm;
use crate::promptctx::{shared_context, UNTRUSTED_DATA_SYSTEM_NOTE};
use crate::spec::Spec;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub const IMPROVE_SYSTEM: &str = "You propose concrete remediation steps for confirmed secret-scan findings: \
rotate the credential, add the right .gitignore entry, or scrub it from history with git filter-repo/BFG. \
Never restate a raw secret value, and never propose a 'fix' that requires you to have seen the real value. \
Respond only in the specified JSON schema.";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suggestion {
    pub candidate_id: String,
    pub action: String, // e.g. "rotate", "gitignore", "history-scrub", "false-positive-tune-rule"
    pub suggestion_content: String,
    pub command_snippet: String,
    pub one_sentence_summary: String,
    pub label: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ImproveOutput {
    #[serde(default, deserialize_with = "crate::llm::null_to_default")]
    suggestions: Vec<Suggestion>,
}

pub fn run(llm: &Llm, spec: &Spec, input: &Input) -> Result<Vec<Suggestion>> {
    let ctx = shared_context(spec, input);
    let task = format!(
        "# Task\nPropose remediation for the candidates found in this scan.\n\n\
         ## Rules\n\
         - Reference candidates only by candidate_id — never their raw value.\n\
         - command_snippet should be a real, safe shell command (git filter-repo, .gitignore append, etc.) — not one that requires the raw secret.\n\
         - one_sentence_summary: 6 words or fewer.\n\
         - label must be exactly one of: {labels}\n\n\
         ## Output (JSON only, no code fences)\n\
         {{\"suggestions\":[{{\"candidate_id\":\"...\",\"action\":\"rotate|gitignore|history-scrub|false-positive-tune-rule\",\
         \"suggestion_content\":\"...\",\"command_snippet\":\"...\",\"one_sentence_summary\":\"...\",\"label\":<one of the allowed values>}}]}}\n",
        labels = spec.labels_prompt(),
    );
    let system = format!("{IMPROVE_SYSTEM}\n\n{UNTRUSTED_DATA_SYSTEM_NOTE}");
    let v = llm
        .json_ctx(Some(&ctx), &task, Some(&system))
        .context("improve failed")?;
    let out: ImproveOutput = serde_json::from_value(v).context("improve schema mismatch")?;
    Ok(out.suggestions)
}
