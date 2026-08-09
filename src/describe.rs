use crate::input::Input;
use crate::llm::Llm;
use crate::promptctx::{shared_context, UNTRUSTED_DATA_SYSTEM_NOTE};
use crate::spec::Spec;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub const DESCRIBE_SYSTEM: &str = "You summarize a secret-scan run for a developer about to push or open-source a repo. \
Never restate raw secret values. Respond only in the specified JSON schema.";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Describe {
    pub title: String,
    pub summary: String,
    #[serde(default, deserialize_with = "crate::llm::null_to_default")]
    pub risk_highlights: Vec<String>,
    #[serde(default, deserialize_with = "crate::llm::null_to_default")]
    pub labels: Vec<String>,
    pub safe_to_publish: String, // yes|no|unknown
    #[serde(default, deserialize_with = "crate::llm::null_to_default")]
    pub safe_to_publish_note: String,
}

pub fn run(llm: &Llm, spec: &Spec, input: &Input) -> Result<Describe> {
    let ctx = shared_context(spec, input);
    let task = "# Task\nSummarize this secret-scan run.\n\n\
         ## Output (JSON only, no code fences)\n\
         {\"title\":\"one line, under 50 chars\",\"summary\":\"2-4 sentences\",\
         \"risk_highlights\":[\"one line per notable candidate/category, reference candidate ids not raw values\"],\
         \"labels\":[\"categories of risk found, e.g. cloud-credential, private-key\"],\
         \"safe_to_publish\":\"yes|no|unknown\",\"safe_to_publish_note\":\"why\"}\n";
    let system = format!("{DESCRIBE_SYSTEM}\n\n{UNTRUSTED_DATA_SYSTEM_NOTE}");
    let v = llm.json_ctx(Some(&ctx), task, Some(&system)).context("describe failed")?;
    serde_json::from_value(v).context("describe schema mismatch")
}
