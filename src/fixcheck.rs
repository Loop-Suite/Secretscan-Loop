use crate::input::Input;
use crate::lens::Finding;
use crate::llm::Llm;
use crate::promptctx::{shared_context, UNTRUSTED_DATA_SYSTEM_NOTE};
use crate::spec::Spec;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// codereview-loop's FIXED/STILL_OPEN/UNKNOWN plus a domain-specific ROTATED
/// (design-spec.md §1): the value is still physically present in the scanned tree, but the
/// underlying credential has since been rotated/revoked, so it's no longer live even though
/// the string wasn't removed. Distinct from STILL_OPEN (present *and* still exploitable).
pub const FIXCHECK_SYSTEM: &str = "You check whether a previously confirmed secret finding was actually addressed in this scan. \
If the candidate is simply gone (removed, replaced with an env-var reference), mark FIXED. \
If it's still present in the same form, mark STILL_OPEN. \
If the notes/policy text explicitly state the credential has been rotated or revoked, mark ROTATED — \
the string may still be sitting in history, but it is no longer a live risk. \
If you cannot tell, mark UNKNOWN. Never restate a raw secret value. Respond only in the specified JSON schema.";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixStatus {
    pub finding_id: String,
    pub status: String, // FIXED|STILL_OPEN|UNKNOWN|ROTATED
    pub evidence: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct FixCheckOutput {
    #[serde(default, deserialize_with = "crate::llm::null_to_default")]
    results: Vec<FixStatus>,
}

pub fn run(llm: &Llm, spec: &Spec, input: &Input, prior_confirmed: &[Finding]) -> Result<Vec<FixStatus>> {
    if prior_confirmed.is_empty() {
        return Ok(Vec::new());
    }
    let list = prior_confirmed
        .iter()
        .map(|f| format!("- id={} | candidate={} | {}\n  evidence: {}", f.id, f.candidate_id, f.claim, f.evidence))
        .collect::<Vec<_>>()
        .join("\n");
    let ctx = shared_context(spec, input);
    let task = format!(
        "# Task\nCheck whether these previously confirmed findings were fixed, are still open, or were rotated.\n\n\
         ## Previously confirmed findings\n{list}\n\n\
         ## Output (JSON only, no code fences)\n\
         {{\"results\":[{{\"finding_id\":\"...\",\"status\":\"FIXED|STILL_OPEN|UNKNOWN|ROTATED\",\"evidence\":\"...\"}}]}}\n",
        list = list
    );
    let system = format!("{FIXCHECK_SYSTEM}\n\n{UNTRUSTED_DATA_SYSTEM_NOTE}");
    let v = llm.json_ctx(Some(&ctx), &task, Some(&system)).context("fix check failed")?;
    let out: FixCheckOutput = serde_json::from_value(v).context("fix check schema mismatch")?;
    Ok(out.results)
}
