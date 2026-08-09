use crate::input::Input;
use crate::lens::Finding;
use crate::llm::Llm;
use crate::promptctx::{shared_context, UNTRUSTED_DATA_SYSTEM_NOTE};
use crate::spec::Spec;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub const POLICY_SYSTEM: &str = "You verify a policy checklist against confirmed secret-scan findings. \
Never restate a raw secret value. Respond only in the specified JSON schema.";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCheck {
    pub policy: String,
    pub status: String, // MET|VIOLATED|N/A
    pub evidence: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PolicyOutput {
    #[serde(default, deserialize_with = "crate::llm::null_to_default")]
    policies: Vec<PolicyCheck>,
}

/// spec.policy_checklist empty => None (nothing to verify).
pub fn verify(llm: &Llm, spec: &Spec, input: &Input, confirmed: &[&Finding]) -> Result<Option<Vec<PolicyCheck>>> {
    if spec.policy_checklist.is_empty() {
        return Ok(None);
    }
    let findings_summary = confirmed
        .iter()
        .map(|f| format!("- [{}] candidate={} — {}", f.severity, f.candidate_id, f.claim))
        .collect::<Vec<_>>()
        .join("\n");
    let checklist = spec.policy_checklist.iter().map(|p| format!("- {p}")).collect::<Vec<_>>().join("\n");
    let ctx = shared_context(spec, input);
    let task = format!(
        "# Task\nCheck each policy item against the confirmed findings.\n\n\
         ## Policy checklist\n{checklist}\n\n\
         ## Confirmed findings\n{fs}\n\n\
         ## Output (JSON only, no code fences)\n\
         {{\"policies\":[{{\"policy\":\"exact text\",\"status\":\"MET|VIOLATED|N/A\",\"evidence\":\"candidate id / reasoning, never raw value\"}}]}}\n",
        fs = if findings_summary.is_empty() { "(none)".to_string() } else { findings_summary },
    );
    let system = format!("{POLICY_SYSTEM}\n\n{UNTRUSTED_DATA_SYSTEM_NOTE}");
    let v = llm.json_ctx(Some(&ctx), &task, Some(&system)).context("policy checklist verification failed")?;
    let out: PolicyOutput = serde_json::from_value(v).context("policy checklist schema mismatch")?;
    Ok(Some(out.policies))
}

pub fn violations(policies: &Option<Vec<PolicyCheck>>) -> Vec<String> {
    match policies {
        None => Vec::new(),
        Some(list) => list.iter().filter(|p| p.status == "VIOLATED").map(|p| format!("{} ({})", p.policy, p.evidence)).collect(),
    }
}
