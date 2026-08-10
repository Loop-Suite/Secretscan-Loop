use crate::input::Input;
use crate::llm::Llm;
use crate::promptctx::{shared_context, UNTRUSTED_DATA_SYSTEM_NOTE};
use crate::spec::{Lens, Spec};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub const LENS_SYSTEM: &str = "You are one security reviewer triaging secret-scanner candidates before a repo goes public or gets pushed. \
Never repeat a candidate's full raw value — refer to it only via its candidate id and masked preview, exactly as given. \
Only flag a candidate as a finding if you believe it is a real risk (CONFIRMED_SECRET or NEEDS_HUMAN_REVIEW) — \
clearing something as a false positive does not need a finding entry. \
Respond only in the specified JSON schema.";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    #[serde(default, deserialize_with = "crate::llm::null_to_default")]
    pub id: String,
    /// References Input.candidates[].id — never the raw secret.
    pub candidate_id: String,
    pub claim: String,
    pub evidence: String,
    #[serde(default, deserialize_with = "crate::llm::null_to_default")]
    pub impact: String,
    pub severity: String, // P0-P3
    pub label: String,
    /// CONFIRMED_SECRET | FALSE_POSITIVE | NEEDS_HUMAN_REVIEW — this persona's classification.
    pub classification: String,
    #[serde(default = "unknown", deserialize_with = "crate::llm::null_to_unknown")]
    pub confidence: String,
    #[serde(default, deserialize_with = "crate::llm::null_to_default")]
    pub recommendation: String,
    #[serde(default, deserialize_with = "crate::llm::null_to_default")]
    pub lens: String,
    #[serde(default, deserialize_with = "crate::llm::null_to_default")]
    pub reviewer: String,
    /// Propagated from the matching Candidate (scanners.rs) after parsing — never LLM-set.
    /// true => quantify.rs hard gate forces BLOCK regardless of discourse outcome (issue #3).
    #[serde(default)]
    pub hard_verified: bool,
}

fn unknown() -> String {
    "UNKNOWN".to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LensOutput {
    #[serde(default, deserialize_with = "crate::llm::null_to_default")]
    pub findings: Vec<Finding>,
    #[serde(default, deserialize_with = "crate::llm::null_to_default")]
    pub unverified: Vec<String>,
}

fn persona_system(lens: &Lens) -> String {
    let base = if lens.persona_name.is_empty() {
        LENS_SYSTEM.to_string()
    } else {
        format!(
            "You are \"{}\". {}\nDo not agree just to agree — if your judgment differs from a generic reviewer's, say so plainly.\n\n{}",
            lens.persona_name, lens.persona_voice, LENS_SYSTEM
        )
    };
    format!("{base}\n\n{UNTRUSTED_DATA_SYSTEM_NOTE}")
}

pub fn select_lenses(llm: &Llm, spec: &Spec, input: &Input) -> Result<Vec<String>> {
    let optional = spec.optional_lenses();
    if optional.is_empty() {
        return Ok(Vec::new());
    }
    let catalog = optional
        .iter()
        .map(|l| {
            let who = if l.persona_name.is_empty() {
                l.title.clone()
            } else {
                format!("{} ({})", l.title, l.persona_name)
            };
            format!(
                "- id=\"{}\" | {} — selection signal: {}",
                l.id, who, l.signal
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let ctx = shared_context(spec, input);
    let task = format!(
        "# Task\nPick 3-5 review lenses that fit the candidates found in this scan.\n\n\
         ## Lens candidates\n{catalog}\n\n\
         ## Output (JSON only)\n{{\"selected\":[\"id\", ...]}}\n"
    );
    let system = format!("You only select lenses, nothing else. Respond in JSON only.\n\n{UNTRUSTED_DATA_SYSTEM_NOTE}");
    let v = llm
        .json_ctx(Some(&ctx), &task, Some(&system))
        .context("lens selection failed")?;
    let selected: Vec<String> = v
        .get("selected")
        .and_then(|s| s.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let valid: Vec<String> = selected
        .into_iter()
        .filter(|id| spec.lens_by_id(id).is_some())
        .collect();
    anyhow::ensure!(!valid.is_empty(), "lens selection returned nothing valid");
    Ok(valid)
}

fn build_review_task(spec: &Spec, lens_title: &str, lens_guide: &str) -> String {
    format!(
        "# Task\nReview every candidate independently (you cannot see other reviewers' output) from the \"{lens_title}\" perspective.\n\n\
         ## This lens's focus\n{lens_guide}\n\n\
         ## Rules\n\
         - Only produce a finding for candidates you believe are CONFIRMED_SECRET or NEEDS_HUMAN_REVIEW. Skip clean false positives silently.\n\
         - severity: P0 (confirmed live-looking credential) .. P3 (low-confidence entropy match, likely a fixture) — see docs/design-spec.md §5.\n\
         - Never restate the raw secret value — reference candidate_id and quote only the masked preview you were given.\n\
         - label must be exactly one of: {labels}\n\n\
         ## Output (JSON only, no code fences)\n\
         {{\"findings\":[{{\"candidate_id\":\"...\",\"claim\":\"...\",\"evidence\":\"...\",\"impact\":\"...\",\
         \"severity\":\"P0|P1|P2|P3\",\"label\":<one of the allowed values>,\"classification\":\"CONFIRMED_SECRET|NEEDS_HUMAN_REVIEW\",\
         \"confidence\":\"high|medium|low\",\"recommendation\":\"...\"}}],\"unverified\":[\"...\"]}}\n",
        lens_title = lens_title,
        lens_guide = lens_guide,
        labels = spec.labels_prompt(),
    )
}

pub fn review_lens(
    llm: &Llm,
    spec: &Spec,
    input: &Input,
    lens_id: &str,
    round: usize,
) -> Result<LensOutput> {
    let lens = spec
        .lens_by_id(lens_id)
        .ok_or_else(|| anyhow::anyhow!("lens not in spec: {lens_id}"))?;
    let ctx = shared_context(spec, input);
    let task = build_review_task(spec, &lens.title, &lens.guide);
    let system = persona_system(lens);
    let v = llm
        .json_ctx(Some(&ctx), &task, Some(&system))
        .with_context(|| format!("lens review failed: {lens_id}"))?;
    let mut out: LensOutput = serde_json::from_value(v)
        .with_context(|| format!("lens review schema mismatch: {lens_id}"))?;
    let reviewer = if lens.persona_name.is_empty() {
        lens.title.clone()
    } else {
        lens.persona_name.clone()
    };
    for (i, f) in out.findings.iter_mut().enumerate() {
        // Round is embedded so ids stay unique across separate `--prior` runs (see
        // discourse::run's "surface-r{round}-{i}" ids for the same convention) — without it,
        // a prior-round finding carried forward in main.rs could collide with an unrelated
        // finding produced by this same lens in the current round and silently overwrite its
        // resolution.
        f.id = format!("{}-r{}-{}", lens_id, round, i + 1);
        f.lens = lens_id.to_string();
        f.reviewer = reviewer.clone();
        // Never trust the LLM's own claim about verification status — derive strictly from
        // the scanner-reported Candidate it references (issue #3).
        f.hard_verified = input
            .candidates
            .iter()
            .any(|c| c.id == f.candidate_id && c.hard_verified);
    }
    Ok(out)
}
