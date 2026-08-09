use crate::lens::Finding;
use crate::llm::Llm;
use crate::spec::Spec;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// docs/design-spec.md §4: a CHALLENGE only counts if it presents "evidence this is a test
/// fixture/example" or the reverse "evidence this matches a real provider's format" — not a
/// bare gut feeling either way.
pub const DISCOURSE_SYSTEM: &str = "You are a panel cross-examining findings from several independent security reviewers. \
Do not agree or disagree without substance. AGREE only when you cite genuinely new evidence. \
A CHALLENGE only counts if it presents concrete evidence that a candidate is a test fixture/placeholder/example, \
or conversely, concrete evidence that it matches a real provider's credential format — a bare 'this looks risky' or \
'this looks fake' with no evidence is not a valid CHALLENGE, raise it as SURFACE instead. \
Never restate a candidate's raw value — refer to it only by candidate_id and the masked preview already given. \
At least one CHALLENGE is required this round. State confidence (high|medium|low) on every AGREE/CHALLENGE. \
Respond only in the specified JSON schema.";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Move {
    #[serde(rename = "move")]
    pub kind: String,
    pub lens: String,
    pub target: String,
    pub detail: String,
    #[serde(default, deserialize_with = "crate::llm::null_to_default")]
    pub new_evidence: String,
    #[serde(default = "unknown_confidence", deserialize_with = "crate::llm::null_to_unknown")]
    pub confidence: String,
}

fn unknown_confidence() -> String {
    "UNKNOWN".to_string()
}

fn confidence_weight(c: &str) -> f64 {
    match c {
        "high" => 1.0,
        "low" => 0.3,
        _ => 0.6,
    }
}

const VOTE_THRESHOLD: f64 = 0.6;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resolution {
    pub finding_id: String,
    pub status: String, // CONFIRMED|REJECTED|MERGED|UNCERTAIN
    #[serde(default, deserialize_with = "crate::llm::null_to_default")]
    pub merged_into: String,
    #[serde(default, deserialize_with = "crate::llm::null_to_default")]
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct DiscourseRound {
    #[serde(default, deserialize_with = "crate::llm::null_to_default")]
    moves: Vec<Move>,
    #[serde(default, deserialize_with = "crate::llm::null_to_default")]
    resolutions: Vec<Resolution>,
    #[serde(default, deserialize_with = "crate::llm::null_to_default")]
    surfaced: Vec<Finding>,
}

pub struct DiscourseAudit {
    pub round: usize,
    pub moves: Vec<Move>,
}

fn findings_catalog(findings: &[Finding], resolved: &HashMap<String, Resolution>) -> String {
    findings
        .iter()
        .map(|f| {
            let status = resolved.get(&f.id).map(|r| r.status.as_str()).unwrap_or("UNRESOLVED");
            format!(
                "- id={} | candidate={} | severity={} | label={} | classification={} | status={}\n  claim: {}\n  evidence: {}",
                f.id, f.candidate_id, f.severity, f.label, f.classification, status, f.claim, f.evidence
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn build_round_prompt(spec: &Spec, findings: &[Finding], resolved: &HashMap<String, Resolution>, round: usize) -> String {
    format!(
        "# Task\nRun round {round} of discourse. All previously sealed lens findings are now visible.\n\n\
         ## Lenses available as speakers\n{lenses}\n\n\
         ## All findings (only unresolved ones need a new verdict)\n{catalog}\n\n\
         ## Rules\n\
         - Each move is one of AGREE/CHALLENGE/CONNECT/SURFACE, target names a finding id.\n\
         - AGREE: only with new evidence not already cited for that finding. confidence required.\n\
         - CHALLENGE: at least once this round. Must present concrete evidence the candidate is a fixture, OR concrete evidence it matches a real credential format. confidence required.\n\
         - CONNECT: reference two or more finding ids and explain how they relate (e.g. same file, same leaked key reused elsewhere).\n\
         - SURFACE: add a new finding to `surfaced`, with evidence, when no existing finding covers it (including a bare-suspicion challenge that lacked evidence).\n\
         - resolutions: only for UNRESOLVED or previously UNCERTAIN findings: CONFIRMED|REJECTED|MERGED|UNCERTAIN.\n\
         - Never restate a candidate's raw value.\n\n\
         ## Output (JSON only, no code fences)\n\
         {{\"moves\":[{{\"move\":\"AGREE|CHALLENGE|CONNECT|SURFACE\",\"lens\":\"...\",\"target\":\"finding id\",\
         \"detail\":\"...\",\"new_evidence\":\"...\",\"confidence\":\"high|medium|low\"}}],\
         \"resolutions\":[{{\"finding_id\":\"...\",\"status\":\"CONFIRMED|REJECTED|MERGED|UNCERTAIN\",\"merged_into\":\"\",\"reason\":\"...\"}}],\
         \"surfaced\":[{{\"candidate_id\":\"...\",\"claim\":\"...\",\"evidence\":\"...\",\"impact\":\"...\",\
         \"severity\":\"P0|P1|P2|P3\",\"label\":<one of the allowed values>,\"classification\":\"CONFIRMED_SECRET|NEEDS_HUMAN_REVIEW\",\
         \"confidence\":\"high|medium|low\",\"recommendation\":\"...\"}}]}}\n",
        round = round,
        lenses = spec.lenses.iter().map(|l| l.id.as_str()).collect::<Vec<_>>().join(", "),
        catalog = findings_catalog(findings, resolved),
    )
}

pub fn run(llm: &Llm, spec: &Spec, findings: &mut Vec<Finding>, max_rounds: usize) -> Result<(Vec<DiscourseAudit>, HashMap<String, Resolution>)> {
    let max_rounds = max_rounds.max(1);
    let mut resolved: HashMap<String, Resolution> = HashMap::new();
    let mut audit: Vec<DiscourseAudit> = Vec::new();

    for round in 1..=max_rounds {
        let unresolved = findings.iter().any(|f| resolved.get(&f.id).map(|r| r.status == "UNCERTAIN").unwrap_or(true));
        if !unresolved {
            break;
        }

        let mut dr = run_round_call(llm, spec, findings, &resolved, round)?;
        if !dr.moves.iter().any(|m| m.kind == "CHALLENGE") {
            dr = run_round_call(llm, spec, findings, &resolved, round).context("CHALLENGE-missing retry failed")?;
        }

        for (i, sf) in dr.surfaced.iter_mut().enumerate() {
            sf.id = format!("surface-r{}-{}", round, i + 1);
            if sf.lens.is_empty() {
                sf.lens = "discourse".to_string();
            }
        }
        findings.extend(dr.surfaced.clone());

        for r in dr.resolutions.clone() {
            resolved.insert(r.finding_id.clone(), r);
        }

        audit.push(DiscourseAudit { round, moves: dr.moves });
        if round == max_rounds {
            break;
        }
    }

    for f in findings.iter() {
        let still_uncertain = resolved.get(&f.id).map(|r| r.status == "UNCERTAIN").unwrap_or(true);
        if !still_uncertain {
            continue;
        }
        let net: f64 = audit
            .iter()
            .flat_map(|a| a.moves.iter())
            .filter(|m| m.target == f.id)
            .map(|m| match m.kind.as_str() {
                "AGREE" => confidence_weight(&m.confidence),
                "CHALLENGE" => -confidence_weight(&m.confidence),
                _ => 0.0,
            })
            .sum();
        let (status, reason) = if net >= VOTE_THRESHOLD {
            ("CONFIRMED".to_string(), format!("rounds exhausted, confidence-weighted vote confirmed (net={net:.2})"))
        } else if net <= -VOTE_THRESHOLD {
            ("REJECTED".to_string(), format!("rounds exhausted, confidence-weighted vote rejected (net={net:.2})"))
        } else {
            ("UNCERTAIN".to_string(), format!("rounds exhausted, no verdict (net={net:.2}) — needs human review"))
        };
        resolved.insert(f.id.clone(), Resolution { finding_id: f.id.clone(), status, merged_into: String::new(), reason });
    }

    Ok((audit, resolved))
}

fn run_round_call(llm: &Llm, spec: &Spec, findings: &[Finding], resolved: &HashMap<String, Resolution>, round: usize) -> Result<DiscourseRound> {
    let prompt = build_round_prompt(spec, findings, resolved, round);
    let v = llm.json(&prompt, Some(DISCOURSE_SYSTEM)).with_context(|| format!("discourse round {round} failed"))?;
    serde_json::from_value(v).with_context(|| format!("discourse round {round} schema mismatch"))
}
