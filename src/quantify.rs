use crate::checks::{CheckResult, CheckStatus};
use crate::discourse::Resolution;
use crate::lens::Finding;
use crate::scanners::Candidate;
use std::collections::HashMap;

pub struct QuantSummary {
    pub verdict: String, // BLOCK|WARN|PASS — design-spec.md §5
    pub score: i64,
    pub score_deductions: Vec<String>,
    pub policy_violation_count: usize,
}

fn severity_penalty(severity: &str) -> i64 {
    match severity {
        "P0" => 25,
        "P1" => 12,
        "P2" => 5,
        "P3" => 1,
        _ => 0,
    }
}

fn score(findings: &[Finding], resolved: &HashMap<String, Resolution>) -> (i64, Vec<String>) {
    let mut total = 100i64;
    let mut deductions = Vec::new();
    for f in findings {
        if resolved.get(&f.id).map(|r| r.status.as_str()) == Some("CONFIRMED") {
            let p = severity_penalty(&f.severity);
            total -= p;
            deductions.push(format!("[{}] candidate={} -{} pts — {}", f.severity, f.candidate_id, p, f.claim));
        }
    }
    (total.max(0), deductions)
}

/// Hard gate (issue #3): a verified-active secret or private-key-shaped candidate must
/// BLOCK no matter what discourse/LLM judgment says. Checked at two levels so an LLM lens
/// can't make the risk disappear by simply not raising a Finding for it:
/// - `candidates`: the raw scanner output (TruffleHog `Verified=true`, private-key rule_id).
/// - `findings`: the same flag propagated onto any Finding lens.rs derived from such a
///   candidate (kept for traceability/reporting).
fn hard_gate_hit(candidates: &[Candidate], findings: &[Finding]) -> bool {
    candidates.iter().any(|c| c.hard_verified) || findings.iter().any(|f| f.hard_verified)
}

/// BLOCK if any confirmed P0 (live-looking credential), or the hard gate fires. WARN if
/// confirmed P1/P2, a policy violation, or a FAIL-status deterministic check. Otherwise PASS.
fn verdict(
    candidates: &[Candidate],
    findings: &[Finding],
    resolved: &HashMap<String, Resolution>,
    checks: &[CheckResult],
    policy_violation_count: usize,
) -> String {
    if hard_gate_hit(candidates, findings) {
        return "BLOCK".to_string();
    }
    let confirmed: Vec<&Finding> = findings.iter().filter(|f| resolved.get(&f.id).map(|r| r.status.as_str()) == Some("CONFIRMED")).collect();
    if confirmed.iter().any(|f| f.severity == "P0") {
        return "BLOCK".to_string();
    }
    if checks.iter().any(|c| c.status == CheckStatus::Fail) {
        return "BLOCK".to_string();
    }
    if confirmed.iter().any(|f| f.severity == "P1" || f.severity == "P2") || policy_violation_count > 0 {
        return "WARN".to_string();
    }
    "PASS".to_string()
}

pub fn summarize(
    candidates: &[Candidate],
    findings: &[Finding],
    resolved: &HashMap<String, Resolution>,
    checks: &[CheckResult],
    policy_violation_count: usize,
) -> QuantSummary {
    let (sc, mut deductions) = score(findings, resolved);
    let v = verdict(candidates, findings, resolved, checks, policy_violation_count);
    if v == "BLOCK" && hard_gate_hit(candidates, findings) {
        deductions.push(
            "[HARD GATE] verified-active secret or private-key material detected — BLOCK regardless of discourse verdict"
                .to_string(),
        );
    }
    QuantSummary { verdict: v, score: sc, score_deductions: deductions, policy_violation_count }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::Candidate;

    fn candidate(hard_verified: bool) -> Candidate {
        Candidate {
            id: "c1".into(),
            file: "f".into(),
            line: 1,
            rule_id: "r".into(),
            masked_preview: "***".into(),
            context_line: "".into(),
            source: "builtin".into(),
            confidence_hint: "high".into(),
            hard_verified,
            fingerprint: "fp".into(),
        }
    }

    #[test]
    fn hard_verified_candidate_forces_block_even_with_no_findings() {
        let candidates = vec![candidate(true)];
        let v = verdict(&candidates, &[], &HashMap::new(), &[], 0);
        assert_eq!(v, "BLOCK");
    }

    #[test]
    fn no_hard_verified_and_nothing_confirmed_is_pass() {
        let candidates = vec![candidate(false)];
        let v = verdict(&candidates, &[], &HashMap::new(), &[], 0);
        assert_eq!(v, "PASS");
    }
}
