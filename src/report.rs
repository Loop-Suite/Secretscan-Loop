use crate::checks::CheckResult;
use crate::describe::Describe;
use crate::discourse::{DiscourseAudit, Resolution};
use crate::fixcheck::FixStatus;
use crate::improve::Suggestion;
use crate::input::Input;
use crate::lens::Finding;
use crate::quantify::QuantSummary;
use crate::requirements::PolicyCheck;
use crate::spec::Spec;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

fn severity_rank(s: &str) -> u8 {
    match s {
        "P0" => 0,
        "P1" => 1,
        "P2" => 2,
        "P3" => 3,
        _ => 4,
    }
}

fn checks_table(checks: &[CheckResult]) -> String {
    let mut md = String::new();
    md.push_str("| ID | Check | Status | Evidence |\n|---|---|---|---|\n");
    for c in checks {
        md.push_str(&format!("| {} | {} | {} | {} |\n", c.id, c.title, c.status.label(), c.evidence));
    }
    md
}

pub struct ReportCtx<'a> {
    pub out_dir: &'a Path,
    pub spec: &'a Spec,
    pub input: &'a Input,
    pub selected_lenses: &'a [String],
    pub round: usize,
    pub findings: &'a [Finding],
    pub resolved: &'a HashMap<String, Resolution>,
    pub unverified: &'a [(String, String)],
    pub checks: &'a [CheckResult],
    pub policies: &'a Option<Vec<PolicyCheck>>,
    pub policy_violations: &'a [String],
    pub audit: &'a [DiscourseAudit],
    pub quant: &'a QuantSummary,
    pub fix_results: &'a [FixStatus],
}

pub fn write(ctx: ReportCtx) -> Result<PathBuf> {
    let ReportCtx {
        out_dir, spec, input, selected_lenses, round, findings, resolved, unverified,
        checks, policies, policy_violations, audit, quant, fix_results,
    } = ctx;

    let mut md = String::new();
    md.push_str(&format!("# Secret scan — {} (round {})\n\n", spec.name, round));
    md.push_str(&format!(
        "**Verdict: {}**  ·  Score: {}/100  ·  {} files scanned · {} raw candidate(s)\n\n",
        quant.verdict, quant.score, input.files_scanned, input.candidates.len()
    ));
    md.push_str(&format!("Selected lenses: {}\n\n", selected_lenses.join(", ")));

    if !fix_results.is_empty() {
        md.push_str("## Compared to prior round\n\n| Finding | Status | Evidence |\n|---|---|---|\n");
        for f in fix_results {
            md.push_str(&format!("| {} | {} | {} |\n", f.finding_id, f.status, f.evidence));
        }
        let rotated = fix_results.iter().filter(|f| f.status == "ROTATED").count();
        if rotated > 0 {
            md.push_str(&format!("\nNote: {rotated} finding(s) marked ROTATED — the string may still be in history, but the credential itself is no longer live.\n"));
        }
        md.push('\n');
    }

    md.push_str("## Deterministic checks\n\n");
    md.push_str(&checks_table(checks));
    md.push('\n');

    md.push_str("## Score summary\n\n");
    if quant.score_deductions.is_empty() {
        md.push_str("- no deductions (no CONFIRMED findings)\n");
    } else {
        md.push_str("- deductions:\n");
        for d in &quant.score_deductions {
            md.push_str(&format!("  - {}\n", d));
        }
    }
    md.push_str(&format!("- policy violations: {}\n\n", quant.policy_violation_count));

    md.push_str("## Policy checklist\n\n");
    match policies {
        None => md.push_str("(no policy_checklist configured — skipped)\n\n"),
        Some(list) if list.is_empty() => md.push_str("(empty checklist)\n\n"),
        Some(list) => {
            md.push_str("| Policy | Status | Evidence |\n|---|---|---|\n");
            for p in list {
                md.push_str(&format!("| {} | {} | {} |\n", p.policy, p.status, p.evidence));
            }
            md.push('\n');
        }
    }
    if !policy_violations.is_empty() {
        md.push_str("### policy_violations\n\n");
        for v in policy_violations {
            md.push_str(&format!("- {}\n", v));
        }
        md.push('\n');
    }

    md.push_str("## Candidates (masked)\n\n");
    if input.candidates.is_empty() {
        md.push_str("(none found)\n\n");
    } else {
        md.push_str("| ID | File:line | Rule | Source | Prior confidence | Masked preview |\n|---|---|---|---|---|---|\n");
        for c in &input.candidates {
            md.push_str(&format!(
                "| {} | {}:{} | {} | {} | {} | `{}` |\n",
                c.id, c.file, c.line, c.rule_id, c.source, c.confidence_hint, c.masked_preview
            ));
        }
        md.push('\n');
    }

    let mut confirmed: Vec<&Finding> = findings.iter().filter(|f| resolved.get(&f.id).map(|r| r.status.as_str()) == Some("CONFIRMED")).collect();
    confirmed.sort_by_key(|f| severity_rank(&f.severity));

    md.push_str("## Findings\n\n");
    md.push_str(&format!("allowed labels: {}\n\n", spec.labels_prompt()));
    md.push_str("| ID | Priority | Classification | Label | Lens | Reviewer | Candidate | Claim | Recommendation | Discourse result |\n|---|---|---|---|---|---|---|---|---|---|\n");
    for f in &confirmed {
        let r = resolved.get(&f.id);
        let discourse_result = r.map(|r| r.reason.as_str()).unwrap_or("");
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            f.id, f.severity, f.classification, f.label, f.lens, f.reviewer, f.candidate_id, f.claim, f.recommendation, discourse_result
        ));
    }
    md.push('\n');

    let rejected: Vec<&Finding> = findings.iter().filter(|f| resolved.get(&f.id).map(|r| r.status.as_str()) == Some("REJECTED")).collect();
    if !rejected.is_empty() {
        md.push_str("### Rejected candidates (deemed false positive)\n\n");
        for f in &rejected {
            let reason = resolved.get(&f.id).map(|r| r.reason.as_str()).unwrap_or("");
            md.push_str(&format!("- {} (candidate={}) — {}\n", f.id, f.candidate_id, reason));
        }
        md.push('\n');
    }

    if !unverified.is_empty() {
        md.push_str("### Needs more evidence (not promoted to a finding)\n\n");
        for (lens_id, item) in unverified {
            md.push_str(&format!("- [{}] {}\n", lens_id, item));
        }
        md.push('\n');
    }

    md.push_str("## Discourse audit\n\n");
    md.push_str("| Round | Move | Lens | Target | Detail | New evidence |\n|---|---|---|---|---|---|\n");
    for a in audit {
        for m in &a.moves {
            md.push_str(&format!("| {} | {} | {} | {} | {} | {} |\n", a.round, m.kind, m.lens, m.target, m.detail, m.new_evidence));
        }
    }

    let path = out_dir.join("report.md");
    std::fs::write(&path, md).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

pub fn write_describe(out_dir: &Path, d: &Describe) -> Result<PathBuf> {
    let mut md = String::new();
    md.push_str(&format!("# {}\n\n{}\n\n", d.title, d.summary));
    md.push_str("## Risk highlights\n\n");
    for w in &d.risk_highlights {
        md.push_str(&format!("- {}\n", w));
    }
    md.push_str(&format!("\n## Labels\n\n{}\n\n", d.labels.join(", ")));
    md.push_str(&format!("## safe_to_publish\n\n{} — {}\n\n", d.safe_to_publish, d.safe_to_publish_note));
    let path = out_dir.join("describe.md");
    std::fs::write(&path, md).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

pub fn write_improve(out_dir: &Path, suggestions: &[Suggestion]) -> Result<PathBuf> {
    let mut md = String::new();
    md.push_str("# Remediation suggestions\n\n");
    if suggestions.is_empty() {
        md.push_str("no suggestions\n");
    }
    for s in suggestions {
        md.push_str(&format!("## {} — {} [{}]\n\n", s.candidate_id, s.one_sentence_summary, s.label));
        md.push_str(&format!("Action: **{}**\n\n{}\n\n", s.action, s.suggestion_content));
        md.push_str(&format!("```bash\n{}\n```\n\n", s.command_snippet));
    }
    let path = out_dir.join("improve.md");
    std::fs::write(&path, md).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}
