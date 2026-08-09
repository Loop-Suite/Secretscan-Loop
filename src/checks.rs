//! Deterministic (no-LLM) policy checks. Mirrors codereview-loop's policy.rs role:
//! binary pass/fail gates that don't need judgment. Candidate detection itself lives in
//! scanners.rs (that's the domain-specific "semgrep-equivalent" — see design-spec.md §1).

use serde::Serialize;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
    NotApplicable,
    NotConfigured,
}

impl CheckStatus {
    pub fn label(&self) -> &'static str {
        match self {
            CheckStatus::Pass => "PASS",
            CheckStatus::Warn => "WARN",
            CheckStatus::Fail => "FAIL",
            CheckStatus::NotApplicable => "N/A",
            CheckStatus::NotConfigured => "NOT_CONFIGURED",
        }
    }
}

pub struct CheckResult {
    pub id: String,
    pub title: String,
    pub status: CheckStatus,
    pub evidence: String,
}

/// Ask git itself whether `pattern` (treated as a candidate path under `target`) would be
/// ignored — resolves comments, negation (`!pattern`), nested/parent .gitignore files, and
/// global excludes the way git actually applies them, instead of a naive substring check.
/// Returns `Some(true/false)` when git could answer, `None` when it couldn't (not a git
/// repo, git not installed, etc.) so the caller can fall back gracefully.
fn check_ignore(target: &Path, pattern: &str) -> Option<bool> {
    let out = Command::new("git")
        .arg("-C")
        .arg(target)
        .arg("check-ignore")
        .arg("-v")
        .arg("--no-index")
        .arg(pattern)
        .output()
        .ok()?;
    match out.status.code() {
        Some(0) => Some(true),  // matched an ignore rule
        Some(1) => Some(false), // no matching rule
        _ => None,              // fatal error (not a git repo, bad path, ...)
    }
}

fn gitignore_coverage_check(target: &Path, required: &[String]) -> CheckResult {
    if required.is_empty() {
        return CheckResult {
            id: "gitignore_coverage".into(),
            title: ".gitignore covers required sensitive-file patterns".into(),
            status: CheckStatus::NotConfigured,
            evidence: "spec.required_gitignore_patterns not set".into(),
        };
    }
    let mut missing: Vec<&String> = Vec::new();
    let mut undetermined = false;
    for p in required {
        match check_ignore(target, p) {
            Some(true) => {}
            Some(false) => missing.push(p),
            None => undetermined = true,
        }
    }
    if undetermined && missing.is_empty() {
        return CheckResult {
            id: "gitignore_coverage".into(),
            title: ".gitignore covers required sensitive-file patterns".into(),
            status: CheckStatus::NotApplicable,
            evidence: "`git check-ignore` unavailable (target is not a git repo, or git is not installed)".into(),
        };
    }
    if missing.is_empty() {
        CheckResult {
            id: "gitignore_coverage".into(),
            title: ".gitignore covers required sensitive-file patterns".into(),
            status: CheckStatus::Pass,
            evidence: format!("all {} required patterns are ignored per `git check-ignore`", required.len()),
        }
    } else {
        CheckResult {
            id: "gitignore_coverage".into(),
            title: ".gitignore covers required sensitive-file patterns".into(),
            status: CheckStatus::Fail,
            evidence: format!(
                "not ignored per `git check-ignore`: {}",
                missing.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            ),
        }
    }
}

/// Uses `git ls-files` (if target is a git repo) to check whether well-known sensitive
/// filenames are actually *tracked* — a local .env that's already gitignored is fine,
/// this only fires on files git would actually push.
fn tracked_sensitive_files_check(target: &Path) -> CheckResult {
    let sensitive_names = [".env", ".env.local", ".env.production", "id_rsa", "id_ed25519", "credentials.json"];
    let sensitive_suffixes = [".pem", ".key", ".p12", ".pfx"];

    let out = Command::new("git").arg("-C").arg(target).arg("ls-files").output();
    let Ok(out) = out else {
        return CheckResult {
            id: "tracked_sensitive_files".into(),
            title: "no sensitive filenames tracked by git".into(),
            status: CheckStatus::NotApplicable,
            evidence: "git not available or target is not a git repo".into(),
        };
    };
    if !out.status.success() {
        return CheckResult {
            id: "tracked_sensitive_files".into(),
            title: "no sensitive filenames tracked by git".into(),
            status: CheckStatus::NotApplicable,
            evidence: "target is not a git repository".into(),
        };
    }
    let listing = String::from_utf8_lossy(&out.stdout);
    let hits: Vec<&str> = listing
        .lines()
        .filter(|l| {
            let base = l.rsplit('/').next().unwrap_or(l);
            sensitive_names.contains(&base) || sensitive_suffixes.iter().any(|s| l.ends_with(s))
        })
        .collect();
    if hits.is_empty() {
        CheckResult {
            id: "tracked_sensitive_files".into(),
            title: "no sensitive filenames tracked by git".into(),
            status: CheckStatus::Pass,
            evidence: "no .env/private-key-shaped filenames in `git ls-files`".into(),
        }
    } else {
        CheckResult {
            id: "tracked_sensitive_files".into(),
            title: "no sensitive filenames tracked by git".into(),
            status: CheckStatus::Fail,
            evidence: format!("tracked: {}", hits.join(", ")),
        }
    }
}

fn candidate_volume_check(candidate_count: usize) -> CheckResult {
    CheckResult {
        id: "candidate_volume".into(),
        title: "raw candidate count before persona triage".into(),
        status: if candidate_count == 0 { CheckStatus::Pass } else { CheckStatus::Warn },
        evidence: format!("{candidate_count} raw candidate(s) from builtin scanner + gitleaks/trufflehog if installed — see Findings for post-triage verdicts"),
    }
}

pub fn run_all(target: &Path, required_gitignore: &[String], candidate_count: usize) -> Vec<CheckResult> {
    vec![
        gitignore_coverage_check(target, required_gitignore),
        tracked_sensitive_files_check(target),
        candidate_volume_check(candidate_count),
    ]
}
