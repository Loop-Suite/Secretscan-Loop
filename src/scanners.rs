//! Candidate detection. Mirrors codereview-loop's semgrep.rs::try_run pattern (optional
//! external tool + graceful fallback if not on PATH), but the output here becomes the
//! **input to persona review**, not just a report table — that's the domain-specific twist
//! (docs/design-spec.md §1).
//!
//! SAFETY: nothing in this module ever returns, logs, or serializes the raw secret value.
//! Every Candidate only carries a masked preview, plus a one-way `fingerprint` (normalized
//! path + line + a keyed hash of the secret — see `secret_digest`; deliberately *not*
//! rule_id, see issue #6 — two rules/sources matching the identical secret text at the
//! identical location are the same finding regardless of what each one calls itself). The
//! keyed hash uses a fresh random key generated once per `scan_all()` call, so it is not
//! reversible and not comparable across separate runs — it only exists to dedup findings
//! that the 3 scanners (builtin/gitleaks/trufflehog) all reported within *this* run.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Candidate {
    pub id: String,
    pub file: String,
    pub line: usize,
    pub rule_id: String,
    /// Masked preview only — e.g. "AKIA****...****3F2Q (len=20)". Never the raw value.
    pub masked_preview: String,
    /// The containing line, with every matched secret substring found on that line
    /// (across all rules/sources sharing that line) replaced by its masked form.
    pub context_line: String,
    pub source: String,          // "builtin" | "gitleaks" | "trufflehog"
    pub confidence_hint: String, // "high" | "medium" | "low" — rule-author's prior, not a verdict
    /// true => this candidate must BLOCK regardless of LLM/discourse judgment (quantify.rs
    /// hard gate): TruffleHog live-verified secrets, or any private-key-shaped rule match.
    #[serde(default)]
    pub hard_verified: bool,
    /// Dedup key: normalized relative path + line + keyed hash of the raw secret. Deliberately
    /// excludes rule_id (issue #6) so the same secret matched by two different rules/sources
    /// still dedups. Never the raw secret itself — see module doc.
    #[serde(default)]
    pub fingerprint: String,
}

/// Which slice of the repo to scan. Filesystem (default) preserves prior behavior;
/// the git-aware modes let gitleaks/trufflehog look at staged changes, a commit range,
/// or full history instead of only what's currently on disk.
#[derive(Debug, Clone, PartialEq)]
pub enum ScanScope {
    Filesystem,
    Staged,
    Range(String), // "BASE..HEAD"
    History,
}

impl Default for ScanScope {
    fn default() -> Self {
        ScanScope::Filesystem
    }
}

/// Show enough of a token to identify its *type* and length without exposing the secret.
/// Prefix length scales with total length; middle is always masked. docs/design-spec.md §3:
/// "exposing only the first 4 and last 4 characters" — the lower clamp bound must stay small
/// (1, not 3) so lengths just above the `n <= 8` cutoff don't reveal a disproportionate
/// fraction of the secret (issue #5: a floor of 3 revealed up to 6/9 = 67% of a 9-char value).
fn mask(raw: &str) -> String {
    let n = raw.chars().count();
    if n <= 8 {
        return "*".repeat(n.max(1));
    }
    let keep = (n / 5).clamp(1, 6);
    let chars: Vec<char> = raw.chars().collect();
    let head: String = chars[..keep].iter().collect();
    let tail: String = chars[n - keep..].iter().collect();
    format!(
        "{head}{}...{}{tail} (len={n})",
        "*".repeat(4),
        "*".repeat(4)
    )
}

/// Mask every occurrence of every raw value in `raws` inside `line`.
///
/// This works on byte *ranges*, not string content: find every occurrence of every raw
/// value in the original `line`, merge overlapping/adjacent ranges, then rebuild the line
/// in one left-to-right pass, masking each merged range as a block. Range-based merging is
/// required (issue #15) — an earlier content-based approach (sort raws longest-first, then
/// repeatedly `contains`/`replace` each one against a mutating `result` string) could leave
/// a secret almost entirely unmasked whenever two raw values *partially* overlapped without
/// either containing the other: masking the longer one first consumes the characters it
/// shares with the shorter one, so the shorter one's exact text no longer appears in
/// `result` and its `.contains()` check silently fails, skipping its `.replace()` entirely.
/// Working on ranges instead means every character covered by *any* match is always masked,
/// regardless of how many secrets overlap or how.
fn mask_line_all(line: &str, raws: &[&str]) -> String {
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for raw in raws.iter().filter(|s| !s.is_empty()) {
        let mut cursor = 0usize;
        while let Some(pos) = line[cursor..].find(raw) {
            let start = cursor + pos;
            let end = start + raw.len();
            ranges.push((start, end));
            // Advance by one *character* (not one byte) past `start` so overlapping
            // self-matches are still caught, without landing mid-character on multi-byte
            // UTF-8 input (`line[cursor..]` below would panic on a non-boundary index).
            let step = line[start..]
                .chars()
                .next()
                .map(|c| c.len_utf8())
                .unwrap_or(1);
            cursor = start + step;
        }
    }
    if ranges.is_empty() {
        return line.to_string();
    }
    ranges.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }

    let mut result = String::with_capacity(line.len());
    let mut cursor = 0usize;
    for (start, end) in merged {
        result.push_str(&line[cursor..start]);
        result.push_str(&mask(&line[start..end]));
        cursor = end;
    }
    result.push_str(&line[cursor..]);
    result
}

/// Keyed digest of a raw secret value, used only as a dedup fingerprint component.
/// `key` is generated fresh per `scan_all()` call (see there) so this is a one-way,
/// per-run-only value — not persisted, not comparable across runs, and not reversible
/// back to the secret.
fn secret_digest(key: &RandomState, secret: &str) -> u64 {
    let mut h = key.build_hasher();
    secret.hash(&mut h);
    h.finish()
}

/// Normalize a scanner-reported file path to be relative to `target`, using forward
/// slashes, for stable fingerprinting regardless of which scanner reported it or whether
/// it used an absolute or relative path.
fn normalize_rel_path(target: &Path, file: &str) -> String {
    let f = file.replace('\\', "/");
    let target_str = target.to_string_lossy().replace('\\', "/");
    let stripped = f
        .strip_prefix(&format!("{target_str}/"))
        .or_else(|| f.strip_prefix(&target_str))
        .unwrap_or(&f);
    stripped
        .trim_start_matches('/')
        .trim_start_matches("./")
        .to_string()
}

/// Deliberately excludes rule_id — see issue #6 and the module/struct docs above.
fn fingerprint(key: &RandomState, rel_path: &str, line: usize, secret: &str) -> String {
    format!("{}|{}|{:016x}", rel_path, line, secret_digest(key, secret))
}

/// True for TruffleHog-verified secrets or any rule/detector whose id names a private-key
/// family — these must hard-BLOCK (see quantify.rs), never PASS purely on LLM discourse.
fn is_private_key_rule(rule_id: &str) -> bool {
    let norm: String = rule_id
        .to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect();
    norm.contains("privatekey")
}

struct Rule {
    id: &'static str,
    re: &'static str,
    confidence: &'static str,
    /// Which capture group holds the *actual secret value* (0 = the whole match).
    /// Only `generic_high_entropy_assignment` wraps the secret in its own group — its
    /// full match also includes the keyword/operator/quotes prefix, which must never be
    /// treated as "the secret" for masking/length purposes (see `builtin_scan`).
    secret_group: usize,
}

/// Known-prefix rules first (high confidence, low false-positive), then a generic
/// high-entropy-assignment fallback (lower confidence, needs persona judgment more).
fn rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "aws_access_key_id",
            re: r"AKIA[0-9A-Z]{16}",
            confidence: "high",
            secret_group: 0,
        },
        Rule {
            id: "github_token",
            re: r"gh[pousr]_[A-Za-z0-9]{36,255}",
            confidence: "high",
            secret_group: 0,
        },
        Rule {
            id: "anthropic_api_key",
            re: r"sk-ant-[A-Za-z0-9_-]{20,}",
            confidence: "high",
            secret_group: 0,
        },
        Rule {
            id: "openai_api_key",
            re: r"sk-[A-Za-z0-9]{20,}(?:T3BlbkFJ[A-Za-z0-9]{20,})?",
            confidence: "high",
            secret_group: 0,
        },
        Rule {
            id: "slack_token",
            re: r"xox[baprs]-[A-Za-z0-9-]{10,}",
            confidence: "high",
            secret_group: 0,
        },
        Rule {
            id: "google_api_key",
            re: r"AIza[0-9A-Za-z_-]{35}",
            confidence: "high",
            secret_group: 0,
        },
        Rule {
            id: "stripe_key",
            // Note: `(live|test)` is a capture group but it is NOT the secret — the secret
            // is the whole match, so this stays secret_group: 0 (see doc on Rule::secret_group).
            re: r"[sp]k_(live|test)_[A-Za-z0-9]{16,}",
            confidence: "high",
            secret_group: 0,
        },
        Rule {
            id: "tavily_api_key",
            re: r"tvly-[A-Za-z0-9_-]{20,}",
            confidence: "high",
            secret_group: 0,
        },
        Rule {
            id: "private_key_block",
            re: r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
            confidence: "high",
            secret_group: 0,
        },
        Rule {
            id: "slack_webhook",
            re: r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+",
            confidence: "medium",
            secret_group: 0,
        },
        Rule {
            id: "generic_high_entropy_assignment",
            re: r#"(?i)(api[_-]?key|secret|token|password|passwd|access[_-]?key)\s*[:=]\s*['"]([A-Za-z0-9_\-/+=]{20,})['"]"#,
            confidence: "low",
            // Group 2 is the quoted value itself — group 0 (whole match) also drags in the
            // keyword, operator and quotes, which must never be fed to mask()/fingerprint().
            secret_group: 2,
        },
    ]
}

const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
];

/// `path` must already be relative to the scan root — see call site in `builtin_scan`.
/// (Issue #7: matching against an absolute/full path could false-positive-skip an entire
/// repo if some ancestor directory happened to be named e.g. "build".)
/// `pub(crate)` so `input::count_files` can apply the same skip list — see that call site.
pub(crate) fn should_skip(path: &Path) -> bool {
    path.components().any(|c| {
        let s = c.as_os_str().to_string_lossy();
        SKIP_DIRS.iter().any(|d| s == *d)
    })
}

fn is_probably_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(1024).any(|b| *b == 0)
}

/// Built-in fallback scanner — always runs regardless of gitleaks/trufflehog availability.
/// Walks the target directory, skips build/vendor dirs (relative to `target`) and binary files.
pub fn builtin_scan(target: &Path, key: &RandomState) -> Vec<Candidate> {
    let compiled: Vec<(Regex, &Rule)> = rules()
        .into_iter()
        .filter_map(|r| {
            Regex::new(r.re)
                .ok()
                .map(|re| (re, Box::leak(Box::new(r)) as &Rule))
        })
        .collect();
    let mut out = Vec::new();
    let mut counter = 0usize;

    for entry in WalkDir::new(target).into_iter().filter_map(|e| e.ok()) {
        let rel_path = entry.path().strip_prefix(target).unwrap_or(entry.path());
        if !entry.file_type().is_file() || should_skip(rel_path) {
            continue;
        }
        // Check size via metadata *before* reading — issue #16: reading the whole file
        // first and only checking `bytes.len()` afterward defeats the cap's purpose,
        // since a multi-GB file would already be fully loaded into memory by then.
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if meta.len() > 5_000_000 {
            continue;
        }
        let Ok(bytes) = std::fs::read(entry.path()) else {
            continue;
        };
        if is_probably_binary(&bytes) {
            continue;
        }
        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };
        let rel = rel_path.to_string_lossy().to_string();

        for (line_no, line) in text.lines().enumerate() {
            // Collect every match from every rule on this line first, so masking (below)
            // can hide *all* of them, not just the one belonging to the rule currently
            // producing a Candidate (issue #4).
            let mut line_matches: Vec<(&Rule, &str)> = Vec::new();
            for (re, rule) in &compiled {
                for cap in re.captures_iter(line) {
                    // Use the rule's designated secret group, not the whole match — for
                    // generic_high_entropy_assignment the whole match also contains the
                    // keyword/operator/quotes, which must never be treated as "the secret"
                    // (see Rule::secret_group doc).
                    if let Some(m) = cap.get(rule.secret_group).or_else(|| cap.get(0)) {
                        line_matches.push((rule, m.as_str()));
                    }
                }
            }
            if line_matches.is_empty() {
                continue;
            }
            let raws: Vec<&str> = line_matches.iter().map(|(_, s)| *s).collect();
            let masked_context = mask_line_all(line.trim(), &raws);

            for (rule, raw) in &line_matches {
                counter += 1;
                out.push(Candidate {
                    id: format!("builtin-{counter}"),
                    file: rel.clone(),
                    line: line_no + 1,
                    rule_id: rule.id.to_string(),
                    masked_preview: mask(raw),
                    context_line: masked_context.clone(),
                    source: "builtin".to_string(),
                    confidence_hint: rule.confidence.to_string(),
                    hard_verified: is_private_key_rule(rule.id),
                    fingerprint: fingerprint(key, &rel, line_no + 1, raw),
                });
            }
        }
    }
    out
}

fn which(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        let full = dir.join(bin);
        if full.is_file() {
            Some(full)
        } else {
            None
        }
    })
}

/// Files staged in the index (`git diff --cached --name-only`), relative to `target`.
/// Empty if `target` isn't a git repo or nothing is staged.
fn staged_files(target: &Path) -> Vec<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(target)
        .arg("diff")
        .arg("--cached")
        .arg("--name-only")
        .arg("--diff-filter=ACMR")
        .output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

fn parse_range(range: &str) -> (String, String) {
    match range.split_once("..") {
        Some((a, b)) if !b.is_empty() => (a.to_string(), b.to_string()),
        Some((a, _)) => (a.to_string(), "HEAD".to_string()),
        None => (range.to_string(), "HEAD".to_string()),
    }
}

/// gitleaks, if installed: proven regex+entropy ruleset. We only take file/line/rule id/
/// a short masked slice of its own "Match" field — never the "Secret" field's raw form.
///
/// Scope decides the gitleaks subcommand/mode:
/// - Filesystem (default): `detect --no-git` — working tree only, same as before.
/// - Staged: `protect --staged` — only what's about to be committed.
/// - Range: `detect --log-opts="BASE..HEAD"` — commits in that range.
/// - History: `detect` (git mode, no --no-git) — full repo history.
pub fn try_gitleaks(target: &Path, scope: &ScanScope, key: &RandomState) -> Option<Vec<Candidate>> {
    let bin = which("gitleaks")?;
    let mut cmd = Command::new(bin);
    match scope {
        ScanScope::Filesystem => {
            cmd.arg("detect")
                .arg("--no-git")
                .arg("--source")
                .arg(target);
        }
        ScanScope::Staged => {
            cmd.arg("protect")
                .arg("--staged")
                .arg("--source")
                .arg(target);
        }
        ScanScope::Range(range) => {
            cmd.arg("detect")
                .arg("--source")
                .arg(target)
                .arg("--log-opts")
                .arg(range);
        }
        ScanScope::History => {
            cmd.arg("detect").arg("--source").arg(target);
        }
    }
    cmd.arg("--report-format")
        .arg("json")
        .arg("--report-path")
        .arg("/dev/stdout")
        .arg("--exit-code")
        .arg("0");
    let out = cmd.output().ok()?;
    let arr: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    let items = arr.as_array()?;

    struct Raw {
        file: String,
        line: usize,
        rule: String,
        secret: String,
        raw_match: String,
    }
    let raws: Vec<Raw> = items
        .iter()
        .map(|item| {
            let file = item
                .get("File")
                .and_then(|v| v.as_str())
                .unwrap_or("UNKNOWN")
                .to_string();
            let line = item.get("StartLine").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let rule = item
                .get("RuleID")
                .and_then(|v| v.as_str())
                .unwrap_or("gitleaks-rule")
                .to_string();
            let secret = item
                .get("Secret")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let raw_match = item
                .get("Match")
                .and_then(|v| v.as_str())
                .unwrap_or(&secret)
                .to_string();
            Raw {
                file,
                line,
                rule,
                secret,
                raw_match,
            }
        })
        .collect();

    // Group by (file, line) so every candidate on that line masks *all* secrets found
    // there, not just its own (issue #4).
    let mut by_loc: HashMap<(String, usize), Vec<String>> = HashMap::new();
    for r in &raws {
        by_loc
            .entry((r.file.clone(), r.line))
            .or_default()
            .push(r.secret.clone());
    }

    let mut result = Vec::new();
    for (i, r) in raws.into_iter().enumerate() {
        let secrets_here = by_loc
            .get(&(r.file.clone(), r.line))
            .cloned()
            .unwrap_or_default();
        let raw_refs: Vec<&str> = secrets_here.iter().map(|s| s.as_str()).collect();
        let masked_context = mask_line_all(&r.raw_match, &raw_refs);
        let rel = normalize_rel_path(target, &r.file);
        result.push(Candidate {
            id: format!("gitleaks-{}", i + 1),
            file: r.file,
            line: r.line,
            rule_id: r.rule.clone(),
            masked_preview: mask(&r.secret),
            context_line: masked_context,
            source: "gitleaks".to_string(),
            confidence_hint: "high".to_string(), // gitleaks default rules are curated, not raw entropy
            hard_verified: is_private_key_rule(&r.rule),
            fingerprint: fingerprint(key, &rel, r.line, &r.secret),
        });
    }
    Some(result)
}

fn trufflehog_file_and_line(v: &serde_json::Value) -> (String, usize) {
    let data = v.get("SourceMetadata").and_then(|m| m.get("Data"));
    let fs = data.and_then(|d| d.get("Filesystem"));
    let git = data.and_then(|d| d.get("Git"));
    let file = fs
        .and_then(|f| f.get("file"))
        .and_then(|x| x.as_str())
        .or_else(|| git.and_then(|g| g.get("file")).and_then(|x| x.as_str()))
        .unwrap_or("UNKNOWN")
        .to_string();
    let line = fs
        .and_then(|f| f.get("line"))
        .and_then(|x| x.as_u64())
        .or_else(|| git.and_then(|g| g.get("line")).and_then(|x| x.as_u64()))
        .unwrap_or(0) as usize;
    (file, line)
}

/// trufflehog, if installed: JSON lines output.
///
/// Scope decides the trufflehog subcommand:
/// - Filesystem (default): `filesystem <target>` — working tree only, same as before.
/// - Staged: `filesystem <staged files>` — restricted to `git diff --cached --name-only`.
///   (trufflehog has no native "staged" mode; this is the closest equivalent.)
/// - Range: `git file://<target> --since-commit BASE --branch HEAD`.
/// - History: `git file://<target>` — full default-branch history.
pub fn try_trufflehog(
    target: &Path,
    scope: &ScanScope,
    key: &RandomState,
) -> Option<Vec<Candidate>> {
    let bin = which("trufflehog")?;
    let mut cmd = Command::new(bin);
    match scope {
        ScanScope::Filesystem => {
            cmd.arg("filesystem").arg(target);
        }
        ScanScope::Staged => {
            let staged = staged_files(target);
            if staged.is_empty() {
                return Some(Vec::new());
            }
            cmd.arg("filesystem");
            for f in &staged {
                cmd.arg(target.join(f));
            }
        }
        ScanScope::Range(range) => {
            let (base, head) = parse_range(range);
            cmd.arg("git")
                .arg(format!("file://{}", target.display()))
                .arg("--since-commit")
                .arg(base)
                .arg("--branch")
                .arg(head);
        }
        ScanScope::History => {
            cmd.arg("git").arg(format!("file://{}", target.display()));
        }
    }
    cmd.arg("--json").arg("--no-update");
    let out = cmd.output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut result = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let detector = v
            .get("DetectorName")
            .and_then(|x| x.as_str())
            .unwrap_or("trufflehog-rule")
            .to_string();
        let raw = v.get("Raw").and_then(|x| x.as_str()).unwrap_or("");
        let (file, tline) = trufflehog_file_and_line(&v);
        let verified = v.get("Verified").and_then(|x| x.as_bool()).unwrap_or(false);
        let rel = normalize_rel_path(target, &file);
        result.push(Candidate {
            id: format!("trufflehog-{}", i + 1),
            file,
            line: tline, // trufflehog filesystem mode doesn't always report line numbers
            rule_id: detector.clone(),
            masked_preview: mask(raw),
            context_line: format!("(trufflehog verified={verified})"),
            source: "trufflehog".to_string(),
            // TruffleHog already did live verification — treat verified hits as high confidence,
            // unverified as medium (still pattern-matched, just not confirmed live).
            confidence_hint: if verified {
                "high".to_string()
            } else {
                "medium".to_string()
            },
            hard_verified: verified || is_private_key_rule(&detector),
            fingerprint: fingerprint(key, &rel, tline, raw),
        });
    }
    Some(result)
}

/// Keeps the first-seen candidate per fingerprint, but ORs `hard_verified` across every
/// candidate sharing that fingerprint first (issue #6) — otherwise, now that dedup collapses
/// across rules/sources more aggressively (rule_id no longer part of the fingerprint), a
/// duplicate that happened to be hard-verified (TruffleHog `Verified=true`, or a
/// private-key-shaped rule/detector) could have that signal silently dropped just because a
/// lower-priority duplicate for the same secret was inserted first, defeating the
/// quantify.rs hard-block gate.
fn dedup_by_fingerprint(candidates: Vec<Candidate>) -> Vec<Candidate> {
    let mut hard_verified_by_fp: HashMap<String, bool> = HashMap::new();
    for c in &candidates {
        let entry = hard_verified_by_fp
            .entry(c.fingerprint.clone())
            .or_default();
        *entry = *entry || c.hard_verified;
    }
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::with_capacity(candidates.len());
    for mut c in candidates {
        if seen.insert(c.fingerprint.clone()) {
            c.hard_verified = hard_verified_by_fp
                .get(&c.fingerprint)
                .copied()
                .unwrap_or(c.hard_verified);
            out.push(c);
        }
    }
    out
}

/// Merge all available sources. External tools run only if present on PATH; builtin always runs
/// so the tool is fully functional with zero external dependencies. Results sharing the same
/// (path, line, secret) fingerprint — regardless of which rule/source reported them, see
/// issue #6 — are deduped, keeping the first occurrence (builtin, then gitleaks, then
/// trufflehog) with `hard_verified` OR'd in from every duplicate.
pub fn scan_all(target: &Path, scope: &ScanScope) -> Vec<Candidate> {
    let key = RandomState::new();
    let mut all = builtin_scan(target, &key);
    if let Some(mut gl) = try_gitleaks(target, scope, &key) {
        all.append(&mut gl);
    }
    if let Some(mut th) = try_trufflehog(target, scope, &key) {
        all.append(&mut th);
    }
    dedup_by_fingerprint(all)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_line_all_masks_every_secret_on_the_line() {
        let line = r#"aws="AKIAABCDEFGHIJKLMNOP" gh="ghp_0123456789012345678901234567890123456""#;
        let masked = mask_line_all(
            line,
            &[
                "AKIAABCDEFGHIJKLMNOP",
                "ghp_0123456789012345678901234567890123456",
            ],
        );
        assert!(!masked.contains("AKIAABCDEFGHIJKLMNOP"));
        assert!(!masked.contains("ghp_0123456789012345678901234567890123456"));
    }

    #[test]
    fn should_skip_is_relative_to_scan_root() {
        // A path like "target/src/lib.rs" is a normal build-dir hit...
        assert!(should_skip(Path::new("target/src/lib.rs")));
        // ...but a repo whose own name happens to contain "build" must not be excluded
        // wholesale once the caller passes a scan-root-relative path (issue #7).
        assert!(!should_skip(Path::new("src/lib.rs")));
    }

    #[test]
    fn is_private_key_rule_matches_known_shapes() {
        assert!(is_private_key_rule("private_key_block"));
        assert!(is_private_key_rule("private-key"));
        assert!(is_private_key_rule("PrivateKey"));
        assert!(!is_private_key_rule("aws_access_key_id"));
    }

    #[test]
    fn fingerprint_dedups_same_secret_regardless_of_rule_id() {
        // issue #6: fingerprint must not include rule_id, so the same secret at the same
        // location dedups even when two different rules/sources reported it under different
        // names (builtin `aws_access_key_id` vs. gitleaks `aws-access-token` vs. trufflehog
        // `AWS`, for example).
        let key = RandomState::new();
        let a = fingerprint(&key, "src/main.rs", 10, "AKIAABCDEFGHIJKLMNOP");
        let b = fingerprint(&key, "src/main.rs", 10, "AKIAABCDEFGHIJKLMNOP");
        let c = fingerprint(&key, "src/main.rs", 11, "AKIAABCDEFGHIJKLMNOP");
        let d = fingerprint(&key, "src/main.rs", 10, "AKIAZZZZZZZZZZZZZZZZ");
        assert_eq!(a, b);
        assert_ne!(a, c, "different line must not collide");
        assert_ne!(a, d, "different secret must not collide");
    }

    #[test]
    fn dedup_collapses_same_secret_matched_by_two_different_rules() {
        // issue #6, reproduced entirely within the builtin scanner (no gitleaks/trufflehog
        // needed): a line like `aws_access_key = "AKIA..."` matches both the specific
        // `aws_access_key_id` rule and the generic `generic_high_entropy_assignment` fallback
        // on the identical secret text — before the fix these produced two undeduped
        // Candidates for the same real secret.
        let dir = std::env::temp_dir().join(format!(
            "secretscan_dedup_test_{}_{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("config.env"),
            "aws_access_key = \"AKIAABCDEFGHIJKLMNOP\"\n",
        )
        .unwrap();
        let key = RandomState::new();
        let raw = builtin_scan(&dir, &key);
        assert_eq!(raw.len(), 2, "expected both rules to match: {raw:?}");
        let deduped = dedup_by_fingerprint(raw);
        assert_eq!(
            deduped.len(),
            1,
            "the same secret at the same location must dedup to one candidate"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dedup_preserves_hard_verified_from_any_duplicate() {
        // A duplicate's hard_verified=true must survive even if the candidate kept (first
        // inserted) for that fingerprint was itself hard_verified=false — otherwise merging
        // duplicates more aggressively (dropping rule_id) could silently defeat the
        // quantify.rs hard-block gate.
        fn candidate(hard_verified: bool) -> Candidate {
            Candidate {
                id: "c".into(),
                file: "f".into(),
                line: 1,
                rule_id: "r".into(),
                masked_preview: "***".into(),
                context_line: String::new(),
                source: "builtin".into(),
                confidence_hint: "low".into(),
                hard_verified,
                fingerprint: "same-fp".into(),
            }
        }
        let out = dedup_by_fingerprint(vec![candidate(false), candidate(true)]);
        assert_eq!(out.len(), 1);
        assert!(
            out[0].hard_verified,
            "hard_verified must be OR'd across duplicates"
        );
    }

    #[test]
    fn mask_never_reveals_more_than_40_percent_for_short_secrets() {
        // issue #5: with the clamp(3, 6) floor, a 9-char secret revealed 6/9 = 67% of its
        // characters. After the fix (clamp(1, 6)) the ~40% ceiling that already applied at
        // n>=15 must hold uniformly down to n=9 too.
        for n in 9..=64usize {
            let raw: String = (0..n).map(|i| (b'a' + (i % 26) as u8) as char).collect();
            let masked = mask(&raw);
            assert!(
                !masked.contains(&raw),
                "n={n}: raw value must never appear whole"
            );
            let keep = (n / 5).clamp(1, 6);
            let revealed = keep * 2;
            assert!(
                revealed * 5 <= n * 2 + 1, // revealed/n <= 0.4 (+rounding slack)
                "n={n}: revealed {revealed}/{n} exceeds the 40% ceiling ({masked})"
            );
        }
    }

    // --- issue #15: partial-overlap masking leak ---------------------------------------

    #[test]
    fn mask_line_all_does_not_leak_on_partial_overlap() {
        // Two "secrets" whose spans partially overlap without either containing the
        // other. Before the fix, masking the longer one first consumed the characters it
        // shares with the shorter one, so the shorter one's `.contains()` check silently
        // failed and its (mostly non-overlapping) text was left in plaintext.
        let line = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let raw1 = &line[0..20]; // "0123456789ABCDEFGHIJ"
        let raw2 = &line[15..36]; // "FGHIJKLMNOPQRSTUVWXYZ" — overlaps raw1 at [15,20)
        let masked = mask_line_all(line, &[raw1, raw2]);
        assert!(
            !masked.contains("0123456789ABCDE"),
            "raw1's non-overlapping prefix must not survive: {masked}"
        );
        assert!(!masked.contains(raw1), "{masked}");
        assert!(!masked.contains(raw2), "{masked}");
    }

    #[test]
    fn mask_line_all_handles_three_way_chained_overlap() {
        // A chain of three pairwise-overlapping-but-not-nested secrets (A overlaps B,
        // B overlaps C, A and C don't touch) must all end up merged into one masked run
        // with nothing left unmasked.
        let line = "AAAAAAAAAABBBBBBBBBBCCCCCCCCCCDDDDDDDDDD"; // 40 chars, 10 each
        let a = &line[0..15]; // "AAAAAAAAAABBBBB"  (10 A's + 5 B's)
        let b = &line[10..25]; // "BBBBBBBBBBCCCCC" (10 B's + 5 C's)
        let c = &line[20..35]; // "CCCCCCCCCCDDDDD" (10 C's + 5 D's)
        let masked = mask_line_all(line, &[a, b, c]);
        assert!(!masked.contains(a) && !masked.contains(b) && !masked.contains(c));
        // The untouched tail (last 5 'D's, positions 35..40) must remain visible —
        // proves the fix doesn't over-mask the whole line, only the covered ranges.
        assert!(masked.ends_with("DDDDD"), "{masked}");
    }

    #[test]
    fn mask_handles_unicode_secret_without_panicking_or_leaking() {
        // Multi-byte UTF-8 (Korean + emoji) must not panic on char-boundary slicing and
        // must never reveal the value whole.
        let raw = "비밀번호값입니다🔥emoji-mixed-secret-value-1234567890";
        let masked = mask(raw);
        assert!(!masked.contains(raw));
        let line = format!("token = \"{raw}\"");
        let masked_line = mask_line_all(&line, &[raw]);
        assert!(!masked_line.contains(raw), "{masked_line}");
    }

    #[test]
    fn mask_fully_masks_very_short_secrets() {
        for raw in ["", "a", "ab", "1234567", "12345678"] {
            let masked = mask(raw);
            if !raw.is_empty() {
                assert!(!masked.contains(raw), "raw={raw:?} masked={masked}");
            }
            assert!(masked.chars().all(|c| c == '*'), "masked={masked}");
        }
    }

    #[test]
    fn mask_handles_very_long_secret_without_panicking() {
        let raw: String = (0..200_000)
            .map(|i| (b'a' + (i % 26) as u8) as char)
            .collect();
        let masked = mask(&raw);
        assert!(!masked.contains(&raw));
        // clamp(1, 6) caps reveal at 6 head + 6 tail regardless of length.
        assert!(
            masked.starts_with(&raw[..6]),
            "{}",
            &masked[..20.min(masked.len())]
        );
    }

    fn unique_test_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "secretscan_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // --- issue #16: full-file read before size-cap check ---------------------------------

    #[test]
    fn builtin_scan_skips_file_over_size_cap() {
        // issue #16: a file over the 5MB cap must be skipped, and skipped based on its
        // metadata size — not only after the fact via `bytes.len()`. Put a real secret
        // right at the end so a regression back to "read first, size-check after" would
        // still (accidentally) find it; the fixed version must skip it before ever
        // reading, so it must never appear in the output either way.
        let dir = unique_test_dir("huge_file");
        let mut content = "x".repeat(5_000_001);
        content.push_str("\naws_key = \"AKIAABCDEFGHIJKLMNOP\"\n");
        std::fs::write(dir.join("huge.txt"), &content).unwrap();
        let key = RandomState::new();
        let out = builtin_scan(&dir, &key);
        assert!(
            out.is_empty(),
            "file over the size cap must be skipped: {out:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    // --- broader edge-case coverage --------------------------------------------------------

    #[test]
    fn builtin_scan_handles_empty_target_dir() {
        let dir = unique_test_dir("empty_dir");
        let key = RandomState::new();
        let out = builtin_scan(&dir, &key);
        assert!(out.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn builtin_scan_handles_empty_file() {
        let dir = unique_test_dir("empty_file");
        std::fs::write(dir.join("empty.txt"), "").unwrap();
        let key = RandomState::new();
        let out = builtin_scan(&dir, &key);
        assert!(out.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn builtin_scan_ignores_non_utf8_file() {
        let dir = unique_test_dir("bad_utf8");
        // 0xFF is never valid as a UTF-8 lead byte.
        std::fs::write(dir.join("bad.bin"), [b'a', b'=', 0xFF, 0xFE, b'"']).unwrap();
        let key = RandomState::new();
        let out = builtin_scan(&dir, &key); // must not panic
        assert!(out.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn builtin_scan_handles_very_deep_directory_tree() {
        let dir = unique_test_dir("deep_tree");
        let mut nested = dir.clone();
        for i in 0..150 {
            nested = nested.join(format!("d{i}"));
        }
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(
            nested.join("config.env"),
            "aws_key = \"AKIAABCDEFGHIJKLMNOP\"\n",
        )
        .unwrap();
        let key = RandomState::new();
        let out = builtin_scan(&dir, &key); // must not stack-overflow or hang
        assert_eq!(out.len(), 1);
        assert!(!out[0].context_line.contains("AKIAABCDEFGHIJKLMNOP"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn builtin_scan_does_not_merge_secrets_split_across_two_files() {
        // A secret's value split across two different files' content must be scanned
        // independently — no cross-file concatenation.
        let dir = unique_test_dir("two_files");
        std::fs::write(dir.join("a.env"), "aws_key = \"AKIA\"\n").unwrap();
        std::fs::write(dir.join("b.env"), "aws_key = \"ABCDEFGHIJKLMNOP\"\n").unwrap();
        let key = RandomState::new();
        let out = builtin_scan(&dir, &key);
        // Neither half alone matches the aws_access_key_id rule (needs `AKIA` + 16 chars
        // in one token); the generic fallback needs >=20 chars in one quoted value, and
        // neither half reaches that either, so this must find nothing — not a merged hit.
        assert!(
            out.is_empty(),
            "must not synthesize a cross-file match: {out:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn builtin_scan_does_not_merge_secret_split_across_two_lines() {
        // Characterization test: this scanner works line-by-line, so a single secret
        // value wrapped across two lines is *not* detected as one token. Document that
        // explicitly rather than leaving it as an unverified assumption — this is a
        // detection-coverage limitation, not a masking leak (nothing unmasked is ever
        // reported, because no candidate is produced from either half here).
        let dir = unique_test_dir("split_line");
        std::fs::write(
            dir.join("wrapped.env"),
            "aws_key = \"AKIAABCDEFGH\nIJKLMNOP\"\n",
        )
        .unwrap();
        let key = RandomState::new();
        let out = builtin_scan(&dir, &key);
        assert!(
            out.is_empty(),
            "line-wrapped secret unexpectedly matched: {out:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn builtin_scan_does_not_follow_symlinked_files() {
        use std::os::unix::fs::symlink;
        let dir = unique_test_dir("symlink_file");
        let real = dir.join("real_secret.env");
        std::fs::write(&real, "aws_key = \"AKIAABCDEFGHIJKLMNOP\"\n").unwrap();
        let outside = unique_test_dir("symlink_file_target_outside");
        let real_outside = outside.join("real_secret.env");
        std::fs::write(&real_outside, "aws_key = \"AKIAABCDEFGHIJKLMNOP\"\n").unwrap();
        symlink(&real_outside, dir.join("link.env")).unwrap();

        let key = RandomState::new();
        let out = builtin_scan(&dir, &key);
        // `real.env` (an actual file) is found; `link.env` (a symlink) is not followed —
        // WalkDir's default (no follow_links) reports symlinks via symlink_metadata, so
        // `file_type().is_file()` is false for them and builtin_scan's own filter skips
        // them. This also means a symlink can never be used to read/leak content from
        // outside the scan target.
        assert_eq!(
            out.len(),
            1,
            "expected only the real file to be scanned: {out:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    #[cfg(unix)]
    #[test]
    fn builtin_scan_does_not_hang_on_symlink_loop() {
        use std::os::unix::fs::symlink;
        let dir = unique_test_dir("symlink_loop");
        let sub = dir.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        // sub/loop -> dir (a directory symlink cycle back to an ancestor).
        symlink(&dir, sub.join("loop")).unwrap();
        std::fs::write(dir.join("real.env"), "aws_key = \"AKIAABCDEFGHIJKLMNOP\"\n").unwrap();

        let key = RandomState::new();
        // Must terminate (WalkDir's default is not to follow directory symlinks) rather
        // than recursing forever.
        let out = builtin_scan(&dir, &key);
        assert_eq!(out.len(), 1, "{out:?}");
        std::fs::remove_dir_all(&dir).ok();
    }
}
