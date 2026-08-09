mod ask;
mod checks;
mod describe;
mod discourse;
mod fixcheck;
mod improve;
mod input;
mod lens;
mod llm;
mod promptctx;
mod quantify;
mod report;
mod requirements;
mod scanners;
mod spec;
mod state;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use lens::Finding;
use llm::Llm;
use scanners::ScanScope;
use spec::Spec;
use std::path::PathBuf;

#[derive(clap::ValueEnum, Clone, Debug, PartialEq)]
enum Backend {
    Claude,
    Openrouter,
}

/// Exit-code contract (issue #1): PASS=0, WARN=2, BLOCK=3, run/config error=4.
/// `--fail-on` controls which verdicts actually cause a non-zero exit — the mapped code is
/// still 0/2/3/4 as above, it's just forced to 0 when the verdict doesn't meet the threshold.
#[derive(clap::ValueEnum, Clone, Debug, PartialEq)]
enum FailOn {
    /// Non-zero exit on WARN or BLOCK.
    Warn,
    /// Non-zero exit only on BLOCK (default — matches prior "just report" behavior for WARN).
    Block,
    /// Always exit 0, whatever the verdict (report-only mode).
    Never,
}

fn verdict_code(verdict: &str) -> i32 {
    match verdict {
        "PASS" => 0,
        "WARN" => 2,
        "BLOCK" => 3,
        _ => 4,
    }
}

fn exit_code_for(verdict: &str, fail_on: &FailOn) -> i32 {
    let should_fail = match fail_on {
        FailOn::Never => false,
        FailOn::Warn => verdict == "WARN" || verdict == "BLOCK",
        FailOn::Block => verdict == "BLOCK",
    };
    if should_fail {
        verdict_code(verdict)
    } else {
        0
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "secretscan",
    version,
    about = "Multi-persona review + discourse cross-examination that triages secret-scanner findings before you push or go public"
)]
struct Cli {
    #[arg(long, default_value = "claude", global = true)]
    claude_bin: String,
    #[arg(long, value_enum, default_value = "claude", global = true)]
    backend: Backend,
    #[arg(long, global = true)]
    model: Option<String>,
    #[arg(long, global = true)]
    cheap_model: Option<String>,
    #[arg(long, default_value_t = 2, global = true)]
    retries: u32,
    #[arg(long, global = true)]
    verbose: bool,
    /// Which verdicts should cause a non-zero exit code (CI/pre-push gate). See issue #1.
    #[arg(long, value_enum, default_value = "block", global = true)]
    fail_on: FailOn,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Detect candidates (builtin + gitleaks/trufflehog if installed), then persona review + discourse
    Scan {
        #[arg(long)]
        spec: PathBuf,
        /// Directory to scan (defaults to current directory)
        #[arg(long, default_value = ".")]
        target: PathBuf,
        /// Extra free-text policy notes
        #[arg(long)]
        notes: Option<PathBuf>,
        #[arg(long)]
        lenses: Option<String>,
        #[arg(long, default_value = "runs")]
        out: PathBuf,
        #[arg(long, default_value_t = 1)]
        concurrency: usize,
        #[arg(long, default_value_t = 2)]
        max_rounds: usize,
        /// Prior round's --out directory (state.json), for FIXED/STILL_OPEN/UNKNOWN/ROTATED
        #[arg(long)]
        prior: Option<PathBuf>,
        /// Scan only files staged for commit (git diff --cached), instead of the whole
        /// working tree. Mutually exclusive with --range/--history.
        #[arg(long)]
        staged: bool,
        /// Scan a commit range (e.g. "origin/main..HEAD") via git history instead of the
        /// working tree. Mutually exclusive with --staged/--history.
        #[arg(long, value_name = "BASE..HEAD")]
        range: Option<String>,
        /// Scan full git history instead of just the working tree. Mutually exclusive with
        /// --staged/--range.
        #[arg(long)]
        history: bool,
    },
    /// Summarize a scan (risk highlights, safe_to_publish)
    Describe {
        #[arg(long)]
        spec: PathBuf,
        #[arg(long, default_value = ".")]
        target: PathBuf,
        #[arg(long)]
        notes: Option<PathBuf>,
        #[arg(long, default_value = "runs")]
        out: PathBuf,
    },
    /// Propose remediation (rotate/gitignore/history-scrub) for found candidates
    Improve {
        #[arg(long)]
        spec: PathBuf,
        #[arg(long, default_value = ".")]
        target: PathBuf,
        #[arg(long)]
        notes: Option<PathBuf>,
        #[arg(long, default_value = "runs")]
        out: PathBuf,
    },
    /// Free-form Q&A about a scan (appended to ask.md)
    Ask {
        #[arg(long)]
        spec: PathBuf,
        #[arg(long, default_value = ".")]
        target: PathBuf,
        #[arg(long)]
        notes: Option<PathBuf>,
        #[arg(long, default_value = "runs")]
        out: PathBuf,
        question: String,
    },
}

fn main() {
    match real_main() {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::exit(4); // run/config error — see exit-code contract (issue #1)
        }
    }
}

fn build_llm(cli: &Cli) -> Result<(Llm, Llm)> {
    let usage = Llm::new_usage_tracker();
    let cheap_model = cli.cheap_model.clone().or_else(|| cli.model.clone());
    let (main_llm, cheap_llm) = match cli.backend {
        Backend::Claude => (
            Llm::claude_cli(
                cli.claude_bin.clone(),
                cli.model.clone(),
                cli.retries,
                cli.verbose,
                usage.clone(),
            ),
            Llm::claude_cli(
                cli.claude_bin.clone(),
                cheap_model,
                cli.retries,
                cli.verbose,
                usage.clone(),
            ),
        ),
        Backend::Openrouter => (
            Llm::openrouter(cli.model.clone(), cli.retries, cli.verbose, usage.clone())?,
            Llm::openrouter(cheap_model, cli.retries, cli.verbose, usage.clone())?,
        ),
    };
    Ok((main_llm, cheap_llm))
}

fn real_main() -> Result<i32> {
    let cli = Cli::parse();
    let (llm, cheap_llm) = build_llm(&cli)?;

    match &cli.cmd {
        Cmd::Scan {
            spec,
            target,
            notes,
            lenses,
            out,
            concurrency,
            max_rounds,
            prior,
            staged,
            range,
            history,
        } => {
            let scope = scan_scope_from_flags(*staged, range, *history)?;
            run_scan(
                &llm,
                &cheap_llm,
                spec,
                target,
                notes,
                lenses,
                out,
                *concurrency,
                *max_rounds,
                prior,
                &scope,
                &cli.fail_on,
            )
        }
        Cmd::Describe {
            spec,
            target,
            notes,
            out,
        } => {
            run_describe(&llm, spec, target, notes, out)?;
            Ok(0)
        }
        Cmd::Improve {
            spec,
            target,
            notes,
            out,
        } => {
            run_improve(&llm, spec, target, notes, out)?;
            Ok(0)
        }
        Cmd::Ask {
            spec,
            target,
            notes,
            out,
            question,
        } => {
            run_ask(&llm, spec, target, notes, out, question)?;
            Ok(0)
        }
    }
}

/// At most one of --staged/--range/--history may be given; none of them => Filesystem
/// (backward-compatible default — issue #2).
fn scan_scope_from_flags(staged: bool, range: &Option<String>, history: bool) -> Result<ScanScope> {
    let picked = staged as u8 + range.is_some() as u8 + history as u8;
    anyhow::ensure!(
        picked <= 1,
        "--staged, --range, --history are mutually exclusive"
    );
    if staged {
        Ok(ScanScope::Staged)
    } else if let Some(r) = range {
        Ok(ScanScope::Range(r.clone()))
    } else if history {
        Ok(ScanScope::History)
    } else {
        Ok(ScanScope::Filesystem)
    }
}

#[allow(clippy::too_many_arguments)]
fn run_scan(
    llm: &Llm,
    cheap_llm: &Llm,
    spec_path: &PathBuf,
    target: &PathBuf,
    notes_path: &Option<PathBuf>,
    lenses_arg: &Option<String>,
    out: &PathBuf,
    concurrency: usize,
    max_rounds: usize,
    prior: &Option<PathBuf>,
    scope: &ScanScope,
    fail_on: &FailOn,
) -> Result<i32> {
    let sp = Spec::load(spec_path)?;
    let inp = input::normalize(target, notes_path, scope)?;
    let out_dir = prepare_out(out)?;

    let prior_state = match prior {
        None => None,
        Some(p) => Some(state::load(p)?),
    };
    let round = prior_state.as_ref().map(|s| s.round + 1).unwrap_or(1);

    println!(
        "scan start (round {}) — {} ({} files scanned, {} raw candidates)",
        round,
        sp.name,
        inp.files_scanned,
        inp.candidates.len()
    );

    let checks_results = checks::run_all(
        target,
        &sp.required_gitignore_patterns,
        inp.candidates.len(),
    );

    if inp.candidates.is_empty() {
        println!("no candidates found — skipping lens review and discourse");
        let quant = quantify::summarize(
            &inp.candidates,
            &[],
            &Default::default(),
            &checks_results,
            0,
        );
        let path = report::write(report::ReportCtx {
            out_dir: &out_dir,
            spec: &sp,
            input: &inp,
            selected_lenses: &[],
            round,
            findings: &[],
            resolved: &Default::default(),
            unverified: &[],
            checks: &checks_results,
            policies: &None,
            policy_violations: &[],
            audit: &[],
            quant: &quant,
            fix_results: &[],
        })?;
        state::write(
            &out_dir,
            &state::State {
                round,
                findings: vec![],
                resolved: Default::default(),
            },
        )?;
        println!("\nverdict={} score={}/100", quant.verdict, quant.score);
        println!("report: {}", path.display());
        return Ok(exit_code_for(&quant.verdict, fail_on));
    }

    let optional_selected: Vec<String> = match lenses_arg {
        Some(s) => {
            let ids: Vec<String> = s
                .split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect();
            for id in &ids {
                anyhow::ensure!(sp.lens_by_id(id).is_some(), "lens id not in spec: {id}");
            }
            ids
        }
        None => lens::select_lenses(cheap_llm, &sp, &inp)?,
    };
    let mut selected_ids: Vec<String> = optional_selected;
    for l in sp.always_lenses() {
        if !selected_ids.contains(&l.id) {
            selected_ids.push(l.id.clone());
        }
    }
    println!("selected lenses: {}", selected_ids.join(", "));

    let lens_outputs: Vec<(String, lens::LensOutput)> =
        par_map(concurrency, selected_ids.clone(), |id| {
            let out = lens::review_lens(llm, &sp, &inp, &id)?;
            println!(
                "  lens done: {} — {} finding(s), {} unverified",
                id,
                out.findings.len(),
                out.unverified.len()
            );
            Ok((id, out))
        })?;

    let mut findings: Vec<Finding> = Vec::new();
    let mut unverified: Vec<(String, String)> = Vec::new();
    for (id, out) in lens_outputs {
        findings.extend(out.findings);
        for u in out.unverified {
            unverified.push((id.clone(), u));
        }
    }

    let (audit, mut resolved) = if findings.is_empty() {
        println!("no findings raised by any lens — discourse skipped");
        (Vec::new(), std::collections::HashMap::new())
    } else {
        println!("discourse start (max {} round(s))", max_rounds);
        discourse::run(llm, &sp, &mut findings, max_rounds)?
    };

    let mut fix_results: Vec<fixcheck::FixStatus> = Vec::new();
    if let Some(ps) = &prior_state {
        let prior_confirmed: Vec<Finding> = ps
            .findings
            .iter()
            .filter(|f| {
                ps.resolved
                    .get(&f.id)
                    .map(|r| r.status == "CONFIRMED")
                    .unwrap_or(false)
            })
            .cloned()
            .collect();
        fix_results = fixcheck::run(cheap_llm, &sp, &inp, &prior_confirmed)?;
        for fr in &fix_results {
            if fr.status == "STILL_OPEN" {
                if let Some(orig) = prior_confirmed.iter().find(|f| f.id == fr.finding_id) {
                    findings.push(orig.clone());
                    resolved.insert(
                        orig.id.clone(),
                        discourse::Resolution {
                            finding_id: orig.id.clone(),
                            status: "CONFIRMED".to_string(),
                            merged_into: String::new(),
                            reason: format!(
                                "still open per prior-round comparison: {}",
                                fr.evidence
                            ),
                        },
                    );
                }
            }
        }
    }

    let confirmed_refs: Vec<&Finding> = findings
        .iter()
        .filter(|f| resolved.get(&f.id).map(|r| r.status.as_str()) == Some("CONFIRMED"))
        .collect();
    let policies = requirements::verify(cheap_llm, &sp, &inp, &confirmed_refs)?;
    let policy_violations = requirements::violations(&policies);

    let quant = quantify::summarize(
        &inp.candidates,
        &findings,
        &resolved,
        &checks_results,
        policy_violations.len(),
    );

    let path = report::write(report::ReportCtx {
        out_dir: &out_dir,
        spec: &sp,
        input: &inp,
        selected_lenses: &selected_ids,
        round,
        findings: &findings,
        resolved: &resolved,
        unverified: &unverified,
        checks: &checks_results,
        policies: &policies,
        policy_violations: &policy_violations,
        audit: &audit,
        quant: &quant,
        fix_results: &fix_results,
    })?;

    state::write(
        &out_dir,
        &state::State {
            round,
            findings: findings.clone(),
            resolved: resolved.clone(),
        },
    )?;

    println!(
        "\ndone — verdict={} score={}/100 policy_violations={}",
        quant.verdict, quant.score, quant.policy_violation_count
    );
    println!("report: {}", path.display());
    println!("next round: --prior {}", out_dir.display());
    println!("{}", llm.usage().summary());
    Ok(exit_code_for(&quant.verdict, fail_on))
}

fn run_describe(
    llm: &Llm,
    spec_path: &PathBuf,
    target: &PathBuf,
    notes_path: &Option<PathBuf>,
    out: &PathBuf,
) -> Result<()> {
    let sp = Spec::load(spec_path)?;
    let inp = input::normalize(target, notes_path, &ScanScope::Filesystem)?;
    let out_dir = prepare_out(out)?;
    let d = describe::run(llm, &sp, &inp)?;
    let path = report::write_describe(&out_dir, &d)?;
    println!("describe done: {}", path.display());
    println!("{}", llm.usage().summary());
    Ok(())
}

fn run_improve(
    llm: &Llm,
    spec_path: &PathBuf,
    target: &PathBuf,
    notes_path: &Option<PathBuf>,
    out: &PathBuf,
) -> Result<()> {
    let sp = Spec::load(spec_path)?;
    let inp = input::normalize(target, notes_path, &ScanScope::Filesystem)?;
    let out_dir = prepare_out(out)?;
    let suggestions = improve::run(llm, &sp, &inp)?;
    let path = report::write_improve(&out_dir, &suggestions)?;
    println!(
        "improve done: {} suggestion(s) — {}",
        suggestions.len(),
        path.display()
    );
    println!("{}", llm.usage().summary());
    Ok(())
}

fn run_ask(
    llm: &Llm,
    spec_path: &PathBuf,
    target: &PathBuf,
    notes_path: &Option<PathBuf>,
    out: &PathBuf,
    question: &str,
) -> Result<()> {
    let sp = Spec::load(spec_path)?;
    let inp = input::normalize(target, notes_path, &ScanScope::Filesystem)?;
    let out_dir = prepare_out(out)?;
    let answer = ask::run(llm, &sp, &inp, question)?;
    let path = out_dir.join("ask.md");
    let mut existing = std::fs::read_to_string(&path).unwrap_or_default();
    existing.push_str(&format!("\n## Q: {question}\n\n{answer}\n"));
    std::fs::write(&path, existing)
        .with_context(|| format!("failed to write {}", path.display()))?;
    println!("{}", answer);
    println!("\n(accumulated: {})", path.display());
    println!("{}", llm.usage().summary());
    Ok(())
}

fn prepare_out(p: &PathBuf) -> Result<PathBuf> {
    std::fs::create_dir_all(p)
        .with_context(|| format!("failed to create output dir: {}", p.display()))?;
    Ok(p.clone())
}

fn par_map<T, R, F>(concurrency: usize, items: Vec<T>, f: F) -> Result<Vec<R>>
where
    T: Send,
    R: Send,
    F: Fn(T) -> Result<R> + Sync,
{
    let c = concurrency.max(1);
    let mut out: Vec<R> = Vec::new();
    let mut rest = items;
    while !rest.is_empty() {
        let take = c.min(rest.len());
        let chunk: Vec<T> = rest.drain(..take).collect();
        let results: Vec<Result<R>> = std::thread::scope(|s| {
            let handles: Vec<_> = chunk.into_iter().map(|item| s.spawn(|| f(item))).collect();
            handles
                .into_iter()
                .map(|h| {
                    h.join()
                        .map_err(|_| anyhow!("worker thread panicked"))
                        .and_then(|r| r)
                })
                .collect()
        });
        for r in results {
            out.push(r?);
        }
    }
    Ok(out)
}
