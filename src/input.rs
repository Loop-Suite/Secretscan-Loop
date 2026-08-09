use crate::scanners::{self, Candidate, ScanScope};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub struct Input {
    pub target: PathBuf,
    pub candidates: Vec<Candidate>,
    pub files_scanned: usize,
    /// Extra policy notes (e.g. "this repo is about to go public, be strict").
    pub requirements: Option<String>,
}

fn read_opt(p: &Option<std::path::PathBuf>) -> Result<Option<String>> {
    match p {
        None => Ok(None),
        Some(path) => {
            let s = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            Ok(Some(s))
        }
    }
}

fn count_files(target: &Path) -> usize {
    walkdir::WalkDir::new(target)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .count()
}

pub fn normalize(
    target: &Path,
    requirements_path: &Option<std::path::PathBuf>,
    scope: &ScanScope,
) -> Result<Input> {
    anyhow::ensure!(
        target.exists(),
        "scan target does not exist: {}",
        target.display()
    );
    let candidates = scanners::scan_all(target, scope);
    let files_scanned = count_files(target);
    let requirements = read_opt(requirements_path)?;
    Ok(Input {
        target: target.to_path_buf(),
        candidates,
        files_scanned,
        requirements,
    })
}
