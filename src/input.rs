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

/// Counts files actually eligible for scanning — i.e. applies the same directory skip list
/// (`.git`, `node_modules`, `target`, etc.) as `builtin_scan`. Without this, the count included
/// every file physically present under `target`, so a repo with a populated `node_modules` or
/// `target` build dir would report a "files scanned" number orders of magnitude larger than
/// what was actually content-scanned — misrepresenting scan coverage (see GH issue: `count_files`
/// counts files inside skipped directories).
fn count_files(target: &Path) -> usize {
    walkdir::WalkDir::new(target)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let rel = e.path().strip_prefix(target).unwrap_or(e.path());
            e.file_type().is_file() && !scanners::should_skip(rel)
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_files_excludes_skipped_directories() {
        let dir = std::env::temp_dir().join(format!(
            "secretscan_count_files_test_{}_{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(dir.join("node_modules/pkg")).unwrap();
        for i in 0..20 {
            std::fs::write(dir.join(format!("node_modules/pkg/file{i}.js")), "noop").unwrap();
        }
        std::fs::write(dir.join("real_source.rs"), "fn main() {}").unwrap();

        assert_eq!(
            count_files(&dir),
            1,
            "files under node_modules must not be counted as scanned"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
