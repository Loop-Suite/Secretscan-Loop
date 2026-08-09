use crate::discourse::Resolution;
use crate::lens::Finding;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Snapshot of findings and verdicts at the end of a round. The next round (--prior) picks up from here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    pub round: usize,
    pub findings: Vec<Finding>,
    pub resolved: HashMap<String, Resolution>,
}

pub fn write(out_dir: &Path, state: &State) -> Result<PathBuf> {
    let path = out_dir.join("state.json");
    std::fs::write(&path, serde_json::to_string_pretty(state)?)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

pub fn load(dir: &Path) -> Result<State> {
    let path = if dir.is_dir() {
        dir.join("state.json")
    } else {
        dir.to_path_buf()
    };
    let s = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "failed to read {} (--prior expects a previous --out directory)",
            path.display()
        )
    })?;
    serde_json::from_str(&s).with_context(|| format!("failed to parse {}", path.display()))
}
