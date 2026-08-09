use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Review lens (7 persona types). Fields are identical to codereview-loop's Lens —
/// only the domain is distinguished via prompts (guide/persona_voice).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Lens {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub guide: String,
    #[serde(default)]
    pub always: bool,
    #[serde(default)]
    pub signal: String,
    #[serde(default)]
    pub persona_name: String,
    #[serde(default)]
    pub persona_voice: String,
    #[serde(default)]
    pub tier: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Spec {
    pub name: String,
    /// Context of the scan target (e.g. "MangroveCafeOrder pre-public-release check"). Inserted into the prompt.
    #[serde(default)]
    pub context: String,
    pub lenses: Vec<Lens>,
    /// List of labels allowed in findings (candidate types).
    pub labels: Vec<String>,
    /// List of patterns that must be included in .gitignore (policy check). E.g. [".env", "*.pem", "*.key"].
    #[serde(default)]
    pub required_gitignore_patterns: Vec<String>,
    /// Policy checklist (requirements). Cross-checks items like "no AWS keys" against confirmed findings.
    #[serde(default)]
    pub policy_checklist: Vec<String>,
}

impl Spec {
    pub fn load(path: &Path) -> Result<Spec> {
        let s = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read spec file: {}", path.display()))?;
        let spec: Spec = toml::from_str(&s)
            .with_context(|| format!("failed to parse spec TOML: {}", path.display()))?;
        anyhow::ensure!(!spec.lenses.is_empty(), "lenses is empty");
        anyhow::ensure!(!spec.labels.is_empty(), "labels is empty");
        Ok(spec)
    }

    pub fn lens_by_id(&self, id: &str) -> Option<&Lens> {
        self.lenses.iter().find(|l| l.id == id)
    }

    pub fn always_lenses(&self) -> Vec<&Lens> {
        self.lenses.iter().filter(|l| l.always).collect()
    }

    pub fn optional_lenses(&self) -> Vec<&Lens> {
        self.lenses.iter().filter(|l| !l.always).collect()
    }

    pub fn labels_prompt(&self) -> String {
        self.labels
            .iter()
            .map(|l| format!("\"{l}\""))
            .collect::<Vec<_>>()
            .join(", ")
    }
}
