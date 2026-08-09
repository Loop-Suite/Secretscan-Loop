use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

const OPENROUTER_URL: &str = "https://openrouter.ai/api/v1/chat/completions";
pub const OPENROUTER_DEFAULT_MODEL: &str = "openai/gpt-oss-120b";

/// LLM call backend. ClaudeCli = `claude -p` subprocess, OpenRouter = REST API.
#[derive(Clone, Debug)]
pub enum Provider {
    ClaudeCli { bin: String },
    OpenRouter { api_key: String },
}

/// Cumulative token/cost usage. If multiple Llm instances (e.g. main model + low-cost model)
/// share the same Arc, you get a total aggregated across the whole run.
#[derive(Debug, Clone, Default)]
pub struct Usage {
    pub calls: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_creation_tokens: u64,
    /// Only populated when the claude CLI provides it (absent from OpenRouter responses).
    pub cost_usd: f64,
}

impl Usage {
    pub fn summary(&self) -> String {
        let cost = if self.cost_usd > 0.0 {
            format!(", cost ${:.4}", self.cost_usd)
        } else {
            String::new()
        };
        format!(
            "LLM calls: {} — input {} / output {} / cache_read {} / cache_write {}{}",
            self.calls,
            self.input_tokens,
            self.output_tokens,
            self.cache_read_tokens,
            self.cache_creation_tokens,
            cost
        )
    }
}

#[derive(Debug, Default)]
struct CallUsage {
    input_tokens: u64,
    output_tokens: u64,
    cache_read_tokens: u64,
    cache_creation_tokens: u64,
    cost_usd: f64,
}

struct CallResult {
    text: String,
    usage: CallUsage,
}

#[derive(Clone, Debug)]
pub struct Llm {
    pub provider: Provider,
    pub model: Option<String>,
    pub retries: u32,
    pub verbose: bool,
    usage: Arc<Mutex<Usage>>,
}

impl Llm {
    /// Share across multiple Llm instances to track aggregated usage for the whole run.
    pub fn new_usage_tracker() -> Arc<Mutex<Usage>> {
        Arc::new(Mutex::new(Usage::default()))
    }

    pub fn claude_cli(
        bin: String,
        model: Option<String>,
        retries: u32,
        verbose: bool,
        usage: Arc<Mutex<Usage>>,
    ) -> Self {
        Llm {
            provider: Provider::ClaudeCli { bin },
            model,
            retries,
            verbose,
            usage,
        }
    }

    /// Requires the `OPENROUTER_API_KEY` env var. Defaults to the 120B open model if model is unspecified.
    pub fn openrouter(
        model: Option<String>,
        retries: u32,
        verbose: bool,
        usage: Arc<Mutex<Usage>>,
    ) -> Result<Self> {
        let api_key = std::env::var("OPENROUTER_API_KEY")
            .context("OPENROUTER_API_KEY env var not set (export OPENROUTER_API_KEY=...)")?;
        Ok(Llm {
            provider: Provider::OpenRouter { api_key },
            model: Some(model.unwrap_or_else(|| OPENROUTER_DEFAULT_MODEL.to_string())),
            retries,
            verbose,
            usage,
        })
    }

    /// Snapshot of usage accumulated so far (based on the shared tracker). Even if another
    /// thread panics while holding the lock and poisons it (the accumulated total may end up
    /// wrong), this won't panic again here.
    pub fn usage(&self) -> Usage {
        self.usage.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn record_usage(&self, u: &CallUsage) {
        let mut g = self.usage.lock().unwrap_or_else(|e| e.into_inner());
        g.calls += 1;
        g.input_tokens += u.input_tokens;
        g.output_tokens += u.output_tokens;
        g.cache_read_tokens += u.cache_read_tokens;
        g.cache_creation_tokens += u.cache_creation_tokens;
        g.cost_usd += u.cost_usd;
    }

    fn call_once(&self, ctx: Option<&str>, task: &str, system: Option<&str>) -> Result<CallResult> {
        match &self.provider {
            Provider::ClaudeCli { bin } => {
                call_claude(bin, self.model.as_deref(), ctx, task, system)
            }
            Provider::OpenRouter { api_key } => {
                call_openrouter(api_key, self.model.as_deref(), ctx, task, system)
            }
        }
    }

    /// Takes `ctx` (a stable prefix repeated across calls: project context, conventions,
    /// requirements, diff) separately from `task` (the instruction that varies per call). On
    /// the OpenRouter backend, `cache_control(ephemeral)` is attached to ctx to aim for cache
    /// hits when the same ctx is reused across repeated calls. The claude-cli backend spawns a
    /// fresh subprocess per call, so caching has no effect there — it just concatenates them.
    pub fn text_ctx(&self, ctx: Option<&str>, task: &str, system: Option<&str>) -> Result<String> {
        let mut last: Option<anyhow::Error> = None;
        for attempt in 0..=self.retries {
            match self.call_once(ctx, task, system) {
                Ok(r) => {
                    self.record_usage(&r.usage);
                    if !r.text.trim().is_empty() {
                        return Ok(r.text);
                    }
                    last = Some(anyhow!("empty response"));
                }
                Err(e) => last = Some(e),
            }
            if self.verbose {
                match last.as_ref() {
                    Some(error) => eprintln!("[retry {}/{}] {error}", attempt + 1, self.retries),
                    None => eprintln!(
                        "[retry {}/{}] unknown retry error",
                        attempt + 1,
                        self.retries
                    ),
                }
            }
        }
        Err(last.unwrap_or_else(|| anyhow!("unknown failure")))
    }

    /// Forces a JSON response. Retries on parse failure.
    pub fn json(&self, prompt: &str, system: Option<&str>) -> Result<serde_json::Value> {
        self.json_ctx(None, prompt, system)
    }

    /// JSON-forcing variant of [`Llm::text_ctx`].
    pub fn json_ctx(
        &self,
        ctx: Option<&str>,
        task: &str,
        system: Option<&str>,
    ) -> Result<serde_json::Value> {
        let mut last: Option<anyhow::Error> = None;
        for attempt in 0..=self.retries {
            let raw = match self.call_once(ctx, task, system) {
                Ok(r) => {
                    self.record_usage(&r.usage);
                    r.text
                }
                Err(e) => {
                    last = Some(e);
                    if self.verbose {
                        match last.as_ref() {
                            Some(error) => {
                                eprintln!("[json retry {}/{}] {error}", attempt + 1, self.retries)
                            }
                            None => {
                                eprintln!(
                                    "[json retry {}/{}] unknown json retry error",
                                    attempt + 1,
                                    self.retries
                                );
                            }
                        }
                    }
                    continue;
                }
            };
            match extract_json(&raw) {
                Ok(v) => return Ok(v),
                Err(e) => {
                    last = Some(e);
                    if self.verbose {
                        match last.as_ref() {
                            Some(error) => {
                                eprintln!("[json retry {}/{}] {error}", attempt + 1, self.retries)
                            }
                            None => {
                                eprintln!(
                                    "[json retry {}/{}] unknown json retry error",
                                    attempt + 1,
                                    self.retries
                                );
                            }
                        }
                    }
                }
            }
        }
        Err(last.unwrap_or_else(|| anyhow!("JSON response failed")))
    }
}

/// Passes the prompt via stdin (to avoid argument length limits). Since this is a subprocess
/// call, caching doesn't apply, so ctx+task are simply concatenated (order only: stable context
/// first, variable instructions last).
fn call_claude(
    bin: &str,
    model: Option<&str>,
    ctx: Option<&str>,
    task: &str,
    system: Option<&str>,
) -> Result<CallResult> {
    let mut cmd = Command::new(bin);
    cmd.arg("-p").arg("--output-format").arg("json");
    if let Some(m) = model {
        cmd.arg("--model").arg(m);
    }
    if let Some(s) = system {
        cmd.arg("--append-system-prompt").arg(s);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to run `{bin}` (check install and PATH)"))?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow!("failed to open stdin"))?;
        if let Some(c) = ctx {
            stdin.write_all(c.as_bytes())?;
        }
        stdin.write_all(task.as_bytes())?;
    }
    drop(child.stdin.take());

    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(anyhow!(
            "claude exit code {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).with_context(|| {
        format!(
            "failed to parse claude JSON output: {}",
            truncate(&stdout, 400)
        )
    })?;
    if v.get("is_error").and_then(|b| b.as_bool()).unwrap_or(false) {
        return Err(anyhow!(
            "claude returned an error response: {}",
            truncate(&stdout, 400)
        ));
    }
    let result = v
        .get("result")
        .and_then(|r| r.as_str())
        .ok_or_else(|| anyhow!("response has no result field: {}", truncate(&stdout, 400)))?;

    // usage/cost fields may or may not exist, and their names may vary, depending on the claude
    // CLI version, so parse them leniently (default to 0 rather than failing — only the result
    // field is treated as the contract).
    let usage_obj = v.get("usage");
    let get_u64 = |key: &str| {
        usage_obj
            .and_then(|u| u.get(key))
            .and_then(|x| x.as_u64())
            .unwrap_or(0)
    };
    let cost_usd = v
        .get("total_cost_usd")
        .or_else(|| v.get("cost_usd"))
        .and_then(|c| c.as_f64())
        .unwrap_or(0.0);
    Ok(CallResult {
        text: result.to_string(),
        usage: CallUsage {
            input_tokens: get_u64("input_tokens"),
            output_tokens: get_u64("output_tokens"),
            cache_read_tokens: get_u64("cache_read_input_tokens"),
            cache_creation_tokens: get_u64("cache_creation_input_tokens"),
            cost_usd,
        },
    })
}

/// `cache_control(ephemeral)` is an Anthropic Messages API extension, so it's only meaningful
/// for Claude-family models — for other models (including OPENROUTER_DEFAULT_MODEL) there's no
/// caching benefit, so there's no reason to attach it. If the model name doesn't contain
/// "claude", send a plain single-string content as before.
fn supports_prompt_caching(model: &str) -> bool {
    model.to_ascii_lowercase().contains("claude")
}

/// One call to the OpenRouter chat completions API. If ctx is given and the target model is
/// Claude-family, split it into a separate content block and attach cache_control(ephemeral) —
/// an optimization aiming for cache hits when the same ctx is reused across repeated calls
/// (e.g. per-lens review). Otherwise, send a plain single-string content as before.
fn call_openrouter(
    api_key: &str,
    model: Option<&str>,
    ctx: Option<&str>,
    task: &str,
    system: Option<&str>,
) -> Result<CallResult> {
    let mut messages: Vec<serde_json::Value> = Vec::new();
    if let Some(s) = system {
        messages.push(serde_json::json!({"role": "system", "content": s}));
    }
    let resolved_model = model.unwrap_or(OPENROUTER_DEFAULT_MODEL);
    let cacheable_ctx = ctx.filter(|c| !c.is_empty() && supports_prompt_caching(resolved_model));
    let user_content = match cacheable_ctx {
        Some(c) => serde_json::json!([
            {"type": "text", "text": c, "cache_control": {"type": "ephemeral"}},
            {"type": "text", "text": task},
        ]),
        None => {
            let combined = match ctx {
                Some(c) if !c.is_empty() => format!("{c}{task}"),
                _ => task.to_string(),
            };
            serde_json::json!(combined)
        }
    };
    messages.push(serde_json::json!({"role": "user", "content": user_content}));

    let body = serde_json::json!({
        "model": resolved_model,
        "messages": messages,
    });

    let result = ureq::post(OPENROUTER_URL)
        .set("Authorization", &format!("Bearer {api_key}"))
        .set("Content-Type", "application/json")
        .send_json(body);

    let resp = match result {
        Ok(r) => r,
        Err(ureq::Error::Status(code, r)) => {
            let body = r.into_string().unwrap_or_default();
            return Err(anyhow!(
                "openrouter response code {code}: {}",
                truncate(&body, 400)
            ));
        }
        Err(e) => return Err(anyhow!("openrouter call failed: {e}")),
    };

    let v: serde_json::Value = resp
        .into_json()
        .context("failed to parse openrouter response JSON")?;
    let content = v
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        .ok_or_else(|| {
            anyhow!(
                "openrouter response has no content: {}",
                truncate(&v.to_string(), 400)
            )
        })?;

    // OpenAI-compatible usage schema (prompt_tokens/completion_tokens). cost isn't in the
    // response, so it's left at 0.
    let usage_obj = v.get("usage");
    let get_u64 = |key: &str| {
        usage_obj
            .and_then(|u| u.get(key))
            .and_then(|x| x.as_u64())
            .unwrap_or(0)
    };
    Ok(CallResult {
        text: content.to_string(),
        usage: CallUsage {
            input_tokens: get_u64("prompt_tokens"),
            output_tokens: get_u64("completion_tokens"),
            cache_read_tokens: 0,
            cache_creation_tokens: 0,
            cost_usd: 0.0,
        },
    })
}

/// Extracts just the JSON object (or array) from a response mixed with code fences/chatter.
pub fn extract_json(raw: &str) -> Result<serde_json::Value> {
    let t = raw.trim();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(t) {
        return Ok(v);
    }
    if let Some(start) = t.find("```") {
        let after = &t[start + 3..];
        let after = after.strip_prefix("json").unwrap_or(after);
        if let Some(end) = after.find("```") {
            let body = after[..end].trim();
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
                return Ok(v);
            }
        }
    }
    if let (Some(s), Some(e)) = (t.find('{'), t.rfind('}')) {
        if s < e {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&t[s..=e]) {
                return Ok(v);
            }
        }
    }
    if let (Some(s), Some(e)) = (t.find('['), t.rfind(']')) {
        if s < e {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&t[s..=e]) {
                return Ok(v);
            }
        }
    }
    Err(anyhow!("JSON extraction failed: {}", truncate(t, 400)))
}

pub fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n).collect::<String>() + "…"
    }
}

/// serde's `#[serde(default)]` only fills in *missing* keys — if the model emits an explicit
/// `null` for an optional field (which happens in practice), deserialization still fails with
/// "invalid type: null, expected a string". This treats an explicit null the same as a missing
/// key. Discovered via an actual failed discourse round during smoke testing, not hypothetically.
pub fn null_to_default<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + serde::Deserialize<'de>,
{
    let opt: Option<T> = Option::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}

/// Same rationale as `null_to_default`, but for confidence-like fields where the codebase's
/// convention is `"UNKNOWN"` rather than an empty string.
pub fn null_to_unknown<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    Ok(opt.unwrap_or_else(|| "UNKNOWN".to_string()))
}
