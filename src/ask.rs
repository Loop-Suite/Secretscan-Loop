use crate::input::Input;
use crate::llm::Llm;
use crate::promptctx::{shared_context, UNTRUSTED_DATA_SYSTEM_NOTE};
use crate::spec::Spec;
use anyhow::{Context, Result};

pub const ASK_SYSTEM: &str = "You answer questions about a secret-scan run. \
Ground answers in the candidates/findings given. Never restate a raw secret value. \
Say you don't know if there's no basis for an answer.";

pub fn run(llm: &Llm, spec: &Spec, input: &Input, question: &str) -> Result<String> {
    let ctx = shared_context(spec, input);
    let task = format!("# Question\n{question}\n");
    let system = format!("{ASK_SYSTEM}\n\n{UNTRUSTED_DATA_SYSTEM_NOTE}");
    llm.text_ctx(Some(&ctx), &task, Some(&system)).context("ask failed")
}
