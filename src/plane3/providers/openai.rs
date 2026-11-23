//! Universal OpenAI-compatible adapter covering OpenAI, Gemini, Groq, Mistral, Together, OpenRouter, Cohere, Ollama, Azure, and custom endpoints.

use crate::error::api_error::AppError;
use crate::error::result::AppResult;
use crate::plane3::providers::traits::{ChatRequest, ProviderOutput};
use futures::TryStreamExt;
use reqwest::Client;
use serde_json::Value;

/// Resolve default base URL for known OpenAI-compatible providers.
pub fn default_base_url(provider: &str) -> &'static str {
    match provider {
        "openai" => "https://api.openai.com/v1",
        "groq" => "https://api.groq.com/openai/v1",
        "mistral" => "https://api.mistral.ai/v1",
        "together" => "https://api.together.xyz/v1",
        "openrouter" => "https://openrouter.ai/api/v1",
        "gemini" => "https://generativelanguage.googleapis.com/v1beta/openai",
        "cohere" => "https://api.cohere.ai/compatibility/v1",
        "ollama" => "http://127.0.0.1:11434/v1",
        _ => "https://api.openai.com/v1",
    }
}

/// Execute an OpenAI-compatible chat completion (streaming or non-streaming).
pub async fn call_openai_compat(
    client: &Client,
    provider: &str,
    base_url: Option<&str>,
    api_key: &str,
    model: &str,
    req: &ChatRequest,
) -> AppResult<ProviderOutput> {
    let base = base_url.unwrap_or_else(|| default_base_url(provider));
    let url = format!("{}/chat/completions", base.trim_end_matches('/'));
    let mut payload = req.clone();
    payload.model = model.to_string();
    let is_stream = payload.stream.unwrap_or(false);

    let mut builder = client.post(url).json(&payload);
    if !api_key.is_empty() {
        builder = builder.bearer_auth(api_key);
    }

    let resp = builder
        .send()
        .await
        .map_err(|e| AppError::Upstream(format!("{provider}: {e}")))?;

    if !resp.status().is_success() {
        return Err(AppError::Upstream(format!(
            "{provider} returned HTTP {}",
            resp.status()
        )));
    }

    if is_stream {
        let p = provider.to_string();
        let stream = resp
            .bytes_stream()
            .map_err(move |e| AppError::Upstream(format!("{p}: {e}")));
        Ok(ProviderOutput::Stream(Box::pin(stream)))
    } else {
        let body: Value = resp
            .json()
            .await
            .map_err(|e| AppError::Upstream(format!("{provider} json: {e}")))?;
        let tin = body.pointer("/usage/prompt_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
        let tout = body.pointer("/usage/completion_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
        Ok(ProviderOutput::Complete(body, tin, tout))
    }
}
