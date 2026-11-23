//! Native Anthropic Messages API adapter with OpenAI-shaped response and SSE translation.

use crate::error::api_error::AppError;
use crate::error::result::AppResult;
use crate::plane3::providers::traits::{ChatRequest, ProviderOutput};
use bytes::Bytes;
use reqwest::Client;
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Call Anthropic `/v1/messages` and return an OpenAI-compatible response or SSE stream.
pub async fn call_anthropic(
    client: &Client,
    base_url: Option<&str>,
    api_key: &str,
    model: &str,
    req: &ChatRequest,
) -> AppResult<ProviderOutput> {
    let base = base_url.unwrap_or("https://api.anthropic.com/v1");
    let url = format!("{}/messages", base.trim_end_matches('/'));

    let mut system_parts = Vec::new();
    let mut msgs = Vec::new();
    for m in &req.messages {
        if m.role == "system" {
            system_parts.push(m.text());
        } else {
            let role = if m.role == "assistant" { "assistant" } else { "user" };
            msgs.push(json!({ "role": role, "content": m.text() }));
        }
    }

    let mut payload = json!({
        "model": model,
        "max_tokens": req.max_tokens.unwrap_or(4096),
        "messages": msgs,
    });
    if !system_parts.is_empty() {
        payload["system"] = Value::String(system_parts.join("\n\n"));
    }

    let resp = client
        .post(url)
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .json(&payload)
        .send()
        .await
        .map_err(|e| AppError::Upstream(format!("anthropic: {e}")))?;

    if !resp.status().is_success() {
        return Err(AppError::Upstream(format!(
            "anthropic returned HTTP {}",
            resp.status()
        )));
    }

    let body: Value = resp
        .json()
        .await
        .map_err(|e| AppError::Upstream(format!("anthropic json: {e}")))?;
    let text = body
        .get("content")
        .and_then(|c| c.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_default();
    let tin = body.pointer("/usage/input_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
    let tout = body.pointer("/usage/output_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
    let created = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let id = format!("chatcmpl-{}", Uuid::new_v4());

    if req.stream.unwrap_or(false) {
        let c1 = json!({
            "id": id, "object": "chat.completion.chunk", "created": created, "model": model,
            "choices": [{"index": 0, "delta": {"role": "assistant", "content": text}, "finish_reason": null}]
        });
        let c2 = json!({
            "id": id, "object": "chat.completion.chunk", "created": created, "model": model,
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
        });
        let sse = format!("data: {c1}\n\ndata: {c2}\n\ndata: [DONE]\n\n");
        return Ok(ProviderOutput::Stream(Box::pin(futures::stream::once(async move {
            Ok(Bytes::from(sse))
        }))));
    }

    let openai_json = json!({
        "id": id,
        "object": "chat.completion",
        "created": created,
        "model": model,
        "choices": [{
            "index": 0,
            "message": { "role": "assistant", "content": text },
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": tin,
            "completion_tokens": tout,
            "total_tokens": tin + tout
        }
    });
    Ok(ProviderOutput::Complete(openai_json, tin, tout))
}
