//! Common OpenAI-compatible request/response types for upstream provider adapters.

use crate::error::result::AppResult;
use bytes::Bytes;
use futures::Stream;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::pin::Pin;

/// Boxed async SSE byte stream.
pub type SseStream = Pin<Box<dyn Stream<Item = AppResult<Bytes>> + Send>>;

/// OpenAI chat message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    /// Role (`system`, `user`, `assistant`, `tool`).
    pub role: String,
    /// Content (plain text or multi-part JSON).
    #[serde(default)]
    pub content: Value,
}

impl ChatMessage {
    /// Extract plain text from string or multi-part content.
    pub fn text(&self) -> String {
        if let Some(s) = self.content.as_str() {
            return s.to_string();
        }
        if let Some(arr) = self.content.as_array() {
            return arr
                .iter()
                .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
                .collect::<Vec<_>>()
                .join("\n");
        }
        String::new()
    }
}

/// Incoming OpenAI `/v1/chat/completions` payload with unknown-field passthrough.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRequest {
    /// Target model or virtual router alias (`nosih-auto`, `nosih-symbolic`, etc.).
    pub model: String,
    /// Conversation messages.
    pub messages: Vec<ChatMessage>,
    /// Whether to stream SSE chunks.
    #[serde(default)]
    pub stream: Option<bool>,
    /// Sampling temperature.
    #[serde(default)]
    pub temperature: Option<f64>,
    /// Nucleus sampling `top_p`.
    #[serde(default)]
    pub top_p: Option<f64>,
    /// Maximum output tokens.
    #[serde(default)]
    pub max_tokens: Option<u32>,
    /// Optional tool definitions.
    #[serde(default)]
    pub tools: Option<Vec<Value>>,
    /// Optional tool choice.
    #[serde(default)]
    pub tool_choice: Option<Value>,
    /// Optional response format (e.g. `json_object`).
    #[serde(default)]
    pub response_format: Option<Value>,
    /// Pass-through of unknown OpenAI-compatible fields to upstream providers.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

impl ChatRequest {
    /// Extract latest user prompt for profiling and caching.
    pub fn primary_prompt(&self) -> String {
        for m in self.messages.iter().rev() {
            if m.role == "user" {
                let t = m.text();
                if !t.trim().is_empty() {
                    return t;
                }
            }
        }
        self.messages.iter().map(ChatMessage::text).collect::<Vec<_>>().join("\n")
    }
}

/// Unified provider execution result.
pub enum ProviderOutput {
    /// Complete JSON response body + token usage `(in, out)`.
    Complete(Value, u64, u64),
    /// Live OpenAI-formatted SSE byte stream.
    Stream(SseStream),
}
