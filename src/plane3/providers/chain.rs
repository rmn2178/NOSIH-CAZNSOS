//! Authorized upstream provider dispatch chain.
//!
//! `ProviderChain::call` REQUIRES `Authorized<ProviderCall>`, enforcing Plane I non-bypassability
//! at compile time.

use crate::config::secrets::SecretVault;
use crate::error::api_error::AppError;
use crate::error::result::AppResult;
use crate::plane3::providers::anthropic::call_anthropic;
use crate::plane3::providers::openai::call_openai_compat;
use crate::plane3::providers::traits::{ChatRequest, ProviderOutput};
use crate::types::authorized::{Authorized, ProviderCall};
use bytes::Bytes;
use reqwest::Client;
use secrecy::ExposeSecret;
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Multi-provider HTTP execution chain.
pub struct ProviderChain {
    client: Client,
    vault: Arc<SecretVault>,
    /// When true, uses deterministic local stub responses (for CI & `--self-test`).
    pub stub_mode: bool,
}

impl ProviderChain {
    /// Build a pooled rustls HTTP client.
    pub fn new(vault: Arc<SecretVault>, stub_mode: bool) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(120))
            .pool_max_idle_per_host(8)
            .build()
            .unwrap_or_else(|_| Client::new());
        Self {
            client,
            vault,
            stub_mode,
        }
    }

    /// Infer upstream provider family from concrete model name.
    pub fn infer_provider(model: &str) -> &'static str {
        let m = model.to_lowercase();
        if m.starts_with("claude") {
            "anthropic"
        } else if m.starts_with("gemini") {
            "gemini"
        } else if m.starts_with("llama") || m.starts_with("qwen") || m.starts_with("codellama") {
            "ollama"
        } else if m.starts_with("mixtral") {
            "groq"
        } else if m.starts_with("mistral") {
            "mistral"
        } else {
            "openai"
        }
    }

    /// Execute an upstream LLM call — **ONLY callable with a verified `Authorized<ProviderCall>`**.
    pub async fn call(
        &self,
        auth: Authorized<ProviderCall>,
        req: &ChatRequest,
    ) -> AppResult<ProviderOutput> {
        let provider = auth.payload().provider.clone();
        let model = auth.payload().model.clone();

        if self.stub_mode || provider == "stub" {
            return Ok(self.stub_response(&model, req));
        }

        let vault = Arc::clone(&self.vault);
        let provider_lookup = provider.clone();
        let resolved = tokio::task::spawn_blocking(move || {
            vault.resolve_for_provider(&provider_lookup)
        })
        .await
        .map_err(|e| AppError::Internal(format!("vault_join_err: {e}")))??;

        let (api_key_secret, base_url) = match resolved {
            Some(k) => (Some(k.api_key), k.base_url),
            None if provider == "ollama" => (None, None),
            None => {
                return Err(AppError::Upstream(format!(
                    "no_api_key_configured_for:{provider} (upload via UI Keys tab or POST /admin/keys)"
                )));
            }
        };
        let api_key_ref = api_key_secret
            .as_ref()
            .map(|s| s.expose_secret())
            .unwrap_or("");

        if provider == "anthropic" {
            call_anthropic(&self.client, base_url.as_deref(), api_key_ref, &model, req).await
        } else {
            call_openai_compat(
                &self.client,
                &provider,
                base_url.as_deref(),
                api_key_ref,
                &model,
                req,
            )
            .await
        }
    }

    fn stub_response(&self, model: &str, req: &ChatRequest) -> ProviderOutput {
        let prompt = req.primary_prompt();
        let reply = format!("[nosih-caznsos stub:{model}] {prompt}");
        let created = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let id = format!("chatcmpl-{}", Uuid::new_v4());
        let tin = prompt.split_whitespace().count().max(1) as u64;
        let tout = reply.split_whitespace().count().max(1) as u64;

        if req.stream.unwrap_or(false) {
            let c1 = json!({
                "id": id, "object": "chat.completion.chunk", "created": created, "model": model,
                "choices": [{"index": 0, "delta": {"role": "assistant", "content": reply}, "finish_reason": null}]
            });
            let c2 = json!({
                "id": id, "object": "chat.completion.chunk", "created": created, "model": model,
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
            });
            let sse = format!("data: {c1}\n\ndata: {c2}\n\ndata: [DONE]\n\n");
            ProviderOutput::Stream(Box::pin(futures::stream::once(async move {
                Ok(Bytes::from(sse))
            })))
        } else {
            let body = json!({
                "id": id,
                "object": "chat.completion",
                "created": created,
                "model": model,
                "choices": [{
                    "index": 0,
                    "message": { "role": "assistant", "content": reply },
                    "finish_reason": "stop"
                }],
                "usage": {
                    "prompt_tokens": tin,
                    "completion_tokens": tout,
                    "total_tokens": tin + tout
                }
            });
            ProviderOutput::Complete(body, tin, tout)
        }
    }
}
