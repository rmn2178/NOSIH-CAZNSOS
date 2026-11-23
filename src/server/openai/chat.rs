//! `POST /v1/chat/completions` (streaming & non-streaming) and `POST /v1/embeddings`.

use crate::app::AppState;
use crate::error::api_error::AppError;
use crate::error::result::AppResult;
use crate::kernel::NosihKernel;
use crate::kernel::request::KernelContext;
use crate::kernel::stage1_ingress::run_stage1;
use crate::kernel::stage2_cache::run_stage2;
use crate::kernel::stage3_dispatch::run_stage3;
use crate::kernel::stage4_verify::run_stage4;
use crate::kernel::stage5_mint::run_stage5;
use crate::kernel::stage6_execute::run_stage6;
use crate::kernel::stage7_update::run_stage7;
use crate::plane3::providers::traits::{ChatRequest, ProviderOutput, SseStream};
use crate::server::openai::auth::LocalAuthInfo;
use axum::body::Body;
use axum::extract::{Extension, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::Json;
use bytes::Bytes;
use futures::StreamExt;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

struct StreamTeeState {
    stream: SseStream,
    kernel: Arc<NosihKernel>,
    ctx: KernelContext,
    t0: Instant,
    warmup_j: f64,
    tokens_in: u64,
    tokens_out_usage: Option<u64>,
    accumulated: String,
    line_buf: String,
    had_error: bool,
}

fn parse_sse_line(
    line: &str,
    accumulated: &mut String,
    tokens_in: &mut u64,
    tokens_out_usage: &mut Option<u64>,
) {
    let trimmed = line.trim();
    let Some(data) = trimmed.strip_prefix("data:") else {
        return;
    };
    let payload = data.trim();
    if payload.is_empty() || payload == "[DONE]" {
        return;
    }
    if let Ok(v) = serde_json::from_str::<Value>(payload) {
        if let Some(delta) = v
            .pointer("/choices/0/delta/content")
            .and_then(|c| c.as_str())
        {
            accumulated.push_str(delta);
        }
        if let Some(pt) = v.pointer("/usage/prompt_tokens").and_then(|n| n.as_u64()) {
            *tokens_in = pt;
        }
        if let Some(ct) = v
            .pointer("/usage/completion_tokens")
            .and_then(|n| n.as_u64())
        {
            *tokens_out_usage = Some(ct);
        }
    }
}

fn extract_sse_delta(
    chunk: &[u8],
    line_buf: &mut String,
    accumulated: &mut String,
    tokens_in: &mut u64,
    tokens_out_usage: &mut Option<u64>,
) {
    let text = String::from_utf8_lossy(chunk);
    line_buf.push_str(&text);
    while let Some(pos) = line_buf.find('\n') {
        let line: String = line_buf.drain(..=pos).collect();
        parse_sse_line(&line, accumulated, tokens_in, tokens_out_usage);
    }
}

/// Main OpenAI-compatible chat completions endpoint running the 7-stage NOSIH kernel.
pub async fn chat_completions(
    State(state): State<Arc<AppState>>,
    Extension(auth_info): Extension<LocalAuthInfo>,
    body_bytes: Bytes,
) -> AppResult<Response> {
    let t0 = Instant::now();
    let req: ChatRequest = serde_json::from_slice(&body_bytes)
        .map_err(|e| AppError::BadRequest(format!("invalid_chat_request: {e}")))?;
    if req.messages.is_empty() {
        return Err(AppError::BadRequest("messages_empty".into()));
    }
    let prompt = req.primary_prompt();
    let is_stream = req.stream.unwrap_or(false);

    // Stage 1: Strict JCS ingress + provenance binding + 10D CPU profiling
    let (mut ctx, _validated) =
        run_stage1(&state.kernel, &body_bytes, &req.model, &prompt, &auth_info.origin).await?;

    // Stage 2: PS-RCSC provenance-scoped semantic cache
    let cache_hit = run_stage2(&state.kernel, &ctx).await;
    if cache_hit.hit {
        if let Some(ans) = cache_hit.response {
            let model = cache_hit.model.unwrap_or_else(|| "nosih-cache".into());
            let (co2_g, leaf) = run_stage7(
                &state.kernel,
                &ctx,
                &ans,
                prompt.split_whitespace().count() as u64,
                ans.split_whitespace().count() as u64,
                t0.elapsed().as_secs_f64() * 1000.0,
                0.0,
                true,
            )
            .await;
            return Ok(build_local_response(&model, &ans, is_stream, co2_g, leaf));
        }
    }

    // Stage 3: Carbon-conformal dispatch + PCSP + CPU symbolic check
    let settings = state.settings.read().await.clone();
    if let Some(sym_ans) = run_stage3(&state.kernel, &mut ctx, &settings).await {
        let (co2_g, leaf) = run_stage7(
            &state.kernel,
            &ctx,
            &sym_ans,
            prompt.split_whitespace().count() as u64,
            sym_ans.split_whitespace().count() as u64,
            t0.elapsed().as_secs_f64() * 1000.0,
            0.0,
            true,
        )
        .await;
        return Ok(build_local_response(
            "nosih-symbolic",
            &sym_ans,
            is_stream,
            co2_g,
            leaf,
        ));
    }

    // Stage 4: Static Kahn + IFC DAG verification
    run_stage4(&state.kernel, &ctx).await?;

    // Stage 5: Mint, attenuate & verify SPCCE-Macaroon -> Authorized<ProviderCall>
    let auth_call = run_stage5(&state.kernel, &mut ctx).await?;

    // Stage 6: Pre-authorized PA-PCS-PMC warmup + upstream execution
    let (output, warmup_j) =
        run_stage6(&state.kernel, &state.providers, &ctx, auth_call, &req).await?;

    match output {
        ProviderOutput::Stream(stream) => {
            let tier_str = ctx.selected_tier.as_str().to_string();
            let tee_state = StreamTeeState {
                stream,
                kernel: Arc::clone(&state.kernel),
                ctx,
                t0,
                warmup_j,
                tokens_in: prompt.split_whitespace().count().max(1) as u64,
                tokens_out_usage: None,
                accumulated: String::new(),
                line_buf: String::new(),
                had_error: false,
            };
            let inspected = futures::stream::unfold(tee_state, |mut st| async move {
                match st.stream.next().await {
                    Some(Ok(chunk)) => {
                        extract_sse_delta(
                            &chunk,
                            &mut st.line_buf,
                            &mut st.accumulated,
                            &mut st.tokens_in,
                            &mut st.tokens_out_usage,
                        );
                        Some((Ok(chunk), st))
                    }
                    Some(Err(e)) => {
                        st.had_error = true;
                        Some((Err(e), st))
                    }
                    None => {
                        if !st.line_buf.is_empty() {
                            let rem = std::mem::take(&mut st.line_buf);
                            parse_sse_line(
                                &rem,
                                &mut st.accumulated,
                                &mut st.tokens_in,
                                &mut st.tokens_out_usage,
                            );
                        }
                        let tout = st.tokens_out_usage.unwrap_or_else(|| {
                            st.accumulated.split_whitespace().count() as u64
                        });
                        let _ = run_stage7(
                            &st.kernel,
                            &st.ctx,
                            &st.accumulated,
                            st.tokens_in,
                            tout,
                            st.t0.elapsed().as_secs_f64() * 1000.0,
                            st.warmup_j,
                            !st.had_error,
                        )
                        .await;
                        None
                    }
                }
            });

            let mut resp = Response::new(Body::from_stream(inspected));
            *resp.status_mut() = StatusCode::OK;
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/event-stream"),
            );
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
            if let Ok(hv) = HeaderValue::from_str(&tier_str) {
                resp.headers_mut().insert("x-nosih-tier", hv);
            }
            Ok(resp)
        }
        ProviderOutput::Complete(body_json, tin, tout) => {
            let reply_txt = body_json
                .pointer("/choices/0/message/content")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let (co2_g, leaf) = run_stage7(
                &state.kernel,
                &ctx,
                reply_txt,
                tin,
                tout,
                t0.elapsed().as_secs_f64() * 1000.0,
                warmup_j,
                true,
            )
            .await;
            let mut resp = Json(body_json).into_response();
            if let Ok(hv) = HeaderValue::from_str(ctx.selected_tier.as_str()) {
                resp.headers_mut().insert("x-nosih-tier", hv);
            }
            if let Ok(hv) = HeaderValue::from_str(&format!("{co2_g:.6}")) {
                resp.headers_mut().insert("x-nosih-co2-g", hv);
            }
            if let Some(l) = leaf {
                if let Ok(hv) = HeaderValue::from_str(&l.to_string()) {
                    resp.headers_mut().insert("x-nosih-merkle-leaf", hv);
                }
            }
            Ok(resp)
        }
    }
}

fn build_local_response(
    model: &str,
    content: &str,
    is_stream: bool,
    co2_g: f64,
    leaf: Option<usize>,
) -> Response {
    let created = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let id = format!("chatcmpl-{}", Uuid::new_v4());
    let mut resp = if is_stream {
        let c1 = json!({
            "id": id, "object": "chat.completion.chunk", "created": created, "model": model,
            "choices": [{"index": 0, "delta": {"role": "assistant", "content": content}, "finish_reason": null}]
        });
        let c2 = json!({
            "id": id, "object": "chat.completion.chunk", "created": created, "model": model,
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
        });
        let sse = format!("data: {c1}\n\ndata: {c2}\n\ndata: [DONE]\n\n");
        let mut r = Response::new(Body::from(sse));
        *r.status_mut() = StatusCode::OK;
        r.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/event-stream"),
        );
        r
    } else {
        Json(json!({
            "id": id,
            "object": "chat.completion",
            "created": created,
            "model": model,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
        }))
        .into_response()
    };
    if let Ok(hv) = HeaderValue::from_str(&format!("{co2_g:.6}")) {
        resp.headers_mut().insert("x-nosih-co2-g", hv);
    }
    if let Some(l) = leaf {
        if let Ok(hv) = HeaderValue::from_str(&l.to_string()) {
            resp.headers_mut().insert("x-nosih-merkle-leaf", hv);
        }
    }
    resp
}

/// Deterministic local/proxied `POST /v1/embeddings` endpoint (320D signed feature-hash fallback).
pub async fn embeddings(Json(req): Json<Value>) -> AppResult<Json<Value>> {
    let model = req
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("nosih-embed-320d");
    let input = req
        .get("input")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let vec = crate::plane2::cache::search::embed_320d(input);
    Ok(Json(json!({
        "object": "list",
        "model": model,
        "data": [{
            "object": "embedding",
            "index": 0,
            "embedding": vec.to_vec(),
        }],
        "usage": { "prompt_tokens": input.split_whitespace().count(), "total_tokens": input.split_whitespace().count() }
    })))
}
