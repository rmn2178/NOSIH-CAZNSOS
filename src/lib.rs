#![forbid(unsafe_code)]
#![allow(clippy::collapsible_if)]
//! NOSIH-CAZNSOS (`nosih-caznsos`): Zero-trust, carbon-aware multi-provider OpenAI-compatible LLM proxy.

pub mod app;
pub mod benchmark;
pub mod bootstrap;
pub mod config;
pub mod error;
pub mod kernel;
pub mod plane1;
pub mod plane2;
pub mod plane3;
pub mod security;
pub mod server;
pub mod shutdown;
pub mod storage;
pub mod telemetry;
pub mod types;
pub mod ui;
