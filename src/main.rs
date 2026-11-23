#![forbid(unsafe_code)]
//! Binary entrypoint for `nosih-caznsos` (NOSIH-CAZNSOS).

use clap::Parser;
use nosih_caznsos::app::AppState;
use nosih_caznsos::benchmark::run_self_test;
use nosih_caznsos::bootstrap::{CliArgs, init_tracing};
use nosih_caznsos::config::settings::Settings;
use nosih_caznsos::security::local_key::{ensure_admin_token, ensure_local_key};
use nosih_caznsos::server::router::build_router;
use nosih_caznsos::shutdown::shutdown_signal;
use std::net::SocketAddr;
use std::sync::Arc;

fn open_browser(url: &str) {
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("cmd")
        .args(["/C", "start", "", url])
        .spawn();
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(url).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let _ = std::process::Command::new("xdg-open").arg(url).spawn();
}

#[tokio::main]
async fn main() {
    let args = CliArgs::parse();
    init_tracing(&args.log_level);

    if args.self_test {
        match run_self_test(args.stub_provider).await {
            Ok(report) => {
                println!("{report}");
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("SELF-TEST FAILED: {e}");
                std::process::exit(1);
            }
        }
    }

    let mut settings = Settings::load_or_default(args.config.as_deref());
    if let Some(port) = args.port {
        settings.port = port;
    }
    if args.public {
        settings.host = "0.0.0.0".to_string();
    }
    if args.stub_provider {
        settings.stub_provider = true;
    }

    let (local_key, local_created) = match ensure_local_key(&settings.data_dir) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to initialize local key: {e}");
            std::process::exit(1);
        }
    };
    let (admin_token, admin_created) = match ensure_admin_token(&settings.data_dir) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to initialize admin token: {e}");
            std::process::exit(1);
        }
    };

    if local_created {
        println!("Local API key: {}", local_key.as_str());
    }
    if admin_created {
        println!("Admin token: {}", admin_token.as_str());
    }

    let state = match AppState::new(settings.clone(), local_key, admin_token) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("Failed to boot NOSIH-CAZNSOS AppState: {e}");
            std::process::exit(1);
        }
    };

    let addr_str = format!("{}:{}", settings.host, settings.port);
    let addr: SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Invalid listen address '{addr_str}': {e}");
            std::process::exit(1);
        }
    };

    let router = build_router(Arc::clone(&state));
    let url = format!("http://{addr}");
    println!("Listening on {url}");

    if !args.no_browser && !args.self_test {
        open_browser(&url);
    }

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind {addr}: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal(Arc::clone(&state)))
    .await
    {
        eprintln!("Server exited with error: {e}");
        std::process::exit(1);
    }
}
