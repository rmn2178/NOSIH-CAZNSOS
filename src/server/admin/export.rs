//! Universal Multi-Format Exporter (JSON, JSONL, CSV, TSV, Markdown, TXT, XML, OTel, Merkle, SVG, HTML)
//! and Pure-Rust Light/Dark Monochrome SVG Graph & Visualization Engine.

use crate::app::AppState;
use crate::config::paths::default_export_dir;
use crate::error::api_error::AppError;
use crate::error::result::AppResult;
use crate::kernel::trace::KernelEvent;
use axum::extract::{Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Query parameters for `GET`/`POST /admin/export`.
#[derive(Debug, Deserialize)]
pub struct ExportQuery {
    /// Export format: `json`, `jsonl`, `csv`, `tsv`, `md`, `txt`, `xml`, `otel`, `merkle`, `svg`, or `html`.
    #[serde(default = "default_fmt")]
    pub format: String,
    /// Optional leaf index when `format=merkle`.
    pub leaf: Option<usize>,
    /// Optional request ID filter for single-request audit trail export.
    pub request_id: Option<String>,
    /// If true, write file directly into `~/Downloads/`.
    #[serde(default)]
    pub save_to_disk: bool,
    /// If true, return raw file bytes with `Content-Disposition: attachment` for direct browser download.
    #[serde(default)]
    pub download: bool,
    /// Optional theme (`dark` or `light`) for `svg`/`html` exports.
    #[serde(default = "default_theme")]
    pub theme: String,
}

/// Query parameters for `GET /admin/viz/svg`.
#[derive(Debug, Deserialize)]
pub struct VizQuery {
    /// Chart selector: `all`, `carbon`, `latency`, or `planes`.
    #[serde(default = "default_chart")]
    pub chart: String,
    /// Theme palette: `dark` (default) or `light`.
    #[serde(default = "default_theme")]
    pub theme: String,
}

fn default_fmt() -> String {
    "json".to_string()
}

fn default_chart() -> String {
    "all".to_string()
}

fn default_theme() -> String {
    "dark".to_string()
}

struct SvgPalette {
    outer_bg: &'static str,
    panel_bg: &'static str,
    border: &'static str,
    axis: &'static str,
    title: &'static str,
    muted: &'static str,
    line: &'static str,
    area_fill: &'static str,
    bar1: &'static str,
    bar2: &'static str,
    bar3: &'static str,
    bar4: &'static str,
}

fn palette(is_light: bool) -> SvgPalette {
    if is_light {
        SvgPalette {
            outer_bg: "#f4f4f5",
            panel_bg: "#ffffff",
            border: "#d4d4d8",
            axis: "#a1a1aa",
            title: "#09090b",
            muted: "#52525b",
            line: "#09090b",
            area_fill: "#09090b",
            bar1: "#09090b",
            bar2: "#3f3f46",
            bar3: "#71717a",
            bar4: "#a1a1aa",
        }
    } else {
        SvgPalette {
            outer_bg: "#050505",
            panel_bg: "#0f0f10",
            border: "#27272a",
            axis: "#3f3f46",
            title: "#fafafa",
            muted: "#a1a1aa",
            line: "#ffffff",
            area_fill: "#ffffff",
            bar1: "#ffffff",
            bar2: "#d4d4d8",
            bar3: "#a1a1aa",
            bar4: "#71717a",
        }
    }
}

/// Pure-Rust SVG Graph endpoint (`GET /admin/viz/svg?chart=all|carbon|latency|planes&theme=dark|light`).
pub async fn render_viz_svg(
    State(state): State<Arc<AppState>>,
    Query(q): Query<VizQuery>,
) -> Response {
    let events = state.log_ring.snapshot().await;
    let curve: Vec<(f64, f64)> = {
        let fc = state.kernel.forecaster.read().await;
        (0..=24)
            .map(|h| (h as f64, fc.deterministic_intensity(h as f64)))
            .collect()
    };
    let current_carbon = state.kernel.forecaster.read().await.current().gco2_per_kwh;
    let is_light = q.theme.eq_ignore_ascii_case("light");

    let svg = match q.chart.to_lowercase().as_str() {
        "carbon" => svg_carbon_chart(&curve, current_carbon, is_light),
        "latency" => svg_latency_chart(&events, is_light),
        "planes" => svg_plane_bars(&events, is_light),
        _ => svg_dashboard(&curve, current_carbon, &events, is_light),
    };

    let mut resp = (StatusCode::OK, svg).into_response();
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("image/svg+xml; charset=utf-8"));
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    resp
}

/// Export redacted audit logs, Merkle proofs, or pure-Rust visualizations in any supported format.
pub async fn export_logs(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ExportQuery>,
) -> AppResult<Response> {
    let mut events = state.log_ring.snapshot().await;
    if let Some(req_id) = &q.request_id {
        if !req_id.trim().is_empty() {
            events.retain(|e| e.request_id == req_id.trim());
        }
    }

    let curve: Vec<(f64, f64)> = {
        let fc = state.kernel.forecaster.read().await;
        (0..=24)
            .map(|h| (h as f64, fc.deterministic_intensity(h as f64)))
            .collect()
    };
    let current_carbon = state.kernel.forecaster.read().await.current().gco2_per_kwh;
    let merkle_for_sth = Arc::clone(&state.kernel.merkle);
    let sth_opt = tokio::task::spawn_blocking(move || merkle_for_sth.latest_sth().ok())
        .await
        .ok()
        .flatten();
    let is_light = q.theme.eq_ignore_ascii_case("light");

    let fmt = q.format.trim().to_lowercase();
    let (ext, mime, content): (&str, &str, String) = match fmt.as_str() {
        "json" => {
            let plane_counts = count_by_plane(&events);
            let total_co2: f64 = events.iter().filter_map(|e| e.co2_g).sum();
            let doc = json!({
                "meta": {
                    "app": "NOSIH-CAZNSOS",
                    "version": env!("CARGO_PKG_VERSION"),
                    "exported_at": chrono::Utc::now().to_rfc3339(),
                    "event_count": events.len(),
                },
                "summary": {
                    "current_carbon_gco2_kwh": current_carbon,
                    "total_co2_g": total_co2,
                    "plane_counts": plane_counts,
                    "merkle_root": sth_opt.as_ref().map(|s| s.root_hash_hex.clone()),
                    "merkle_tree_size": sth_opt.as_ref().map(|s| s.tree_size).unwrap_or(0),
                },
                "diurnal_carbon_curve": curve.iter().map(|(h, c)| json!({"hour": h, "gco2_kwh": c})).collect::<Vec<_>>(),
                "events": events,
            });
            ("json", "application/json", serde_json::to_string_pretty(&doc).unwrap_or_default())
        }
        "csv" => ("csv", "text/csv", format_delimited(&events, ',')),
        "tsv" => ("tsv", "text/tab-separated-values", format_delimited(&events, '\t')),
        "md" | "markdown" => ("md", "text/markdown", format_markdown(&events, current_carbon)),
        "txt" | "text" => ("txt", "text/plain", format_plain_text(&events)),
        "xml" => ("xml", "application/xml", format_xml(&events)),
        "otel" => {
            let spans: Vec<Value> = events
                .iter()
                .map(|e| {
                    json!({
                        "traceId": e.request_id,
                        "name": e.stage,
                        "attributes": [
                            {"key": "nosih.plane", "value": {"stringValue": e.plane}},
                            {"key": "nosih.decision", "value": {"stringValue": e.decision}},
                            {"key": "nosih.integrity", "value": {"stringValue": e.integrity}},
                            {"key": "nosih.latency_us", "value": {"intValue": e.latency_us}},
                        ]
                    })
                })
                .collect();
            let doc = json!({ "resourceSpans": [{ "scopeSpans": [{ "spans": spans }] }] });
            ("otel.json", "application/json", serde_json::to_string_pretty(&doc).unwrap_or_default())
        }
        "merkle" => {
            let merkle_for_export = Arc::clone(&state.kernel.merkle);
            let sth = tokio::task::spawn_blocking(move || merkle_for_export.latest_sth())
                .await
                .map_err(|e| AppError::Internal(format!("merkle_join_err: {e}")))??;
            let doc = if sth.tree_size == 0 {
                json!({
                    "tree_size": 0,
                    "root_hash_hex": sth.root_hash_hex,
                    "sth_signature_hex": sth.signature_hex,
                    "inclusion_proof": [],
                    "note": "no_leaves_committed_yet"
                })
            } else {
                let idx = q.leaf.unwrap_or_else(|| sth.tree_size.saturating_sub(1));
                let merkle_for_proof = Arc::clone(&state.kernel.merkle);
                let (proof, sth, payload) =
                    tokio::task::spawn_blocking(move || merkle_for_proof.inclusion_proof(idx))
                        .await
                        .map_err(|e| AppError::Internal(format!("merkle_join_err: {e}")))??;
                json!({
                    "tree_size": sth.tree_size,
                    "leaf_index": idx,
                    "root_hash_hex": sth.root_hash_hex,
                    "sth_signature_hex": sth.signature_hex,
                    "payload_jcs": String::from_utf8_lossy(&payload),
                    "inclusion_proof": proof,
                })
            };
            ("merkle.json", "application/json", serde_json::to_string_pretty(&doc).unwrap_or_default())
        }
        "svg" => ("svg", "image/svg+xml", svg_dashboard(&curve, current_carbon, &events, is_light)),
        "html" => {
            let svg = svg_dashboard(&curve, current_carbon, &events, is_light);
            let p = palette(is_light);
            let html = format!(
                "<!doctype html><html><head><meta charset='utf-8'><title>NOSIH-CAZNSOS Visual Report</title>\
                 <style>body{{background:{bg};color:{fg};font-family:system-ui,sans-serif;padding:24px;max-width:1040px;margin:auto}}\
                 h1{{font-size:20px;margin-bottom:14px}}svg{{width:100%;height:auto;border:1px solid {bd};border-radius:10px}}</style>\
                 </head><body><h1>NOSIH-CAZNSOS — Pure-Rust Telemetry &amp; Carbon Visual Report ({cnt} events)</h1>{svg}</body></html>",
                bg = p.outer_bg,
                fg = p.title,
                bd = p.border,
                cnt = events.len(),
                svg = svg
            );
            ("html", "text/html", html)
        }
        _ => {
            let mut out = String::new();
            for e in &events {
                if let Ok(line) = serde_json::to_string(e) {
                    out.push_str(&line);
                    out.push('\n');
                }
            }
            ("jsonl", "application/x-ndjson", out)
        }
    };

    if q.download {
        let fname = format!(
            "nosih-caznsos-export-{}.{ext}",
            chrono::Utc::now().format("%Y%m%d-%H%M%S")
        );
        let mut resp = (StatusCode::OK, content).into_response();
        if let Ok(ct) = HeaderValue::from_str(mime) {
            resp.headers_mut().insert(header::CONTENT_TYPE, ct);
        }
        if let Ok(cd) = HeaderValue::from_str(&format!("attachment; filename=\"{fname}\"")) {
            resp.headers_mut().insert(header::CONTENT_DISPOSITION, cd);
        }
        return Ok(resp);
    }

    let saved_path = if q.save_to_disk {
        let dir = default_export_dir();
        let _ = tokio::fs::create_dir_all(&dir).await;
        let fname = format!(
            "nosih-caznsos-export-{}.{ext}",
            chrono::Utc::now().format("%Y%m%d-%H%M%S")
        );
        let full = dir.join(fname);
        tokio::fs::write(&full, &content)
            .await
            .map_err(|e| AppError::Internal(format!("export_write_failed: {e}")))?;
        Some(full.display().to_string())
    } else {
        None
    };

    Ok(Json(json!({
        "format": fmt,
        "extension": ext,
        "count": events.len(),
        "saved_path": saved_path,
        "content": content,
    }))
    .into_response())
}

fn count_by_plane(events: &[KernelEvent]) -> BTreeMap<String, usize> {
    let mut map = BTreeMap::new();
    for e in events {
        *map.entry(e.plane.clone()).or_insert(0) += 1;
    }
    map
}

fn csv_cell(s: &str, sep: char) -> String {
    if s.contains(sep) || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn format_delimited(events: &[KernelEvent], sep: char) -> String {
    let mut out = format!(
        "ts{sep}request_id{sep}stage{sep}plane{sep}severity{sep}latency_us{sep}tokens_in{sep}tokens_out{sep}cost_usd{sep}co2_g{sep}integrity{sep}confidentiality{sep}decision\n"
    );
    for e in events {
        out.push_str(&format!(
            "{}{sep}{}{sep}{}{sep}{}{sep}{}{sep}{}{sep}{}{sep}{}{sep}{}{sep}{}{sep}{}{sep}{}{sep}{}\n",
            csv_cell(&e.ts, sep),
            csv_cell(&e.request_id, sep),
            csv_cell(&e.stage, sep),
            csv_cell(&e.plane, sep),
            csv_cell(&e.severity, sep),
            e.latency_us,
            e.tokens_in.map(|v| v.to_string()).unwrap_or_default(),
            e.tokens_out.map(|v| v.to_string()).unwrap_or_default(),
            csv_cell(e.cost_usd.as_deref().unwrap_or(""), sep),
            e.co2_g.map(|v| format!("{v:.6}")).unwrap_or_default(),
            csv_cell(&e.integrity, sep),
            csv_cell(&e.confidentiality, sep),
            csv_cell(&e.decision, sep)
        ));
    }
    out
}

fn format_markdown(events: &[KernelEvent], current_carbon: f64) -> String {
    let mut out = format!(
        "# NOSIH-CAZNSOS Audit Report\n\n- **Total Events:** {}\n- **Current Grid Carbon:** {:.1} gCO2eq/kWh\n\n| Timestamp | Request ID | Stage | Plane | Latency (us) | Decision |\n| :--- | :--- | :--- | :--- | ---: | :--- |\n",
        events.len(),
        current_carbon
    );
    for e in events.iter().take(200) {
        out.push_str(&format!(
            "| {} | `{}` | `{}` | {} | {} | {} |\n",
            e.ts,
            e.request_id,
            e.stage,
            e.plane,
            e.latency_us,
            e.decision.replace('|', "\\|")
        ));
    }
    out
}

fn format_plain_text(events: &[KernelEvent]) -> String {
    let mut out = String::new();
    for e in events {
        out.push_str(&format!(
            "[{}] {} {} ({}) latency={}us decision={} — {}\n",
            e.ts, e.request_id, e.stage, e.plane, e.latency_us, e.decision, e.summary
        ));
    }
    out
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn format_xml(events: &[KernelEvent]) -> String {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<nosih_audit>\n");
    for e in events {
        out.push_str(&format!(
            "  <event ts=\"{}\" request_id=\"{}\" stage=\"{}\" plane=\"{}\" latency_us=\"{}\" decision=\"{}\">{}</event>\n",
            xml_escape(&e.ts),
            xml_escape(&e.request_id),
            xml_escape(&e.stage),
            xml_escape(&e.plane),
            e.latency_us,
            xml_escape(&e.decision),
            xml_escape(&e.summary)
        ));
    }
    out.push_str("</nosih_audit>\n");
    out
}

/// Pure-Rust Monochrome SVG: 24-Hour Diurnal Grid Carbon Curve.
pub fn svg_carbon_chart(curve: &[(f64, f64)], current_carbon: f64, is_light: bool) -> String {
    let p = palette(is_light);
    let (w, h) = (480.0_f64, 210.0_f64);
    let (pad_l, pad_r, pad_t, pad_b) = (46.0_f64, 18.0_f64, 34.0_f64, 28.0_f64);
    let plot_w = w - pad_l - pad_r;
    let plot_h = h - pad_t - pad_b;
    let (min_y, max_y) = (150.0_f64, 550.0_f64);

    let mut pts = Vec::with_capacity(curve.len());
    for &(hr, c) in curve {
        let x = pad_l + (hr / 24.0) * plot_w;
        let y = pad_t + plot_h - ((c - min_y) / (max_y - min_y)).clamp(0.0, 1.0) * plot_h;
        pts.push(format!("{x:.1},{y:.1}"));
    }
    let polyline = pts.join(" ");
    let area = format!(
        "{pad_l:.1},{:.1} {polyline} {:.1},{:.1}",
        pad_t + plot_h,
        pad_l + plot_w,
        pad_t + plot_h
    );

    format!(
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 480 210' width='480' height='210'>\
         <rect width='480' height='210' rx='8' fill='{bg}' stroke='{bd}'/>\
         <text x='16' y='22' fill='{title}' font-family='system-ui,sans-serif' font-size='12' font-weight='600'>DIURNAL GRID CARBON C(t) — NOW: {current_carbon:.1} gCO2/kWh</text>\
         <line x1='{pad_l}' y1='{pad_t}' x2='{pad_l}' y2='{b}' stroke='{ax}'/>\
         <line x1='{pad_l}' y1='{b}' x2='{r}' y2='{b}' stroke='{ax}'/>\
         <polygon points='{area}' fill='{af}' fill-opacity='0.09'/>\
         <polyline points='{polyline}' fill='none' stroke='{ln}' stroke-width='2.2'/>\
         <text x='8' y='44' fill='{mt}' font-family='monospace' font-size='10'>550</text>\
         <text x='8' y='182' fill='{mt}' font-family='monospace' font-size='10'>150</text>\
         <text x='46' y='198' fill='{mt}' font-family='monospace' font-size='10'>00h</text>\
         <text x='246' y='198' fill='{mt}' font-family='monospace' font-size='10'>12h</text>\
         <text x='436' y='198' fill='{mt}' font-family='monospace' font-size='10'>24h</text>\
         </svg>",
        bg = p.panel_bg,
        bd = p.border,
        title = p.title,
        ax = p.axis,
        af = p.area_fill,
        ln = p.line,
        mt = p.muted,
        b = pad_t + plot_h,
        r = pad_l + plot_w
    )
}

/// Pure-Rust Monochrome SVG: Recent Stage Latency Bar Chart (microseconds).
pub fn svg_latency_chart(events: &[KernelEvent], is_light: bool) -> String {
    let p = palette(is_light);
    let recent: Vec<&KernelEvent> = events.iter().rev().take(24).collect::<Vec<_>>().into_iter().rev().collect();
    let max_lat = recent.iter().map(|e| e.latency_us).max().unwrap_or(100).max(1) as f64;
    let mut bars = String::new();
    let count = recent.len().max(1);
    let slot_w = 416.0 / count as f64;
    for (i, ev) in recent.iter().enumerate() {
        let bh = ((ev.latency_us as f64) / max_lat).clamp(0.03, 1.0) * 140.0;
        let x = 46.0 + (i as f64) * slot_w;
        let y = 178.0 - bh;
        let bw = (slot_w - 3.0).max(3.0);
        let fill = if ev.plane == "plane1" { p.bar1 } else if ev.plane == "plane2" { p.bar3 } else { p.bar4 };
        bars.push_str(&format!(
            "<rect x='{x:.1}' y='{y:.1}' width='{bw:.1}' height='{bh:.1}' rx='2' fill='{fill}'/>"
        ));
    }
    format!(
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 480 210' width='480' height='210'>\
         <rect width='480' height='210' rx='8' fill='{bg}' stroke='{bd}'/>\
         <text x='16' y='22' fill='{title}' font-family='system-ui,sans-serif' font-size='12' font-weight='600'>STAGE LATENCY TIMELINE (MAX: {max_lat:.0} us)</text>\
         <line x1='46' y1='34' x2='46' y2='178' stroke='{ax}'/>\
         <line x1='46' y1='178' x2='462' y2='178' stroke='{ax}'/>\
         {bars}\
         <text x='16' y='198' fill='{mt}' font-family='monospace' font-size='10'>Last {cnt} kernel stage executions (P1 / P2 / P3)</text>\
         </svg>",
        bg = p.panel_bg,
        bd = p.border,
        title = p.title,
        ax = p.axis,
        mt = p.muted,
        cnt = recent.len()
    )
}

/// Pure-Rust Monochrome SVG: Plane & Activity Horizontal Bar Chart.
pub fn svg_plane_bars(events: &[KernelEvent], is_light: bool) -> String {
    let pal = palette(is_light);
    let counts = count_by_plane(events);
    let planes = ["plane1", "plane2", "plane3", "kernel"];
    let max_c = planes
        .iter()
        .map(|p| counts.get(*p).copied().unwrap_or(0))
        .max()
        .unwrap_or(1)
        .max(1) as f64;
    let mut rows = String::new();
    for (idx, p) in planes.iter().enumerate() {
        let c = counts.get(*p).copied().unwrap_or(0);
        let y = 44.0 + (idx as f64) * 36.0;
        let bw = ((c as f64) / max_c) * 320.0;
        let shade = match idx {
            0 => pal.bar1,
            1 => pal.bar2,
            2 => pal.bar3,
            _ => pal.bar4,
        };
        rows.push_str(&format!(
            "<text x='16' y='{ty:.1}' fill='{mt}' font-family='monospace' font-size='11'>{p}</text>\
             <rect x='84' y='{y:.1}' width='{bw:.1}' height='20' rx='3' fill='{shade}'/>\
             <text x='{tx:.1}' y='{ty:.1}' fill='{title}' font-family='monospace' font-size='11'>{c}</text>",
            mt = pal.muted,
            title = pal.title,
            ty = y + 14.0,
            tx = 92.0 + bw
        ));
    }
    format!(
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 480 210' width='480' height='210'>\
         <rect width='480' height='210' rx='8' fill='{bg}' stroke='{bd}'/>\
         <text x='16' y='22' fill='{title}' font-family='system-ui,sans-serif' font-size='12' font-weight='600'>TRI-PLANE EVENT DISTRIBUTION (TOTAL: {cnt})</text>\
         {rows}</svg>",
        bg = pal.panel_bg,
        bd = pal.border,
        title = pal.title,
        cnt = events.len()
    )
}

/// Pure-Rust Monochrome SVG: Combined Multi-Panel Telemetry Dashboard.
pub fn svg_dashboard(
    curve: &[(f64, f64)],
    current_carbon: f64,
    events: &[KernelEvent],
    is_light: bool,
) -> String {
    let p = palette(is_light);
    let c_svg = svg_carbon_chart(curve, current_carbon, is_light);
    let l_svg = svg_latency_chart(events, is_light);
    let p_svg = svg_plane_bars(events, is_light);
    format!(
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 980 450' width='980' height='450'>\
         <rect width='980' height='450' rx='10' fill='{obg}'/>\
         <g transform='translate(10,10)'>{c_svg}</g>\
         <g transform='translate(495,10)'>{l_svg}</g>\
         <g transform='translate(10,230)'>{p_svg}</g>\
         <g transform='translate(495,230)'>\
           <rect width='480' height='210' rx='8' fill='{pbg}' stroke='{bd}'/>\
           <text x='16' y='26' fill='{title}' font-family='system-ui,sans-serif' font-size='12' font-weight='600'>NOSIH-CAZNSOS PURE-RUST VISUAL ENGINE</text>\
           <text x='16' y='64' fill='{mt}' font-family='monospace' font-size='12'>Total Logged Events : {cnt}</text>\
           <text x='16' y='92' fill='{mt}' font-family='monospace' font-size='12'>Live Grid Carbon    : {current_carbon:.1} gCO2eq/kWh</text>\
           <text x='16' y='120' fill='{mt}' font-family='monospace' font-size='12'>Renderer            : Pure-Rust Zero-Dep SVG</text>\
           <text x='16' y='148' fill='{mt}' font-family='monospace' font-size='12'>Export Formats      : JSON, JSONL, CSV, TSV, MD, TXT, XML, OTel, Merkle, SVG, HTML</text>\
         </g></svg>",
        obg = p.outer_bg,
        pbg = p.panel_bg,
        bd = p.border,
        title = p.title,
        mt = p.muted,
        cnt = events.len()
    )
}

/// Query parameters for `GET /admin/metrics/cards`.
#[derive(Debug, Deserialize)]
pub struct CardsQuery {
    /// Sliding window in minutes (15, 60, or 1440).
    #[serde(default = "default_window_mins")]
    pub window_mins: i64,
    /// Card grouping view (`api` or `planes`).
    #[serde(default = "default_cards_view")]
    pub view: String,
}

fn default_cards_view() -> String {
    "api".to_string()
}

fn default_window_mins() -> i64 {
    60
}

/// `GET /admin/metrics/cards` — 4-card 48-bucket time-series telemetry for the Overview dashboard.
pub async fn metrics_cards(
    State(state): State<Arc<AppState>>,
    Query(q): Query<CardsQuery>,
) -> Json<Value> {
    let window_mins = q.window_mins.clamp(5, 1440);
    let now = chrono::Utc::now();
    let start = now - chrono::Duration::minutes(window_mins);
    let events = state.log_ring.snapshot().await;
    let merkle_for_cards = Arc::clone(&state.kernel.merkle);
    let mtlog_leaves = tokio::task::spawn_blocking(move || {
        merkle_for_cards
            .latest_sth()
            .map(|s| s.tree_size)
            .unwrap_or(0)
    })
    .await
    .unwrap_or(0);

    let bucket_count = 48usize;
    let span_secs = (window_mins * 60).max(1) as f64;

    let specs = if q.view.eq_ignore_ascii_case("planes") {
        [
            ("PLANE I · ZERO-TRUST", "plane1"),
            ("PLANE II · CARBON ROUTER", "plane2"),
            ("PLANE III · PROVIDERS", "plane3"),
            ("STORAGE & MTLOG", "kernel"),
        ]
    } else {
        [
            ("CHAT COMPLETIONS", "plane3"),
            ("ROUTER & CACHE", "plane2"),
            ("AUTH & SECURITY", "plane1"),
            ("STORAGE & MTLOG", "kernel"),
        ]
    };

    let mut total_all = 0usize;
    let mut err_all = 0usize;
    let mut cards = Vec::with_capacity(4);

    for (title, plane_key) in specs {
        let mut ok_b = vec![0u32; bucket_count];
        let mut warn_b = vec![0u32; bucket_count];
        let mut err_b = vec![0u32; bucket_count];
        let mut total = 0usize;
        let mut warns = 0usize;
        let mut errs = 0usize;

        for ev in &events {
            if !ev.plane.eq_ignore_ascii_case(plane_key) {
                continue;
            }
            let ts = chrono::DateTime::parse_from_rfc3339(&ev.ts)
                .map(|d| d.with_timezone(&chrono::Utc))
                .unwrap_or(now);
            if ts < start {
                continue;
            }
            let offset = (ts - start).num_seconds().max(0) as f64;
            let idx = (((offset / span_secs) * (bucket_count as f64)) as usize)
                .min(bucket_count - 1);
            total += 1;
            if ev.severity.eq_ignore_ascii_case("error") {
                errs += 1;
                err_b[idx] += 1;
            } else if ev.severity.eq_ignore_ascii_case("warn") {
                warns += 1;
                warn_b[idx] += 1;
            } else {
                ok_b[idx] += 1;
            }
        }

        if plane_key == "kernel" && total == 0 && mtlog_leaves > 0 {
            total = mtlog_leaves;
            ok_b[bucket_count - 1] = mtlog_leaves as u32;
        }

        total_all += total;
        err_all += errs;

        let buckets: Vec<Value> = (0..bucket_count)
            .map(|i| json!({ "ok": ok_b[i], "warn": warn_b[i], "err": err_b[i] }))
            .collect();

        cards.push(json!({
            "title": title,
            "plane": plane_key,
            "total": total,
            "warnings": warns,
            "errors": errs,
            "buckets": buckets,
        }));
    }

    let success_rate = if total_all == 0 {
        100.0
    } else {
        (((total_all - err_all) as f64) / (total_all as f64)) * 100.0
    };

    Json(json!({
        "total_requests": total_all,
        "success_rate": (success_rate * 10.0).round() / 10.0,
        "window_mins": window_mins,
        "start_label": start.format("%b %d, %I:%M%P").to_string(),
        "end_label": now.format("%b %d, %I:%M%P").to_string(),
        "cards": cards,
    }))
}
