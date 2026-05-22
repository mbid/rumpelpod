// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! In-cluster hub HTTP server, run as `rumpel hub serve` inside
//! the rumpelhub deployment pod.  Exposes `GET /healthz` for the
//! kubelet probes and for `rumpel hub status`.

use anyhow::{Context, Result};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::async_runtime::block_on;

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    version: String,
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("RUMPELPOD_VERSION_INFO").to_string(),
    })
}

/// Run the hub HTTP server on [`super::HUB_PORT`].  Blocks; the
/// pod is terminated via SIGTERM on shutdown.
pub fn run_serve() -> Result<()> {
    let port = super::HUB_PORT;
    let app = Router::new().route("/healthz", get(healthz));

    block_on(async move {
        let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
            .await
            .with_context(|| format!("binding 0.0.0.0:{port} for hub serve"))?;
        eprintln!("rumpelhub listening on 0.0.0.0:{port}");
        axum::serve(listener, app)
            .await
            .context("hub axum::serve failed")
    })
}
