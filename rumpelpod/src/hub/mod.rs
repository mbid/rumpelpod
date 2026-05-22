// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! rumpelhub: an in-cluster companion deployment to rumpelpod.
//!
//! Currently exposes a single `/healthz` endpoint.  See
//! `notes/rumpelhub.md` for the design and roadmap.

mod image;
mod install;
mod manifests;
mod serve;

pub use install::{delete, install, status};
pub use serve::run_serve;

use anyhow::Result;

use crate::cli::HubCommonArgs;
use crate::config::Host;

/// Resolve a `Host::Kubernetes` from `rumpel hub` CLI arguments,
/// falling back to `.rumpelpod.json` in the current directory.
pub fn resolve_hub_host(args: &HubCommonArgs) -> Result<Host> {
    install::resolve_kubernetes_host(
        args.kubernetes_context.as_deref(),
        args.kubernetes_namespace.as_deref(),
        args.kubernetes_registry.as_deref(),
    )
}

/// Port the hub listens on inside its pod.
pub const HUB_PORT: u16 = 7900;

/// Name of the Kubernetes resources the hub installs.
pub const HUB_NAME: &str = "rumpelhub";

/// Labels applied to every k8s object owned by the hub install.
pub fn hub_labels() -> std::collections::BTreeMap<String, String> {
    let mut labels = std::collections::BTreeMap::new();
    labels.insert("app.kubernetes.io/name".to_string(), HUB_NAME.to_string());
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "rumpelpod".to_string(),
    );
    labels
}

/// The label selector used by `rumpel hub delete` and tests to find
/// hub-owned resources.
pub const HUB_SELECTOR: &str =
    "app.kubernetes.io/name=rumpelhub,app.kubernetes.io/managed-by=rumpelpod";
