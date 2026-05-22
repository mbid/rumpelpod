// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! ServiceAccount + Deployment + Service that make up a hub
//! install.  One source of truth so the install path and any
//! future StatefulSet migration (see `notes/rumpelhub.md`) only
//! touch this file.

use anyhow::{Context, Result};
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Service, ServiceAccount};
use serde_json::json;

use super::{hub_labels, HUB_NAME, HUB_PORT};

/// Inputs to [`HubInstallSpec::manifests`].
pub struct HubInstallSpec {
    /// Namespace to install into.
    pub namespace: String,
    /// Fully-qualified container image reference (content-addressed
    /// tag from the hub image build step).
    pub image: String,
}

/// Concrete Kubernetes objects that make up a hub install.
pub struct HubResources {
    pub service_account: ServiceAccount,
    pub deployment: Deployment,
    pub service: Service,
}

impl HubInstallSpec {
    /// Build the full set of Kubernetes objects for this spec.  No
    /// network calls and no state -- the caller applies the
    /// returned objects through the kube API.
    pub fn manifests(&self) -> Result<HubResources> {
        let labels = hub_labels();

        let service_account_json = json!({
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {
                "name": HUB_NAME,
                "namespace": self.namespace,
                "labels": labels,
            },
        });
        let service_account: ServiceAccount =
            serde_json::from_value(service_account_json).context("building ServiceAccount")?;

        let deployment_json = json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": HUB_NAME,
                "namespace": self.namespace,
                "labels": labels,
            },
            "spec": {
                "replicas": 1,
                "strategy": { "type": "Recreate" },
                "selector": {
                    "matchLabels": {
                        "app.kubernetes.io/name": HUB_NAME,
                        "app.kubernetes.io/managed-by": "rumpelpod",
                    }
                },
                "template": {
                    "metadata": { "labels": labels },
                    "spec": {
                        "serviceAccountName": HUB_NAME,
                        "containers": [{
                            "name": "hub",
                            "image": self.image,
                            "imagePullPolicy": "IfNotPresent",
                            "command": ["rumpel", "hub", "serve"],
                            "ports": [{
                                "name": "http",
                                "containerPort": HUB_PORT,
                            }],
                            "readinessProbe": {
                                "httpGet": {
                                    "path": "/healthz",
                                    "port": HUB_PORT,
                                },
                                "initialDelaySeconds": 0,
                                "periodSeconds": 2,
                                "failureThreshold": 15,
                            },
                            "livenessProbe": {
                                "httpGet": {
                                    "path": "/healthz",
                                    "port": HUB_PORT,
                                },
                                "initialDelaySeconds": 5,
                                "periodSeconds": 10,
                            },
                        }],
                    },
                },
            },
        });
        let deployment: Deployment =
            serde_json::from_value(deployment_json).context("building Deployment")?;

        let service_json = json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": HUB_NAME,
                "namespace": self.namespace,
                "labels": labels,
            },
            "spec": {
                "type": "ClusterIP",
                "selector": {
                    "app.kubernetes.io/name": HUB_NAME,
                    "app.kubernetes.io/managed-by": "rumpelpod",
                },
                "ports": [{
                    "name": "http",
                    "port": HUB_PORT,
                    "targetPort": HUB_PORT,
                    "protocol": "TCP",
                }],
            },
        });
        let service: Service = serde_json::from_value(service_json).context("building Service")?;

        Ok(HubResources {
            service_account,
            deployment,
            service,
        })
    }
}
