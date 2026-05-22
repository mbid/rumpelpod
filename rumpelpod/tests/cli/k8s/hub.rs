// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `rumpel hub install/delete/status`.
//!
//! The hub runs as a Deployment+Service inside a sibling k8s
//! namespace created per-test.  All tests skip when the current
//! executor has no Kubernetes (see `has_k8s_executor`).

use std::fs;
use std::process::Command;
use std::time::{Duration, Instant};

use rumpelpod::CommandExt;

use super::{has_k8s_executor, k8s_executor};
use crate::common::{pod_command, TestDaemon, TestHome, TestRepo};

/// Write a `.rumpelpod.json` that points at the test's sibling
/// namespace with the executor's context and registry.
fn write_hub_config(repo: &TestRepo, executor_json: &str) {
    fs::write(repo.path().join(".rumpelpod.json"), executor_json).expect("writing .rumpelpod.json");
}

/// Return the set of resource names matching the hub label selector.
fn hub_resource_names(context: &str, namespace: &str, kind: &str) -> Vec<String> {
    let output = Command::new("kubectl")
        .args(["--context", context])
        .args(["--namespace", namespace])
        .args([
            "get",
            kind,
            "-l",
            "app.kubernetes.io/name=rumpelhub,app.kubernetes.io/managed-by=rumpelpod",
            "-o",
            "jsonpath={range .items[*]}{.metadata.name}\n{end}",
        ])
        .output()
        .expect("kubectl get failed");
    assert!(
        output.status.success(),
        "kubectl get {kind} failed: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[test]
fn hub_install_smoke() {
    if !has_k8s_executor() {
        return;
    }
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = k8s_executor(&home);
    let daemon = TestDaemon::start(&home);
    write_hub_config(&repo, &executor.json);

    pod_command(&repo, &daemon)
        .args(["hub", "install"])
        .success()
        .expect("rumpel hub install failed");

    let deployments = hub_resource_names(&executor.context, &executor.namespace, "deployment");
    assert_eq!(
        deployments,
        vec!["rumpelhub".to_string()],
        "expected exactly one rumpelhub Deployment",
    );
    let services = hub_resource_names(&executor.context, &executor.namespace, "service");
    assert_eq!(
        services,
        vec!["rumpelhub".to_string()],
        "expected exactly one rumpelhub Service",
    );
}

#[test]
fn hub_status_reports_ok() {
    if !has_k8s_executor() {
        return;
    }
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = k8s_executor(&home);
    let daemon = TestDaemon::start(&home);
    write_hub_config(&repo, &executor.json);

    pod_command(&repo, &daemon)
        .args(["hub", "install"])
        .success()
        .expect("rumpel hub install failed");

    let stdout = pod_command(&repo, &daemon)
        .args(["hub", "status"])
        .success()
        .expect("rumpel hub status failed");
    let stdout = String::from_utf8_lossy(&stdout);
    assert!(
        stdout.contains("\"status\":\"ok\""),
        "status output should include 'status: ok': {stdout}",
    );
}

#[test]
fn hub_delete_removes_resources() {
    if !has_k8s_executor() {
        return;
    }
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = k8s_executor(&home);
    let daemon = TestDaemon::start(&home);
    write_hub_config(&repo, &executor.json);

    pod_command(&repo, &daemon)
        .args(["hub", "install"])
        .success()
        .expect("rumpel hub install failed");

    pod_command(&repo, &daemon)
        .args(["hub", "delete"])
        .success()
        .expect("rumpel hub delete failed");

    // After delete, nothing should match the hub label selector.
    // Poll briefly: delete_collection returns immediately but the
    // objects are removed eagerly by the kube API, so a short loop
    // suffices.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let deployments = hub_resource_names(&executor.context, &executor.namespace, "deployment");
        let services = hub_resource_names(&executor.context, &executor.namespace, "service");
        let sas = hub_resource_names(&executor.context, &executor.namespace, "serviceaccount");
        if deployments.is_empty() && services.is_empty() && sas.is_empty() {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "hub resources still present after delete: \
                 deployments={deployments:?}, services={services:?}, sas={sas:?}"
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn hub_delete_idempotent() {
    if !has_k8s_executor() {
        return;
    }
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = k8s_executor(&home);
    let daemon = TestDaemon::start(&home);
    write_hub_config(&repo, &executor.json);

    // No prior install: delete should still succeed.
    pod_command(&repo, &daemon)
        .args(["hub", "delete"])
        .success()
        .expect("rumpel hub delete on fresh namespace failed");
}
