// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for selecting non-standard devcontainer.json files.

use std::fs;
use std::path::Path;
use std::process::Command;

use indoc::formatdoc;
use rumpelpod::CommandExt;
use serde_json::json;

use crate::common::{
    pod_command, TestDaemon, TestHome, TestRepo, TEST_REPO_PATH, TEST_USER, TEST_USER_UID,
};
use crate::executor::ExecutorResources;

fn write_selected_devcontainer(config_dir: &Path, marker: &str) {
    fs::create_dir_all(config_dir).expect("create selected config directory");
    fs::write(config_dir.join("context-marker"), marker).expect("write context marker");
    fs::write(
        config_dir.join("Dockerfile"),
        formatdoc! {r#"
            FROM cgr.dev/chainguard/wolfi-base
            RUN apk add --no-cache git bash shadow coreutils openssh-client
            RUN useradd -m -u {TEST_USER_UID} -s /bin/bash {TEST_USER}
            COPY context-marker /tmp/selected-devcontainer
            USER {TEST_USER}
        "#},
    )
    .expect("write selected Dockerfile");
    fs::write(
        config_dir.join("devcontainer.json"),
        formatdoc! {r#"
            {{
                "build": {{ "dockerfile": "Dockerfile" }},
                "workspaceFolder": "{TEST_REPO_PATH}"
            }}
        "#},
    )
    .expect("write selected devcontainer.json");
}

fn write_executor_config(
    repo: &TestRepo,
    executor: &ExecutorResources,
    devcontainer: Option<&str>,
) {
    let mut config: serde_json::Value =
        serde_json::from_str(&executor.json).expect("parse executor config");
    if let Some(devcontainer) = devcontainer {
        config
            .as_object_mut()
            .expect("executor config must be an object")
            .insert("devcontainer".to_string(), json!(devcontainer));
    }
    fs::write(
        repo.path().join(".rumpelpod.json"),
        serde_json::to_vec_pretty(&config).expect("serialize rumpelpod config"),
    )
    .expect("write .rumpelpod.json");
}

#[test]
fn devcontainer_select_cli_overrides_default_and_preserves_implicit_build_context() {
    let repo = TestRepo::new();
    write_selected_devcontainer(&repo.path().join("configs/cli"), "selected by CLI\n");

    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    write_executor_config(&repo, &executor, Some("missing-default.json"));

    let stdout = pod_command(&repo, &daemon)
        .args([
            "enter",
            "--devcontainer",
            "configs/cli",
            "--create",
            "selected-cli",
            "--",
            "cat",
            "/tmp/selected-devcontainer",
        ])
        .success()
        .expect("enter with selected devcontainer directory failed");

    assert_eq!(String::from_utf8_lossy(&stdout), "selected by CLI\n");
}

#[test]
fn devcontainer_select_rumpelpod_config_accepts_json_file() {
    let repo = TestRepo::new();
    write_selected_devcontainer(&repo.path().join("configs/default"), "selected by config\n");

    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    write_executor_config(&repo, &executor, Some("configs/default/devcontainer.json"));

    let stdout = pod_command(&repo, &daemon)
        .args([
            "enter",
            "--create",
            "selected-default",
            "--",
            "cat",
            "/tmp/selected-devcontainer",
        ])
        .success()
        .expect("enter with .rumpelpod.json devcontainer failed");

    assert_eq!(String::from_utf8_lossy(&stdout), "selected by config\n");
}

#[test]
fn devcontainer_select_accepts_external_implicit_build_context() {
    let repo = TestRepo::new();
    let external = tempfile::tempdir().expect("create external config directory");
    write_selected_devcontainer(external.path(), "selected outside repository\n");

    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    write_executor_config(&repo, &executor, None);

    let stdout = pod_command(&repo, &daemon)
        .arg("enter")
        .arg("--devcontainer")
        .arg(external.path())
        .args([
            "--create",
            "selected-external",
            "--",
            "cat",
            "/tmp/selected-devcontainer",
        ])
        .success()
        .expect("enter with external devcontainer directory failed");

    assert_eq!(
        String::from_utf8_lossy(&stdout),
        "selected outside repository\n"
    );
}

#[test]
fn devcontainer_select_rejects_non_json_file() {
    let repo = TestRepo::new();
    fs::create_dir_all(repo.path().join("configs")).expect("create configs directory");
    fs::write(repo.path().join("configs/devcontainer.json5"), "{}")
        .expect("write non-JSON config path");

    let output = Command::new("rumpel")
        .args([
            "image",
            "build",
            "--devcontainer",
            "configs/devcontainer.json5",
        ])
        .current_dir(repo.path())
        .output()
        .expect("run rumpel image build");

    assert!(!output.status.success(), "non-JSON config path should fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("devcontainer config must be a JSON file"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn devcontainer_select_rejects_standard_config_directory() {
    let repo = TestRepo::new();
    fs::create_dir_all(repo.path().join(".devcontainer/devcontainer.json"))
        .expect("create invalid config directory");

    let output = Command::new("rumpel")
        .args(["image", "build"])
        .current_dir(repo.path())
        .output()
        .expect("run rumpel image build");

    assert!(
        !output.status.success(),
        "config directory should not be ignored"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("devcontainer config is not a file"),
        "unexpected stderr: {stderr}"
    );
}
