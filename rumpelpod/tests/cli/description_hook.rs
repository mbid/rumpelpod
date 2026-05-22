// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the pre-commit hook that validates the
//! DESCRIPTION file inside pods.

use std::fs;

use serde_json::json;

use crate::common::{pod_command, write_test_devcontainer, TestDaemon, TestHome, TestRepo};
use crate::executor::{merge_config, ExecutorResources};

/// Commit-message style string that passes the hook's format checks.
const VALID_SUBJECT: &str = "Describe this branch";

#[test]
fn description_hook_missing_description_fails() {
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    let output = pod_command(&repo, &daemon)
        .args([
            "enter",
            "--create",
            "desc-missing",
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "no description here",
        ])
        .output()
        .expect("failed to run pod commit");

    assert!(
        !output.status.success(),
        "commit should fail when DESCRIPTION is missing"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("DESCRIPTION is not staged"),
        "expected missing-file message, got: {stderr}"
    );
    assert!(
        stderr.contains("--no-verify"),
        "expected bypass hint in stderr, got: {stderr}"
    );
}

#[test]
fn description_hook_bad_format_fails() {
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    // Subject line of 60 characters -- exceeds the 50-character cap.
    let oversized = "x".repeat(60);
    let script = format!(
        "printf '%s\\n' '{oversized}' > DESCRIPTION && \
         git add DESCRIPTION && \
         git commit -m 'add description'"
    );

    let output = pod_command(&repo, &daemon)
        .args(["enter", "--create", "desc-bad", "--", "sh", "-c", &script])
        .output()
        .expect("failed to run pod commit");

    assert!(
        !output.status.success(),
        "commit should fail when DESCRIPTION subject is too long"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("subject line"),
        "expected subject-line complaint, got: {stderr}"
    );
}

#[test]
fn description_hook_no_verify_bypass() {
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    let output = pod_command(&repo, &daemon)
        .args([
            "enter",
            "--create",
            "desc-bypass",
            "--",
            "git",
            "commit",
            "--no-verify",
            "--allow-empty",
            "-m",
            "bypass",
        ])
        .output()
        .expect("failed to run pod commit");

    assert!(
        output.status.success(),
        "--no-verify should bypass the hook: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn description_hook_valid_description_passes() {
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    let script = format!(
        "printf '%s\\n' '{VALID_SUBJECT}' > DESCRIPTION && \
         git add DESCRIPTION && \
         git commit -m 'add description'"
    );

    let output = pod_command(&repo, &daemon)
        .args(["enter", "--create", "desc-valid", "--", "sh", "-c", &script])
        .output()
        .expect("failed to run pod commit");

    assert!(
        output.status.success(),
        "commit with valid DESCRIPTION should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn description_hook_disabled_skips_check() {
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");

    let config = merge_config(&executor.json, json!({"merge": {"description": "off"}}));
    fs::write(repo.path().join(".rumpelpod.json"), &config).unwrap();

    // A plain commit without a DESCRIPTION and without --no-verify
    // should succeed because the hook was never installed.
    let output = pod_command(&repo, &daemon)
        .args([
            "enter",
            "--create",
            "desc-off",
            "--",
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "no description, no hook",
        ])
        .output()
        .expect("failed to run pod commit");

    assert!(
        output.status.success(),
        "commit without DESCRIPTION should succeed when feature is off: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
