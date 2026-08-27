// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for devcontainer build paths outside the repository.

use std::fs;
use std::process::Command;

use indoc::formatdoc;
use rumpelpod::CommandExt;

use crate::common::{pod_command, TestDaemon, TestHome, TestRepo, TEST_USER, TEST_USER_UID};
use crate::executor::ExecutorResources;

fn write_devcontainer(repo: &TestRepo, dockerfile: &str, context: &str) {
    let devcontainer_dir = repo.path().join(".devcontainer");
    fs::create_dir_all(&devcontainer_dir).expect("create .devcontainer directory");

    let devcontainer_json = formatdoc! {r#"
        {{
            "build": {{
                "dockerfile": "{dockerfile}",
                "context": "{context}"
            }}
        }}
    "#};
    fs::write(
        devcontainer_dir.join("devcontainer.json"),
        devcontainer_json,
    )
    .expect("write devcontainer.json");
}

#[test]
fn image_build_accepts_dockerfile_outside_repo() {
    let repo = TestRepo::new();
    let external = tempfile::tempdir().expect("create external Dockerfile directory");
    let outside_dockerfile = external.path().join("Dockerfile");
    fs::write(
        &outside_dockerfile,
        "FROM cgr.dev/chainguard/wolfi-base\nRUN echo external-dockerfile\n",
    )
    .expect("write external Dockerfile");
    write_devcontainer(&repo, &outside_dockerfile.display().to_string(), "..");

    Command::new("rumpel")
        .args(["image", "build"])
        .current_dir(repo.path())
        .success()
        .expect("build with external Dockerfile failed");
}

#[test]
fn enter_accepts_build_context_outside_repo() {
    let repo = TestRepo::new();
    let outside_context = tempfile::tempdir().expect("create external build context");
    fs::write(
        outside_context.path().join("context-marker"),
        "selected external context\n",
    )
    .expect("write external context marker");

    let devcontainer_dir = repo.path().join(".devcontainer");
    fs::create_dir_all(&devcontainer_dir).expect("create .devcontainer directory");
    fs::write(
        devcontainer_dir.join("Dockerfile"),
        formatdoc! {r#"
            FROM cgr.dev/chainguard/wolfi-base
            RUN apk add --no-cache git bash shadow coreutils openssh-client
            RUN useradd -m -u {TEST_USER_UID} -s /bin/bash {TEST_USER}
            COPY context-marker /tmp/external-context
            USER {TEST_USER}
        "#},
    )
    .expect("write Dockerfile");
    write_devcontainer(
        &repo,
        "Dockerfile",
        &outside_context.path().display().to_string(),
    );

    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).expect("write .rumpelpod.json");

    let stdout = pod_command(&repo, &daemon)
        .args([
            "enter",
            "--create",
            "outside-context",
            "--",
            "cat",
            "/tmp/external-context",
        ])
        .success()
        .expect("enter with external build context failed");

    assert_eq!(
        String::from_utf8_lossy(&stdout),
        "selected external context\n"
    );
}
