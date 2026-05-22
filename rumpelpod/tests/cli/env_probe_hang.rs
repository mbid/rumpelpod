// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Regression test: the userEnvProbe shell probe must not hang when
//! .profile/.bashrc spawns a background process that inherits
//! stdout/stderr.
//!
//! The probe runs `bash -lic "env -0"`.  Before the fix,
//! Command::output() waited for all pipe writers to close, so a
//! backgrounded child that inherited those pipes blocked it
//! indefinitely.

use indoc::formatdoc;
use rumpelpod::CommandExt;
use std::fs;

use crate::common::{pod_command, TestDaemon, TestHome, TestRepo, TEST_REPO_PATH, TEST_USER};
use crate::executor::ExecutorResources;

/// A .profile that spawns a background process holding stdout/stderr
/// open must not block container-serve startup.
#[test]
fn env_probe_bashrc_background_process_does_not_hang() {
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);

    let devcontainer_dir = repo.path().join(".devcontainer");
    fs::create_dir_all(&devcontainer_dir).unwrap();

    // Spawn a long-lived background process from .profile.  bash -lic
    // (the default userEnvProbe) sources .profile, so the child
    // inherits the stdout/stderr pipes.  Before the fix this blocked
    // probe_env_impl indefinitely.
    let dockerfile = formatdoc! {r#"
        FROM cgr.dev/chainguard/wolfi-base
        RUN apk add --no-cache git bash shadow coreutils openssh-client
        RUN useradd -m -u 1007 -s /bin/bash {TEST_USER}
        COPY --chown={TEST_USER}:{TEST_USER} . {TEST_REPO_PATH}
        RUN git config --global --add safe.directory {TEST_REPO_PATH}
        RUN echo 'sleep 3600 &' >> /home/{TEST_USER}/.profile
        USER {TEST_USER}
    "#};
    fs::write(devcontainer_dir.join("Dockerfile"), &dockerfile).unwrap();

    let devcontainer_json = formatdoc! {r#"
        {{
            "build": {{
                "dockerfile": "Dockerfile",
                "context": ".."
            }},
            "workspaceFolder": "{TEST_REPO_PATH}",
            "containerUser": "{TEST_USER}",
            "runArgs": ["--runtime=runc"]
        }}
    "#};
    fs::write(
        devcontainer_dir.join("devcontainer.json"),
        &devcontainer_json,
    )
    .unwrap();
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "--create", "bg-hang", "--", "echo", "ready"])
        .success()
        .expect("rumpel enter hung or failed");

    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "ready");
}
