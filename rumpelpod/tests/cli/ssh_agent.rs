// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for SSH agent forwarding in pods.

use std::fs;

use rumpelpod::CommandExt;

use crate::common::{pod_command, write_test_devcontainer, TestDaemon, TestHome, TestRepo};
use crate::executor::ExecutorResources;

/// Add a key to a pod's ssh-agent and verify it is usable from inside the
/// container via the relayed socket.
#[test]
fn ssh_add_and_list() {
    let home = TestHome::new();
    // The daemon spawns `ssh-agent` when handling `rumpel ssh-add`, and
    // the CLI itself execs `ssh-add`, so both need to be reachable from
    // the narrowed PATH.
    home.link_local_bins(&["ssh-agent", "ssh-add"]);
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    let repo = TestRepo::new();

    // The base test image installs openssh-client, giving us ssh-add.
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    // Create the pod.
    pod_command(&repo, &daemon)
        .args(["enter", "--create", "ssh-test", "--", "true"])
        .success()
        .expect("failed to create pod");

    // Generate a throwaway ed25519 key on the local machine.
    let key_path = home.path().join("test_ed25519");
    std::process::Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-f"])
        .arg(&key_path)
        .args(["-N", "", "-q"])
        .success()
        .expect("ssh-keygen failed");

    // Add the key via `rumpel ssh-add <pod> <key>`.  ssh-add prints
    // its confirmation to stderr, so check the combined output there.
    let output = pod_command(&repo, &daemon)
        .args(["ssh-add", "ssh-test"])
        .arg(&key_path)
        .output()
        .expect("rumpel ssh-add failed to execute");
    assert!(
        output.status.success(),
        "rumpel ssh-add failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Identity added") || stderr.contains("identity added"),
        "unexpected ssh-add stderr: {stderr}"
    );

    // List keys from the local machine via `rumpel ssh-add <pod> -l`.
    let stdout = pod_command(&repo, &daemon)
        .args(["ssh-add", "ssh-test", "-l"])
        .success()
        .expect("rumpel ssh-add -l failed");
    let list_output = String::from_utf8_lossy(&stdout);
    assert!(
        list_output.contains("ssh-ed25519") || list_output.contains("ED25519"),
        "expected key in local machine's list: {list_output}"
    );

    // Verify the key is reachable from inside the container through the
    // relayed agent socket.
    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "--create", "ssh-test", "--", "ssh-add", "-l"])
        .success()
        .expect("ssh-add -l inside container failed");
    let container_output = String::from_utf8_lossy(&stdout);
    assert!(
        container_output.contains("ssh-ed25519") || container_output.contains("ED25519"),
        "expected key visible inside container: {container_output}"
    );
}
