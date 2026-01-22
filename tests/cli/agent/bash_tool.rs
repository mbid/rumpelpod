//! Tests for advanced bash tool functionality (output limits, error handling).
//!
//! These tests verify the shared bash execution code in `common.rs`, so we only
//! need to test with one model since the implementation is identical across all
//! providers.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use indoc::formatdoc;
use sandbox::CommandExt;

use crate::common::{
    build_test_image, create_commit, write_test_sandbox_config, TestDaemon, TestRepo,
};

use super::common::run_agent_with_prompt;

#[test]
fn agent_handles_command_with_empty_output_and_nonzero_exit() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    let output = run_agent_with_prompt(
        &repo,
        &daemon,
        "Run the command `false` and tell me what happened.",
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("content cannot be empty"),
        "Agent failed with empty content error.\nstderr: {}",
        stderr
    );
}

#[test]
fn agent_large_file_output() {
    let repo = TestRepo::new();

    let large_content = "x".repeat(35000);
    fs::write(repo.path().join("large.txt"), &large_content).expect("Failed to write large.txt");

    Command::new("git")
        .args(["add", "large.txt"])
        .current_dir(repo.path())
        .success()
        .expect("git add failed");
    create_commit(repo.path(), "Add large file");

    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    let output = run_agent_with_prompt(
        &repo,
        &daemon,
        "Run exactly one tool: `cat large.txt`. After that single tool call, stop immediately and tell me what you observed. Do not run any other tools.",
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("/tmp/agent/bash-output-"),
        "Agent should report that output was saved to a file.\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn agent_can_read_large_output_from_one_time_command() {
    let repo = TestRepo::new();
    let script_name = "once.sh";
    let secret = "SECRET_CODE_XYZ_98765";

    // Generate content larger than 30KB (limit in src/agent/common.rs)
    // 4000 lines of "0123456789" is 40KB+
    let mut script_content = String::from("#!/bin/bash\n");
    for i in 0..4000 {
        script_content.push_str(&format!("echo 'Line {i} 0123456789'\n"));
    }
    script_content.push_str(&format!("echo '{secret}'\n"));
    script_content.push_str(&format!("rm {script_name}\n"));

    fs::write(repo.path().join(script_name), script_content).expect("Failed to write script");

    // Make executable
    let mut perms = fs::metadata(repo.path().join(script_name))
        .unwrap()
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(repo.path().join(script_name), perms).unwrap();

    Command::new("git")
        .args(["add", script_name])
        .current_dir(repo.path())
        .success()
        .expect("git add failed");
    create_commit(repo.path(), "Add one-time script");

    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    let output = run_agent_with_prompt(
        &repo,
        &daemon,
        &formatdoc! {r#"
            Run `./{script_name}`.
            It will print a lot of output and then delete itself.
            The output will be saved to a file because it is too large.
            Use `tail` to read the end of that file to find the secret code.
        "#},
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stdout.contains(secret),
        "Agent should have found the secret in the large output.\nstdout: {stdout}\nstderr: {stderr}"
    );
}
