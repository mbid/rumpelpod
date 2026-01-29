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
fn agent_bash_timeout() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_sandbox_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Create a script that sleeps for 5 seconds and prints something
    let script_name = "sleepy.sh";
    let script_content = r#"#!/bin/bash
echo "Start sleeping"
sleep 5
echo "Done sleeping"
"#;
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
    create_commit(repo.path(), "Add sleepy script");

    // Run agent with 2s timeout
    let output = super::common::run_agent_interactive_model_args_env(
        &repo,
        &daemon,
        &[formatdoc! {r#"
            Run `./{script_name}`.
            Tell me what happens.
        "#}
        .as_str()],
        super::common::DEFAULT_MODEL,
        &[],
        &[("AGENT_BASH_TIMEOUT", "2")],
    );

    assert!(
        output.stdout.contains("Command timed out after 2 seconds"),
        "Agent should report timeout.\nstdout: {}",
        output.stdout
    );
    assert!(
        output.stdout.contains("Process is still running with PID"),
        "Agent should report PID.\nstdout: {}",
        output.stdout
    );
    assert!(
        output.stdout.contains("Start sleeping"),
        "Agent should report partial output.\nstdout: {}",
        output.stdout
    );
}

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

    // In interactive mode, stdout and stderr are combined
    assert!(
        !output.stdout.contains("content cannot be empty"),
        "Agent failed with empty content error.\noutput: {}",
        output.stdout
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

    assert!(
        output.stdout.contains("/tmp/agent/bash-"),
        "Agent should report that output was saved to a file.\nstdout: {}",
        output.stdout
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

    assert!(
        output.stdout.contains(secret),
        "Agent should have found the secret in the large output.\nstdout: {}",
        output.stdout
    );
}
