//! Tests for basic file operations (edit, write).
//!
//! These tests verify the shared file operation code in `common.rs`, so we only
//! need to test with one model since the implementation is identical across all
//! providers.

use std::fs;
use std::process::Command;

use rumpelpod::CommandExt;

use crate::common::{build_test_image, create_commit, TestRepo};
use crate::executor::TestPod;

use super::common::run_agent_with_prompt;

#[test]
fn agent_edits_file() {
    let repo = TestRepo::new();

    let original_content = "Hello World";
    fs::write(repo.path().join("greeting.txt"), original_content)
        .expect("Failed to write greeting.txt");

    Command::new("git")
        .args(["add", "greeting.txt"])
        .current_dir(repo.path())
        .success()
        .expect("git add failed");
    create_commit(repo.path(), "Add greeting");

    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    let pod = TestPod::start(&repo, &image_id, "agent-file-edit");

    let output = run_agent_with_prompt(
        &repo,
        &pod.daemon,
        "Use the edit tool to replace 'World' with 'Universe' in greeting.txt, then run `cat greeting.txt` and tell me the result.",
    );

    assert!(
        output.stdout.contains("Universe"),
        "Agent output should contain the edited content 'Universe'.\nstdout: {}",
        output.stdout
    );
}

#[test]
fn agent_writes_file() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    let pod = TestPod::start(&repo, &image_id, "agent-file-write");

    let expected_content = "WRITTEN_BY_AGENT_12345";

    let output = run_agent_with_prompt(
        &repo,
        &pod.daemon,
        &format!(
            "Run `echo '{expected_content}' > newfile.txt` \
             then run `cat newfile.txt` and tell me the result."
        ),
    );

    assert!(
        output.stdout.contains(expected_content),
        "Agent output should contain the written content.\nstdout: {}",
        output.stdout
    );
}
