//! Integration tests for git HTTP backend.

mod common;

use common::SandboxFixture;

/// Test that the git HTTP endpoint is available inside the sandbox.
///
/// The sandbox has an 'sandbox' remote configured to point to the HTTP server
/// on the Docker network gateway.
#[test]
fn test_git_http_endpoint_available() {
    let fixture = SandboxFixture::new("test-git-http");

    // Use git ls-remote with the sandbox remote (configured to HTTP URL)
    let output = fixture.run(&["git", "ls-remote", "sandbox"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "git ls-remote failed.\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );

    // Should see at least the master branch
    assert!(
        stdout.contains("refs/heads/master") || stdout.contains("refs/heads/main"),
        "Expected to see master or main branch in output.\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );
}

/// Test that fetching via HTTP works from inside the sandbox.
#[test]
fn test_git_http_fetch() {
    let fixture = SandboxFixture::new("test-git-http-fetch");

    // Fetch from sandbox (configured to HTTP URL)
    let output = fixture.run(&[
        "sh",
        "-c",
        r#"
        echo "Origin URL: $(git remote get-url sandbox)"
        git remote -v
        git fetch sandbox
        "#,
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("stdout: {}", stdout);
    eprintln!("stderr: {}", stderr);

    assert!(
        output.status.success(),
        "git fetch failed.\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );
}

/// Test that pushing to the sandbox's own branch works via HTTP.
#[test]
fn test_git_http_push_own_branch() {
    let fixture = SandboxFixture::new("test-git-http-push");

    let branch_name = &fixture.name;
    let output = fixture.run(&[
        "sh",
        "-c",
        &format!(
            r#"
            git config user.email "test@test.com"
            git config user.name "Test User"
            echo 'test content' > test-file.txt
            git add test-file.txt
            git commit -m "Test commit"
            git push sandbox HEAD:refs/heads/{}
            "#,
            branch_name
        ),
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "git push to own branch should succeed.\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );
}

/// Test that pushing to master/main is rejected via HTTP.
#[test]
fn test_git_http_push_master_rejected() {
    let fixture = SandboxFixture::new("test-git-http-reject");

    // First, make a commit
    let output = fixture.run(&[
        "sh",
        "-c",
        r#"
        git config user.email "test@test.com"
        git config user.name "Test User"
        echo 'test content' > test-file.txt
        git add test-file.txt
        git commit -m "Test commit"
        "#,
    ]);
    assert!(
        output.status.success(),
        "Failed to create commit: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Then try to push to master (should fail)
    let output = fixture.run(&["sh", "-c", "git push sandbox HEAD:refs/heads/master 2>&1"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // The command should fail
    assert!(
        !output.status.success(),
        "git push to master should be rejected.\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );

    // The error message should be in stdout (because we redirected stderr to stdout)
    // or stderr
    let combined = format!("{}{}", stdout, stderr);
    assert!(
        combined.contains("Only allowed to push to branch"),
        "Expected rejection message.\nOutput: {}",
        combined
    );
}
