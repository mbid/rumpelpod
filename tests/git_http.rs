//! Integration tests for git HTTP backend.

mod common;

use common::SandboxFixture;

/// Test that the git HTTP endpoint is available inside the sandbox.
///
/// The sandbox should be able to access meta.git via HTTP using the
/// host.docker.internal hostname and the port from $SANDBOX_GIT_HTTP_PORT.
#[test]
fn test_git_http_endpoint_available() {
    let fixture = SandboxFixture::new("test-git-http");

    // Use git ls-remote to check if the endpoint is available
    let output = fixture.run(&[
        "sh",
        "-c",
        "git ls-remote http://host.docker.internal:$SANDBOX_GIT_HTTP_PORT/meta.git",
    ]);

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

    // Use a single shell command to add remote and fetch, ensuring the env var is consistent
    let output = fixture.run(&[
        "sh",
        "-c",
        r#"
        echo "Using port: $SANDBOX_GIT_HTTP_PORT"
        git remote add http-sandbox "http://host.docker.internal:$SANDBOX_GIT_HTTP_PORT/meta.git"
        git remote -v
        git fetch http-sandbox
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
            git remote add http-sandbox "http://host.docker.internal:$SANDBOX_GIT_HTTP_PORT/meta.git"
            git push http-sandbox HEAD:refs/heads/{}
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
    let output = fixture.run(&[
        "sh",
        "-c",
        r#"
        git remote add http-sandbox "http://host.docker.internal:$SANDBOX_GIT_HTTP_PORT/meta.git"
        git push http-sandbox HEAD:refs/heads/master 2>&1
        "#,
    ]);

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
