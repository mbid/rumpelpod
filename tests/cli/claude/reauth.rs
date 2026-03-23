//! Test that `rumpel claude <name> reauth` copies fresh authentication
//! credentials from the host into the container without needing to
//! recreate the pod.

use rumpelpod::CommandExt;

use crate::common::{pod_command, write_test_devcontainer, TestDaemon, TestHome, TestRepo};
use crate::executor::ExecutorResources;

use super::common::setup_controlled_home;

fn setup_reauth_test() -> (TestHome, TestRepo, ExecutorResources, TestDaemon) {
    let repo = TestRepo::new();
    // Plain devcontainer -- no claude CLI needed for reauth.
    write_test_devcontainer(&repo, "", "");

    let home = TestHome::new();
    setup_controlled_home(&home);
    let executor = ExecutorResources::setup(&home, "claude-reauth");
    let daemon = TestDaemon::start(&home);
    std::fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml)
        .expect("write .rumpelpod.toml");
    (home, repo, executor, daemon)
}

/// Helper: run `rumpel` with HOME pointed at the test home.
fn rumpel(repo: &TestRepo, daemon: &TestDaemon, home: &TestHome) -> std::process::Command {
    let mut cmd = pod_command(repo, daemon);
    cmd.env("HOME", home.path());
    cmd
}

#[test]
fn reauth_updates_oauth_credentials() {
    let (home, repo, _executor, daemon) = setup_reauth_test();

    // Create the pod so the in-container HTTP server is running.
    rumpel(&repo, &daemon, &home)
        .args(["enter", "test", "--", "true"])
        .success()
        .expect("create pod");

    // Seed the container with an initial .claude dir and .claude.json
    // so reauth has something to update.
    rumpel(&repo, &daemon, &home)
        .args([
            "enter",
            "test",
            "--",
            "mkdir",
            "-p",
            "/home/testuser/.claude",
        ])
        .success()
        .expect("mkdir .claude");
    rumpel(&repo, &daemon, &home)
        .args([
            "enter",
            "test",
            "--",
            "sh",
            "-c",
            "echo '{}' > /home/testuser/.claude.json",
        ])
        .success()
        .expect("seed .claude.json");

    // Write new OAuth credentials on the host.
    let new_creds = r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-REFRESHED-TOKEN","refreshToken":"sk-ant-ort01-REFRESHED-REFRESH","expiresAt":9999999999999,"scopes":["user:inference"],"subscriptionType":"max","rateLimitTier":"default_claude_max_5x"}}"#;
    std::fs::write(home.path().join(".claude/.credentials.json"), new_creds)
        .expect("write new credentials");

    // Run reauth.
    rumpel(&repo, &daemon, &home)
        .args(["claude", "test", "reauth"])
        .success()
        .expect("reauth");

    // Read back the credentials from the container.
    let output = rumpel(&repo, &daemon, &home)
        .args([
            "enter",
            "test",
            "--",
            "cat",
            "/home/testuser/.claude/.credentials.json",
        ])
        .output()
        .expect("read credentials");
    let got = String::from_utf8_lossy(&output.stdout);
    assert!(
        got.contains("REFRESHED-TOKEN"),
        "expected refreshed OAuth token in container, got: {got}",
    );
}

#[test]
fn reauth_updates_api_key() {
    let (home, repo, _executor, daemon) = setup_reauth_test();

    rumpel(&repo, &daemon, &home)
        .args(["enter", "test", "--", "true"])
        .success()
        .expect("create pod");

    // Seed the container with a .claude.json that has an old API key.
    rumpel(&repo, &daemon, &home)
        .args([
            "enter", "test", "--", "sh", "-c",
            r#"echo '{"primaryApiKey":"sk-old-key","hasCompletedOnboarding":true}' > /home/testuser/.claude.json"#,
        ])
        .success()
        .expect("seed .claude.json with old key");
    rumpel(&repo, &daemon, &home)
        .args([
            "enter",
            "test",
            "--",
            "mkdir",
            "-p",
            "/home/testuser/.claude",
        ])
        .success()
        .expect("mkdir .claude");

    // Put a new API key on the host.
    std::fs::write(
        home.path().join(".claude.json"),
        r#"{"primaryApiKey":"sk-new-key-12345","hasCompletedOnboarding":true}"#,
    )
    .expect("write host .claude.json with new key");

    rumpel(&repo, &daemon, &home)
        .args(["claude", "test", "reauth"])
        .success()
        .expect("reauth");

    let output = rumpel(&repo, &daemon, &home)
        .args(["enter", "test", "--", "cat", "/home/testuser/.claude.json"])
        .output()
        .expect("read .claude.json");
    let got = String::from_utf8_lossy(&output.stdout);

    // API key should be updated.
    assert!(
        got.contains("sk-new-key-12345"),
        "expected new API key in container .claude.json, got: {got}",
    );
    // Existing fields should be preserved.
    assert!(
        got.contains("hasCompletedOnboarding"),
        "expected existing fields preserved in container .claude.json, got: {got}",
    );
}
