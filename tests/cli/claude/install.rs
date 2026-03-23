//! Verify that `rumpel claude` auto-installs the Claude CLI when it
//! is not already present in the container image.

use crate::common::{write_test_devcontainer, TestDaemon, TestHome, TestRepo};
use crate::executor::ExecutorResources;

use super::common::ClaudeSession;
use super::proxy::{claude_proxy, ClaudeTestProxy};

/// Set up a container image with NO pre-installed Claude CLI.
///
/// The PTY handler's ensure_claude_cli will download it from GCS on
/// first session spawn.
fn setup_install_test_repo(
    proxy: &ClaudeTestProxy,
    test_name: &str,
) -> (TestHome, TestRepo, ExecutorResources, TestDaemon) {
    let _ = proxy;
    let repo = TestRepo::new();

    // No extra Dockerfile steps -- the image has no claude binary.
    let extra_json = r#",
        "remoteEnv": {
            "ANTHROPIC_BASE_URL": "${localEnv:ANTHROPIC_BASE_URL}"
        }"#;
    write_test_devcontainer(&repo, "", extra_json);

    let home = TestHome::new();
    super::common::setup_controlled_home(&home);
    let executor = ExecutorResources::setup(&home, test_name);
    let daemon = TestDaemon::start_with_host_claude(&home);
    std::fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml)
        .expect("write .rumpelpod.toml");
    (home, repo, executor, daemon)
}

#[test]
fn claude_auto_install() {
    let proxy = claude_proxy();
    let (home, repo, _executor, daemon) = setup_install_test_repo(proxy, "claude-auto-install");

    let mut session =
        ClaudeSession::spawn(&repo, &daemon, proxy, home.path(), "claude-haiku-4-5", &[]);

    // The PTY handler downloads the Claude CLI from GCS before
    // spawning the session.  Wait for the TUI to finish loading.
    session.wait_for("~/workspace");
}
