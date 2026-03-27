//! Test that the rumpelpod system prompt is injected into the container
//! and visible to the Claude CLI.

use super::common::{setup_claude_test_repo, ClaudeSession};
use super::proxy::claude_proxy;

#[test]
fn claude_system_prompt_describes_remotes() {
    let proxy = claude_proxy();
    let (home, repo, _executor, daemon) = setup_claude_test_repo(proxy, "claude-sysprompt");

    let mut session = ClaudeSession::spawn(
        &repo,
        &daemon,
        proxy,
        home.path(),
        "claude-haiku-4-5",
        &["--allowedTools", ""],
    );

    session.wait_for("~/workspace");
    session.send("What git remote has other pods? One word only.");

    session.wait_for("rumpelpod");
}

#[test]
fn claude_system_prompt_describes_description_file() {
    let proxy = claude_proxy();
    let (home, repo, _executor, daemon) = setup_claude_test_repo(proxy, "claude-sysprompt-desc");

    let mut session = ClaudeSession::spawn(
        &repo,
        &daemon,
        proxy,
        home.path(),
        "claude-haiku-4-5",
        &["--allowedTools", ""],
    );

    session.wait_for("~/workspace");
    session.send("In which file should you put the merge commit message? One word only.");

    session.wait_for("DESCRIPTION");
}
