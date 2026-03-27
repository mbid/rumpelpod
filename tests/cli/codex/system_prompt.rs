//! Test that the rumpelpod system prompt is injected into /AGENTS.md
//! inside the container and visible to the Codex agent.

use super::common::{setup_codex_test_repo, CodexSession};

#[test]
fn codex_system_prompt_describes_remotes() {
    let (_home, repo, _executor, daemon) = setup_codex_test_repo("codex-sysprompt");

    let mut session = CodexSession::spawn(&repo, &daemon, _home.path(), &["-m", "o3"]);
    session.dismiss_dialogs();

    session.send("What git remote has other pods? One word only.");
    session.wait_for("rumpelpod");
}

#[test]
fn codex_system_prompt_describes_description_file() {
    let (_home, repo, _executor, daemon) = setup_codex_test_repo("codex-sysprompt-desc");

    let mut session = CodexSession::spawn(&repo, &daemon, _home.path(), &["-m", "o3"]);
    session.dismiss_dialogs();

    session.send("In which file should you put the merge commit message? One word only.");
    session.wait_for("DESCRIPTION");
}
