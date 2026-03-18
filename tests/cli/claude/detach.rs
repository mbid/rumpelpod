//! Test detach (Ctrl-a d) and reattach: verify the PTY session
//! survives across client disconnections and the screen is replayed.

use super::common::{setup_claude_test_repo, ClaudeSession};
use super::proxy::claude_proxy;

/// Ctrl-a (0x01) followed by 'd' triggers detach.
const CTRL_A: u8 = 0x01;

#[test]
fn claude_detach_reattach() {
    let proxy = claude_proxy();
    let (fake_home, repo, _executor, daemon) = setup_claude_test_repo(proxy, "claude-detach");

    // -- First session: start Claude, then detach ---------------------

    let mut session = ClaudeSession::spawn(
        &repo,
        &daemon,
        proxy,
        fake_home.path(),
        "claude-haiku-4-5",
        &[],
    );

    session.wait_for("~/workspace");

    // Send the detach sequence: Ctrl-a then d.
    session.write_raw(&[CTRL_A, b'd']);

    // The rumpel process should exit after detaching.
    session.wait_for_exit();

    // -- Second session: reattach and verify screen replay -------------
    //
    // The server maintains a virtual terminal buffer (like screen/tmux)
    // and replays the screen contents on attach, so the client sees the
    // full TUI immediately without the app needing to re-render.

    let mut session2 = ClaudeSession::spawn(
        &repo,
        &daemon,
        proxy,
        fake_home.path(),
        "claude-haiku-4-5",
        &[],
    );

    // The screen replay should restore the prompt without any user input.
    session2.wait_for("~/workspace");
}
