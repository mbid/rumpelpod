//! Test detach (Ctrl-a d) and reattach: verify the PTY session
//! survives across client disconnections and typed text persists.

use super::common::{setup_claude_test_repo, ClaudeSession};
use super::proxy::claude_proxy;

/// Ctrl-a (0x01) followed by 'd' triggers detach.
const CTRL_A: u8 = 0x01;

#[test]
fn claude_detach_reattach() {
    let proxy = claude_proxy();
    let (repo, daemon, fake_home) = setup_claude_test_repo(proxy);

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

    // -- Second session: reattach and verify Claude is still alive ----
    //
    // The PTY master doesn't replay past output, so the screen starts
    // blank. We verify the session is alive by typing new text and
    // checking that Claude's TUI renders it.

    let mut session2 = ClaudeSession::spawn(
        &repo,
        &daemon,
        proxy,
        fake_home.path(),
        "claude-haiku-4-5",
        &[],
    );

    // Force Claude to re-render by sending Ctrl-l (form feed),
    // which ink/blessed TUI frameworks treat as a redraw request.
    session2.write_raw(&[0x0c]);

    // Verify the session is alive: type new text and check it appears.
    let marker = "reattach_test_42";
    session2.write_raw(marker.as_bytes());
    session2.wait_for(marker);
}
