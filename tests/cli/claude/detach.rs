//! Test detach (Ctrl-a d) and reattach: verify the PTY session
//! survives across client disconnections and the screen is replayed.
//! Also tests that the client exits cleanly when the remote session ends.

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

/// When Claude exits inside the pod (e.g. /exit), the client must
/// detect it and exit cleanly instead of hanging.  Before the
/// SessionEnded control message this would hang forever because the
/// PTY master returns EIO (not EOF) on Linux when the slave closes.
#[test]
fn claude_session_exit() {
    let proxy = claude_proxy();
    let (home, repo, _executor, daemon) = setup_claude_test_repo(proxy, "claude-exit");

    let mut session =
        ClaudeSession::spawn(&repo, &daemon, proxy, home.path(), "claude-haiku-4-5", &[]);

    session.wait_for("~/workspace");

    // /exit is handled client-side by the Claude CLI.  It causes the
    // node process to exit, closing the PTY slave.
    session.send("/exit");

    // The rumpel process must exit, not hang.  wait_for_exit panics
    // after 10s if the child is still alive.
    session.wait_for_exit();
}
