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

/// When Claude exits inside the pod (via Ctrl-D), the client must
/// detect it and exit cleanly instead of hanging.  Restarting must
/// launch a fresh session, not try to reattach to the dead one.
#[test]
fn claude_session_exit() {
    let proxy = claude_proxy();
    let (home, repo, _executor, daemon) = setup_claude_test_repo(proxy, "claude-exit");

    let mut session =
        ClaudeSession::spawn(&repo, &daemon, proxy, home.path(), "claude-haiku-4-5", &[]);

    session.wait_for("~/workspace");

    // Ctrl-D (0x04) at an empty prompt causes Claude Code to exit.
    // Send it twice: the first triggers the exit intent, the second
    // confirms in case the TUI consumed the first one.
    session.write_raw(&[0x04]);
    std::thread::sleep(std::time::Duration::from_millis(500));
    session.write_raw(&[0x04]);

    // The rumpel process must exit, not hang.  wait_for_exit panics
    // after 10s if the child is still alive.
    session.wait_for_exit();

    // Restarting must launch a fresh Claude session rather than
    // reattaching to the now-dead one.
    let mut session2 =
        ClaudeSession::spawn(&repo, &daemon, proxy, home.path(), "claude-haiku-4-5", &[]);

    session2.wait_for("~/workspace");
}
