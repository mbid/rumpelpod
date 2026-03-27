//! Smoke test: verify that the codex TUI on the host can communicate
//! with the codex app-server inside the container through the pod
//! server's WebSocket proxy.

// TODO: add HTTP caching proxy for offline/deterministic codex tests,
// similar to tests/cli/claude/proxy.rs. Until then, this test makes
// real API calls to OpenAI and requires OPENAI_API_KEY to be set.

use super::common::{setup_codex_test_repo, CodexSession};

#[test]
fn codex_smoke() {
    let (_home, repo, _executor, daemon) = setup_codex_test_repo("codex-smoke");

    // rumpel codex passes --dangerously-bypass-approvals-and-sandbox by default,
    // so we only need an explicit --model to avoid the model selection dialog.
    let mut session = CodexSession::spawn(&repo, &daemon, _home.path(), &["-m", "o3"]);

    // Dismiss any startup dialogs (model selection, announcements)
    // by pressing Enter whenever the TUI is waiting.
    session.dismiss_dialogs();

    session.send("What is the capital of France? Reply with just the city name, nothing else.");
    session.wait_for("Paris");
}
