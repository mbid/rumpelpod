use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use tempfile::TempDir;

use super::common::{llm_cache_dir, setup_test_repo, DEFAULT_MODEL};
use crate::common::TestDaemon;

/// Create a mock editor that just touches a marker file and exits.
fn create_marker_mock_editor(script_dir: &Path, marker_file: &Path) -> PathBuf {
    use indoc::formatdoc;

    let script_path = script_dir.join("mock-editor.sh");
    let marker_file_str = marker_file.to_string_lossy();

    let script_content = formatdoc! {r#"
        #!/bin/bash
        touch "{marker_file_str}"
    "#};
    fs::write(&script_path, &script_content).expect("Failed to write mock editor script");

    let perms = fs::Permissions::from_mode(0o755);
    fs::set_permissions(&script_path, perms).expect("Failed to set script permissions");

    script_path
}

#[test]
fn test_editor_opens_immediately() {
    let repo = setup_test_repo();
    let daemon = TestDaemon::start();
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let marker_file = temp_dir.path().join("editor-ran");
    let editor_path = create_marker_mock_editor(temp_dir.path(), &marker_file);
    let cache_dir = llm_cache_dir();

    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("Failed to create PTY");

    let mut cmd = CommandBuilder::new("rumpel");
    cmd.cwd(repo.path());
    cmd.env(
        "RUMPELPOD_DAEMON_SOCKET",
        daemon.socket_path.to_str().unwrap(),
    );
    cmd.env("EDITOR", editor_path.to_str().unwrap());

    // TODO: We could use something like `waitFor` in devcontainer.json to build a more appropriate image that *must* take longer than, say, 2 seconds
    // (`waitFor` is not implemented atm, we don't respect it).
    // For now, the standard start up time should be enough to trigger a failure if we wait for it.

    cmd.args([
        "agent",
        "test_startup", // Use a unique name to avoid history collisions
        "--model",
        DEFAULT_MODEL,
        "--cache",
        cache_dir.to_str().unwrap(),
        "--new", // Force new conversation so it opens editor immediately
    ]);

    let mut child = pair
        .slave
        .spawn_command(cmd)
        .expect("Failed to spawn command");

    // Poll for the marker file; measure elapsed time from the Rust side
    // to avoid platform-specific shell timestamp issues.
    let start = Instant::now();
    let timeout = Duration::from_secs(10);

    let mut editor_elapsed: Option<Duration> = None;

    while start.elapsed() < timeout {
        if marker_file.exists() {
            editor_elapsed = Some(start.elapsed());
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    // Clean up
    let _ = child.kill();

    let elapsed = editor_elapsed.expect("Editor was not invoked within timeout");
    let diff = elapsed.as_secs_f64();
    println!("Time to editor: {:.4}s", diff);

    // If we wait for pod launch, it should be > 1s typically.
    assert!(diff < 0.5, "Editor took too long to open: {:.4}s", diff);
}
