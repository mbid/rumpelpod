use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use assert_cmd::cargo;
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use tempfile::TempDir;

use super::common::{llm_cache_dir, setup_test_repo, DEFAULT_MODEL};
use crate::common::TestDaemon;

fn create_timestamped_mock_editor(script_dir: &Path, timestamp_file: &Path) -> PathBuf {
    use indoc::formatdoc;

    let script_path = script_dir.join("mock-editor.sh");
    let timestamp_file_str = timestamp_file.to_string_lossy();

    // macOS date(1) does not support %N; fall back to perl there.
    let script_content = formatdoc! {r#"
        #!/bin/bash
        if [ "$(uname)" = "Darwin" ]; then
            perl -MTime::HiRes=time -e 'printf "%.6f\n", time()' > "{timestamp_file_str}"
        else
            date +%s.%N > "{timestamp_file_str}"
        fi
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
    let timestamp_file = temp_dir.path().join("timestamp.txt");
    let editor_path = create_timestamped_mock_editor(temp_dir.path(), &timestamp_file);
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

    let rumpel_bin = cargo::cargo_bin!("rumpel");

    let mut cmd = CommandBuilder::new(rumpel_bin);
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

    let _start_time = Instant::now();
    let start_system_time = SystemTime::now();

    let mut child = pair
        .slave
        .spawn_command(cmd)
        .expect("Failed to spawn command");

    // We wait for the timestamp file to appear
    let start = Instant::now();
    let timeout = Duration::from_secs(10);

    let mut editor_time: Option<f64> = None;

    while start.elapsed() < timeout {
        if timestamp_file.exists() {
            let content =
                fs::read_to_string(&timestamp_file).expect("Failed to read timestamp file");
            if let Ok(ts) = content.trim().parse::<f64>() {
                editor_time = Some(ts);
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    // Clean up
    let _ = child.kill();

    assert!(
        editor_time.is_some(),
        "Editor was not invoked within timeout"
    );

    let editor_ts = editor_time.unwrap();
    let start_ts = start_system_time
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();

    let diff = editor_ts - start_ts;
    println!("Time to editor: {:.4}s", diff);

    // Assert that it took less than 0.2 seconds
    // Note: In a CI environment, 0.2s might be flaky if the machine is very slow.
    // But locally it should be very fast.
    // If we wait for pod launch, it should be > 1s typically.
    assert!(diff < 0.2, "Editor took too long to open: {:.4}s", diff);
}
