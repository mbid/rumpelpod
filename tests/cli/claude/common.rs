//! Common utilities for claude integration tests.

use std::io::Read;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use indoc::formatdoc;
use portable_pty::{native_pty_system, CommandBuilder, PtySize};

use crate::common::{build_test_image, ImageId, TestDaemon, TestRepo, TEST_REPO_PATH};

use super::proxy::ClaudeTestProxy;

/// Output from a `claude --print` invocation.
pub struct ClaudeOutput {
    pub stdout: String,
    pub success: bool,
}

/// Resolve the host's claude CLI binary to its real path (following symlinks).
pub fn find_claude_binary() -> PathBuf {
    let output = Command::new("which")
        .arg("claude")
        .output()
        .expect("run `which claude`");

    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert!(
        !path.is_empty(),
        "claude binary not found on host -- install Claude CLI first"
    );

    std::fs::canonicalize(&path).expect("resolve claude binary symlinks")
}

/// Build the test image with claude CLI, screen, and faketime.
///
/// Copies the host's claude binary into the build context rather than
/// downloading it (Docker builds in this environment lack DNS).
pub fn build_claude_test_image(repo: &TestRepo) -> ImageId {
    let claude_binary = find_claude_binary();
    let claude_dest = repo.path().join("claude-cli-binary");
    std::fs::copy(&claude_binary, &claude_dest).expect("copy claude binary into build context");

    // Extra lines run after `USER testuser` from build_test_image.
    // Switch to root for package install + binary placement, then back.
    let extra = "\
USER root
RUN apt-get update && apt-get install -y screen faketime
RUN mv /home/testuser/workspace/claude-cli-binary /usr/local/bin/claude \
    && chmod +x /usr/local/bin/claude
USER testuser";

    build_test_image(repo.path(), extra).expect("build claude test image")
}

/// Write devcontainer config that points at the given image and injects
/// the proxy's base URL + faketime into the container environment.
pub fn write_claude_test_config(repo: &TestRepo, image_id: &ImageId) {
    let devcontainer_dir = repo.path().join(".devcontainer");
    std::fs::create_dir_all(&devcontainer_dir).expect("create .devcontainer dir");

    let devcontainer_json = formatdoc! {r#"
        {{
            "image": "{image_id}",
            "workspaceFolder": "{TEST_REPO_PATH}",
            "runArgs": ["--runtime=runc"],
            "remoteEnv": {{
                "ANTHROPIC_BASE_URL": "${{localEnv:ANTHROPIC_BASE_URL}}",
                "ANTHROPIC_API_KEY": "${{localEnv:ANTHROPIC_API_KEY}}",
                "LD_PRELOAD": "/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1",
                "FAKETIME": "2026-02-15 12:00:00"
            }}
        }}
    "#};

    std::fs::write(
        devcontainer_dir.join("devcontainer.json"),
        devcontainer_json,
    )
    .expect("write devcontainer.json");

    std::fs::write(repo.path().join(".rumpelpod.toml"), "").expect("write .rumpelpod.toml");
}

/// Build the image, write config, and start a daemon -- everything needed
/// before running a claude command.
pub fn setup_claude_test_repo(proxy: &ClaudeTestProxy) -> (TestRepo, TestDaemon) {
    let _ = proxy; // used only to ensure the proxy is started first
    let repo = TestRepo::new();
    let image_id = build_claude_test_image(&repo);
    write_claude_test_config(&repo, &image_id);
    let daemon = TestDaemon::start();
    (repo, daemon)
}

/// Spawn `rumpel claude test --print <prompt>` inside a PTY, collect all
/// output, and wait for exit (or timeout after 120 s).
pub fn run_claude_print(
    repo: &TestRepo,
    daemon: &TestDaemon,
    proxy: &ClaudeTestProxy,
    prompt: &str,
    model: &str,
) -> ClaudeOutput {
    run_claude_print_with_flags(repo, daemon, proxy, prompt, model, &[])
}

/// Like `run_claude_print` but accepts extra rumpel flags inserted before `--`.
pub fn run_claude_print_with_flags(
    repo: &TestRepo,
    daemon: &TestDaemon,
    proxy: &ClaudeTestProxy,
    prompt: &str,
    model: &str,
    extra_flags: &[&str],
) -> ClaudeOutput {
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("create PTY");

    let mut cmd = CommandBuilder::new("rumpel");
    cmd.cwd(repo.path());
    cmd.env(
        "RUMPELPOD_DAEMON_SOCKET",
        daemon.socket_path.to_str().unwrap(),
    );
    cmd.env(
        "ANTHROPIC_BASE_URL",
        format!("http://{}:{}", proxy.addr, proxy.port),
    );
    cmd.env("ANTHROPIC_API_KEY", "dummy-for-test");

    if std::env::var("RUMPELPOD_TEST_LLM_OFFLINE").is_err() {
        cmd.env("RUMPELPOD_TEST_LLM_OFFLINE", "1");
    }

    cmd.args(["claude", "test", "--no-dangerously-skip-permissions"]);
    cmd.args(extra_flags);
    cmd.args([
        "--",
        "--print",
        prompt,
        "--no-session-persistence",
        "--session-id",
        "00000000-0000-0000-0000-000000000001",
        "--model",
        model,
    ]);

    let mut child = pair.slave.spawn_command(cmd).expect("spawn rumpel claude");

    let mut reader = pair.master.try_clone_reader().expect("clone PTY reader");

    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let mut buffer = [0u8; 4096];
        while let Ok(n) = reader.read(&mut buffer) {
            if n == 0 {
                break;
            }
            if tx
                .send(String::from_utf8_lossy(&buffer[..n]).to_string())
                .is_err()
            {
                break;
            }
        }
    });

    let mut output = String::new();
    let start = Instant::now();
    let timeout = Duration::from_secs(120);

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                while let Ok(s) = rx.try_recv() {
                    output.push_str(&s);
                }
                return ClaudeOutput {
                    stdout: output,
                    success: status.exit_code() == 0,
                };
            }
            Ok(None) => {}
            Err(e) => panic!("Error waiting for rumpel claude: {}", e),
        }

        while let Ok(s) = rx.try_recv() {
            output.push_str(&s);
        }

        if start.elapsed() > timeout {
            let _ = child.kill();
            panic!(
                "rumpel claude did not exit within {:?}.\nOutput so far:\n{}",
                timeout, output
            );
        }

        thread::sleep(Duration::from_millis(50));
    }
}
