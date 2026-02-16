//! Smoke test: verify a simple prompt reaches the Claude CLI inside the
//! container, gets a response via the caching proxy, and exits cleanly.

use std::io::Read;
use std::thread;
use std::time::{Duration, Instant};

use indoc::formatdoc;
use portable_pty::{native_pty_system, CommandBuilder, PtySize};

use crate::common::{build_test_image, TestDaemon, TestRepo, TEST_REPO_PATH};

use super::proxy::claude_proxy;

/// Extra Dockerfile lines to install claude CLI, screen, and faketime.
/// Runs after `USER testuser` from build_test_image, so we switch to root
/// for package installation, then back.
const CLAUDE_IMAGE_EXTRA: &str = "\
USER root
RUN apt-get update && apt-get install -y screen faketime curl
USER testuser
RUN curl -fsSL https://cli.anthropic.com/install.sh | sh
ENV PATH=\"/home/testuser/.claude/bin:$PATH\"
";

fn write_claude_test_config(repo: &TestRepo, image_id: &crate::common::ImageId) {
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

#[test]
fn claude_smoke() {
    let proxy = claude_proxy();

    let repo = TestRepo::new();
    let image_id =
        build_test_image(repo.path(), CLAUDE_IMAGE_EXTRA).expect("build claude test image");
    write_claude_test_config(&repo, &image_id);

    let daemon = TestDaemon::start();

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

    cmd.args([
        "claude",
        "test",
        "--no-dangerously-skip-permissions",
        "--",
        "--print",
        "What is 2+2? Reply with just the number.",
        "--no-session-persistence",
        "--session-id",
        "00000000-0000-0000-0000-000000000001",
        "--model",
        "claude-haiku-4-5",
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
            Ok(Some(_status)) => {
                while let Ok(s) = rx.try_recv() {
                    output.push_str(&s);
                }
                break;
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

    assert!(
        output.contains("4"),
        "Claude should respond with 4 to 'What is 2+2?'.\nFull output:\n{}",
        output
    );
}
